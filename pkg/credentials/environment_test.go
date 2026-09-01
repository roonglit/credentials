package credentials

import (
	"os"
	"path/filepath"
	"testing"
)

type envConfig struct {
	Name     string `mapstructure:"name"`
	Database string `mapstructure:"database"`
}

// Writes a per-environment credentials file and returns its key.
func writeEnvCredentials(t *testing.T, dir, env, yaml string) []byte {
	t.Helper()

	editor := NewEnvironmentEditor(dir, env, "")
	if err := os.MkdirAll(editor.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := GenerateMasterKey(editor.MasterKeyFile)
	if err != nil {
		t.Fatalf("GenerateMasterKey(%s): %v", env, err)
	}
	if err := editor.EncryptAndSave([]byte(yaml), hexOf(key)); err != nil {
		t.Fatalf("EncryptAndSave(%s): %v", env, err)
	}
	return key
}

func TestPerEnvironmentFileIsPreferredAndUnnested(t *testing.T) {
	dir := t.TempDir()

	// The shared file carries a section per environment, the old shape.
	sharedKey, err := GenerateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	shared := NewConfigEditor(dir, "credentials.yml.enc", "master.key", "")
	if err := shared.EncryptAndSave([]byte("production:\n  name: from-shared\n"), hexOf(sharedKey)); err != nil {
		t.Fatal(err)
	}

	// The per-environment file is flat: the file IS production.
	writeEnvCredentials(t, dir, "production", "name: from-production-file\ndatabase: pg://prod\n")

	var cfg envConfig
	if err := NewConfigReader(dir).Read("production", &cfg); err != nil {
		t.Fatalf("Read: %v", err)
	}

	if cfg.Name != "from-production-file" {
		t.Errorf("Name = %q, want the per-environment file to win", cfg.Name)
	}
	if cfg.Database != "pg://prod" {
		t.Errorf("Database = %q — the whole file should be the config, unnested", cfg.Database)
	}
}

// Existing projects have only the shared file. They must keep working.
func TestFallsBackToTheSharedFile(t *testing.T) {
	dir := t.TempDir()

	key, err := GenerateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	shared := NewConfigEditor(dir, "credentials.yml.enc", "master.key", "")
	yaml := "development:\n  name: dev\nproduction:\n  name: prod\n"
	if err := shared.EncryptAndSave([]byte(yaml), hexOf(key)); err != nil {
		t.Fatal(err)
	}

	for env, want := range map[string]string{"development": "dev", "production": "prod"} {
		var cfg envConfig
		if err := NewConfigReader(dir).Read(env, &cfg); err != nil {
			t.Fatalf("Read(%s): %v", env, err)
		}
		if cfg.Name != want {
			t.Errorf("Read(%s).Name = %q, want %q", env, cfg.Name, want)
		}
	}
}

// The reason the feature exists: a key that opens development must NOT open
// production.
func TestEnvironmentKeysDoNotCrossOpen(t *testing.T) {
	dir := t.TempDir()

	devKey := writeEnvCredentials(t, dir, "development", "name: dev\n")
	writeEnvCredentials(t, dir, "production", "name: prod\n")

	// Hand the production reader the development key.
	t.Setenv(EnvKeyVar, hexOf(devKey))

	var cfg envConfig
	err := NewConfigReader(dir).Read("production", &cfg)
	if err == nil {
		t.Fatal("the development key decrypted production")
	}
	if cfg.Name != "" {
		t.Fatalf("leaked production config: %+v", cfg)
	}
}

// Containers should not need the key on disk.
func TestKeyCanComeFromTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	key := writeEnvCredentials(t, dir, "staging", "name: staging\n")

	keyFile := filepath.Join(dir, "credentials", "staging.key")
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}

	t.Setenv(EnvKeyVar, hexOf(key))

	var cfg envConfig
	if err := NewConfigReader(dir).Read("staging", &cfg); err != nil {
		t.Fatalf("Read with %s set: %v", EnvKeyVar, err)
	}
	if cfg.Name != "staging" {
		t.Errorf("Name = %q", cfg.Name)
	}
}

func TestEnvironmentPaths(t *testing.T) {
	creds, key := EnvironmentPaths("config", "production")
	if creds != filepath.Join("config", "credentials", "production.yml.enc") {
		t.Errorf("credentials path = %q", creds)
	}
	if key != filepath.Join("config", "credentials", "production.key") {
		t.Errorf("key path = %q", key)
	}

	creds, key = EnvironmentPaths("config", "")
	if creds != filepath.Join("config", "credentials.yml.enc") || key != filepath.Join("config", "master.key") {
		t.Errorf("shared paths = %q, %q", creds, key)
	}
}

// The editor must resolve keys the same way the reader does. It did not once:
// `credentials show -e production` ignored CREDENTIALS_KEY and read the key
// beside the file, so handing it the wrong key still printed the secrets.
func TestEditorHonoursTheKeyEnvironmentVariable(t *testing.T) {
	dir := t.TempDir()

	devKey := writeEnvCredentials(t, dir, "development", "name: dev\n")
	writeEnvCredentials(t, dir, "production", "name: prod\n")

	t.Setenv(EnvKeyVar, hexOf(devKey))

	if _, err := NewEnvironmentEditor(dir, "production", "").Show(); err == nil {
		t.Fatal("Show decrypted production with the development key")
	}
}
