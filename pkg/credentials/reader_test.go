package credentials

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type Config struct {
	Name                 string        `mapstructure:"name"`
	Enabled              bool          `mapstructure:"enabled"`
	RequestTimeout       time.Duration `mapstructure:"request_timeout"`
	RefreshTokenDuration time.Duration `mapstructure:"refresh_token_duration"`
	MaxRetries           int           `mapstructure:"max_retries"`
	LimitSize            int64         `mapstructure:"limit_size"`
	Hosts                []string      `mapstructure:"hosts"`
}

func TestApplyEnvOverrides(t *testing.T) {
	t.Setenv("NAME", "test-service")
	t.Setenv("ENABLED", "true")
	t.Setenv("REQUEST_TIMEOUT", "15m")
	t.Setenv("REFRESH_TOKEN_DURATION", "24h")
	t.Setenv("MAX_RETRIES", "5")
	t.Setenv("LIMIT_SIZE", "1000")
	t.Setenv("HOSTS", "a.example.com, b.example.com")

	cfg := &Config{}
	if err := applyEnvOverrides(cfg); err != nil {
		t.Fatalf("applyEnvOverrides: %v", err)
	}

	if cfg.Name != "test-service" {
		t.Errorf("Name = %q", cfg.Name)
	}
	if !cfg.Enabled {
		t.Error("Enabled = false, want true")
	}
	if cfg.RequestTimeout != 15*time.Minute {
		t.Errorf("RequestTimeout = %v", cfg.RequestTimeout)
	}
	if cfg.RefreshTokenDuration != 24*time.Hour {
		t.Errorf("RefreshTokenDuration = %v", cfg.RefreshTokenDuration)
	}
	if cfg.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d", cfg.MaxRetries)
	}
	if cfg.LimitSize != 1000 {
		t.Errorf("LimitSize = %d", cfg.LimitSize)
	}
	if len(cfg.Hosts) != 2 || cfg.Hosts[1] != "b.example.com" {
		t.Errorf("Hosts = %v", cfg.Hosts)
	}
}

// A malformed value used to be skipped, leaving the field at its zero value and
// the process running as though the variable had never been set.
func TestApplyEnvOverridesReportsBadValues(t *testing.T) {
	t.Setenv("REQUEST_TIMEOUT", "fifteen-minutes")

	if err := applyEnvOverrides(&Config{}); err == nil {
		t.Fatal("a malformed duration was accepted")
	}
}

func TestApplyEnvOverridesRejectsNonStruct(t *testing.T) {
	if err := applyEnvOverrides(nil); err == nil {
		t.Fatal("nil config was accepted")
	}
	notAStruct := "x"
	if err := applyEnvOverrides(&notAStruct); err == nil {
		t.Fatal("a non-struct pointer was accepted")
	}
}

// End to end: what the editor writes is what the reader reads.
func TestReadDecryptsWhatTheEditorWrote(t *testing.T) {
	dir := t.TempDir()

	key, err := GenerateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}

	editor := NewConfigEditor(dir, "credentials.yml.enc", "master.key", "")
	yaml := "development:\n  name: from-file\n  max_retries: 3\n"
	if err := editor.EncryptAndSave([]byte(yaml), hex.EncodeToString(key)); err != nil {
		t.Fatalf("EncryptAndSave: %v", err)
	}

	var cfg Config
	if err := NewConfigReader(dir).Read("development", &cfg); err != nil {
		t.Fatalf("Read: %v", err)
	}

	if cfg.Name != "from-file" || cfg.MaxRetries != 3 {
		t.Fatalf("cfg = %+v", cfg)
	}

	// And the environment still wins over the file.
	t.Setenv("NAME", "from-env")
	var override Config
	if err := NewConfigReader(dir).Read("development", &override); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if override.Name != "from-env" {
		t.Errorf("env override did not apply: %q", override.Name)
	}
}

func TestGenerateMasterKeyWillNotClobber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")

	if _, err := GenerateMasterKey(path); err != nil {
		t.Fatalf("first generate: %v", err)
	}
	before, _ := os.ReadFile(path)

	if _, err := GenerateMasterKey(path); err == nil {
		t.Fatal("overwrote an existing master key")
	}

	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("the existing key was modified")
	}
}

// A key written by `echo`, or piped through base64 -d in a Dockerfile, carries a
// trailing newline.
func TestReadMasterKeyToleratesTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")

	key, err := GenerateMasterKey(path)
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}

	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadMasterKey(path)
	if err != nil {
		t.Fatalf("ReadMasterKey: %v", err)
	}
	if string(got) != string(key) {
		t.Error("key changed after a trailing newline was added")
	}
}

// The upgrade path, end to end: an old file is refused by default, readable
// with the explicit opt-in, and permanently fixed by Migrate.
func TestLegacyFileRefusedUntilMigrated(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	credsPath := filepath.Join(dir, "credentials.yml.enc")

	key, err := GenerateMasterKey(keyPath)
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}

	yaml := "development:\n  name: legacy-file\n"
	if err := os.WriteFile(credsPath, encryptLegacyCFB(t, key, []byte(yaml)), 0o644); err != nil {
		t.Fatal(err)
	}

	// Backward compatibility: the default reader opens it, so upgrading the
	// module never stops an existing file from loading.
	var cfg Config
	if err := NewConfigReader(dir).Read("development", &cfg); err != nil {
		t.Fatalf("default reader refused a legacy file: %v", err)
	}
	if cfg.Name != "legacy-file" {
		t.Fatalf("cfg.Name = %q", cfg.Name)
	}

	// Strict mode is opt-in and refuses it.
	strict := NewConfigReader(dir)
	strict.AllowLegacy = false
	if err := strict.Read("development", &Config{}); !errors.Is(err, ErrLegacyFormat) {
		t.Fatalf("strict reader err = %v, want ErrLegacyFormat", err)
	}

	editor := NewConfigEditor(dir, "credentials.yml.enc", "master.key", "")
	if err := editor.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// After migration the default path works and the opt-in is unnecessary.
	var after Config
	if err := NewConfigReader(dir).Read("development", &after); err != nil {
		t.Fatalf("Read after Migrate: %v", err)
	}
	if after.Name != "legacy-file" {
		t.Fatalf("after.Name = %q", after.Name)
	}
}

// The v1.0.0 exported surface, exercised exactly as ktc-line-connect uses it.
// If this stops compiling, the module has broken a downstream consumer.
func TestV1APIStillCompiles(t *testing.T) {
	dir := t.TempDir()

	key, err := GenerateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}

	// v1.0.0 signatures, unchanged.
	var editor *ConfigEditor = NewConfigEditor(dir, "credentials.yml.enc", "master.key", "vi")
	if err := editor.EncryptAndSave([]byte("debug:\n  name: v1\n"), hex.EncodeToString(key)); err != nil {
		t.Fatalf("EncryptAndSave: %v", err)
	}

	var reader *ConfigReader = NewConfigReader(dir)
	var cfg Config
	if err := reader.Read("debug", &cfg); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cfg.Name != "v1" {
		t.Fatalf("cfg.Name = %q", cfg.Name)
	}
}
