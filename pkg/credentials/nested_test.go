package credentials

import (
	"os"
	"path/filepath"
	"testing"
)

type metaSection struct {
	AppID       string `mapstructure:"app_id"`
	AppSecret   string `mapstructure:"app_secret"`
	VerifyToken string `mapstructure:"verify_token"`
}

type nestedConfig struct {
	Name     string       `mapstructure:"name"`
	Facebook metaSection  `mapstructure:"facebook"`
	Optional *metaSection `mapstructure:"optional"`
}

func writeNested(t *testing.T, yaml string) (dir string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "credentials"), 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := GenerateMasterKey(filepath.Join(dir, "credentials", "probe.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := NewEnvironmentEditor(dir, "probe", "").EncryptAndSave([]byte(yaml), hexOf(key)); err != nil {
		t.Fatal(err)
	}
	return dir
}

const nestedYAML = `name: top
facebook:
  app_id: "2568801993591229"
  app_secret: "from-file"
  verify_token: "tok"
`

func TestNestedKeysReadFromFile(t *testing.T) {
	dir := writeNested(t, nestedYAML)

	var cfg nestedConfig
	if err := NewConfigReader(dir).Read("probe", &cfg); err != nil {
		t.Fatalf("Read: %v", err)
	}

	if cfg.Facebook.AppID != "2568801993591229" || cfg.Facebook.AppSecret != "from-file" {
		t.Fatalf("nested section = %+v", cfg.Facebook)
	}
}

// The gap this closed: a nested value could be read but never overridden, which
// looks exactly like the variable being ignored.
func TestNestedKeysAreOverriddenByPrefixedEnv(t *testing.T) {
	dir := writeNested(t, nestedYAML)

	t.Setenv("FACEBOOK_APP_SECRET", "from-env")

	var cfg nestedConfig
	if err := NewConfigReader(dir).Read("probe", &cfg); err != nil {
		t.Fatalf("Read: %v", err)
	}

	if cfg.Facebook.AppSecret != "from-env" {
		t.Errorf("AppSecret = %q, want the environment to win", cfg.Facebook.AppSecret)
	}
	if cfg.Facebook.AppID != "2568801993591229" {
		t.Errorf("AppID = %q — untouched siblings must survive", cfg.Facebook.AppID)
	}
}

// The unprefixed name must NOT leak across sections: APP_SECRET is ambiguous
// once there are two channels, and silently applying it to one would be worse
// than ignoring it.
func TestUnprefixedNameDoesNotReachNestedFields(t *testing.T) {
	dir := writeNested(t, nestedYAML)

	t.Setenv("APP_SECRET", "ambiguous")

	var cfg nestedConfig
	if err := NewConfigReader(dir).Read("probe", &cfg); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cfg.Facebook.AppSecret != "from-file" {
		t.Errorf("AppSecret = %q, want the file value", cfg.Facebook.AppSecret)
	}
}

// An optional section absent from the file stays nil unless something under it
// is set, so a pointer section is not materialised by merely existing.
func TestOptionalSectionStaysNilUntilSet(t *testing.T) {
	dir := writeNested(t, nestedYAML)

	var cfg nestedConfig
	if err := NewConfigReader(dir).Read("probe", &cfg); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cfg.Optional != nil {
		t.Fatalf("Optional = %+v, want nil", cfg.Optional)
	}

	t.Setenv("OPTIONAL_APP_SECRET", "materialise-me")

	var cfg2 nestedConfig
	if err := NewConfigReader(dir).Read("probe", &cfg2); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cfg2.Optional == nil || cfg2.Optional.AppSecret != "materialise-me" {
		t.Fatalf("Optional = %+v, want it allocated and set", cfg2.Optional)
	}
}

// FlatShared makes the default file behave like a per-environment one, so a key
// sits at the same depth in every file. Without it the same value has to be
// indented differently depending on which file it is in, and getting that wrong
// is silent.
func TestFlatSharedReadsTheWholeFile(t *testing.T) {
	dir := t.TempDir()

	key, err := GenerateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	flat := "name: flat\nfacebook:\n  app_id: \"123\"\n  app_secret: \"s\"\n"
	if err := NewConfigEditor(dir, "credentials.yml.enc", "master.key", "").
		EncryptAndSave([]byte(flat), hexOf(key)); err != nil {
		t.Fatal(err)
	}

	// Default (sectioned) finds nothing, because there is no development: key.
	var sectioned nestedConfig
	if err := NewConfigReader(dir).Read("development", &sectioned); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if sectioned.Name != "" {
		t.Fatalf("sectioned read found %q — expected the flat file to look empty", sectioned.Name)
	}

	r := NewConfigReader(dir)
	r.FlatShared = true
	var cfg nestedConfig
	if err := r.Read("development", &cfg); err != nil {
		t.Fatalf("Read flat: %v", err)
	}
	if cfg.Name != "flat" || cfg.Facebook.AppID != "123" {
		t.Fatalf("cfg = %+v", cfg)
	}
}
