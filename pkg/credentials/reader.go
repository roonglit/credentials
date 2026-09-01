package credentials

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// ConfigReader loads an encrypted credentials file into a struct.
type ConfigReader struct {
	// ConfigDir is the root the per-environment lookup searches under.
	ConfigDir string

	// CredentialsFile and MasterKeyFile are the SHARED pair, used when the
	// environment has no file of its own.
	CredentialsFile string
	MasterKeyFile   string

	// AllowLegacy permits reading the old unauthenticated format. ON by
	// default, so upgrading this module never stops an existing file from
	// opening; set CREDENTIALS_ALLOW_LEGACY=0 for strict mode.
	AllowLegacy bool

	// FlatShared treats the shared file as one environment's settings rather
	// than a section per environment.
	//
	// The sectioned shape is the original one and stays the default, because
	// changing it would break every project already using it. But it has a sharp
	// edge: the same key sits at a different depth depending on which file it is
	// in, and a value written at the wrong depth is silently ignored rather than
	// rejected. A project that gives every environment its own file has no use
	// for sections and is better off flat everywhere.
	FlatShared bool
}

// NewConfigReader builds a reader rooted at configDir, defaulting to "config".
func NewConfigReader(configDir ...string) *ConfigReader {
	dir := "config"
	if len(configDir) > 0 && configDir[0] != "" {
		dir = configDir[0]
	}

	return &ConfigReader{
		ConfigDir:       dir,
		CredentialsFile: filepath.Join(dir, "credentials.yml.enc"),
		MasterKeyFile:   filepath.Join(dir, "master.key"),
		AllowLegacy:     legacyAllowed(),
	}
}

// Read decrypts the credentials for an environment and unmarshals them into
// config, which must be a non-nil pointer to a struct. Environment variables
// override whatever the file supplies.
//
// If config/credentials/<environment>.yml.enc exists it is used, opened with
// that environment's own key, and the WHOLE file is the config — no section
// nesting, because the file already belongs to one environment. Otherwise the
// shared file is read and its <environment> section is selected, which is how
// this worked before per-environment files existed.
func (cr *ConfigReader) Read(environment string, config interface{}) error {
	p := resolve(cr.ConfigDir, environment, cr.CredentialsFile, cr.MasterKeyFile)

	key, err := readKey(p)
	if err != nil {
		return err
	}

	blob, err := os.ReadFile(p.credentials)
	if err != nil {
		return fmt.Errorf("credentials: read %s: %w", p.credentials, err)
	}

	// One decryption path for the whole package — see crypto.go. A second copy
	// lived here previously, which meant a change to one could silently diverge
	// from the other and only surface as a boot failure in production.
	plaintext, err := openBlob(key, blob, cr.AllowLegacy, p.credentials)
	if err != nil {
		return err
	}

	// A private viper instance, not the package singleton. The global is shared
	// process-wide, so two readers — or two parallel tests — used to overwrite
	// each other's config.
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewBuffer(plaintext)); err != nil {
		return fmt.Errorf("credentials: parse decrypted config: %w", err)
	}

	if p.scoped || cr.FlatShared {
		// The file IS this environment: no section to select.
		if err := v.Unmarshal(config); err != nil {
			return fmt.Errorf("credentials: unmarshal %s: %w", p.credentials, err)
		}
	} else if err := v.UnmarshalKey(environment, config); err != nil {
		return fmt.Errorf("credentials: unmarshal %q section: %w", environment, err)
	}

	return applyEnvOverrides(config)
}

// applyEnvOverrides lets environment variables win over the file, matching each
// field's mapstructure tag upper-cased.
//
// NESTED structs are walked, with the names joined by an underscore, so
//
//	Facebook struct { AppSecret string `mapstructure:"app_secret"` } `mapstructure:"facebook"`
//
// is overridden by FACEBOOK_APP_SECRET. Without this, a nested value could be
// read from the file but never overridden — it would look like the variable was
// simply ignored, which is the kind of thing you discover at 2am in a container.
//
// Every parse failure is returned rather than skipped. A malformed
// ACCESS_TOKEN_DURATION used to leave the field at its previous value silently,
// which is the worst outcome for configuration: the process boots, and behaves
// as though you never set it.
func applyEnvOverrides(cfg interface{}) error {
	rv := reflect.ValueOf(cfg)
	if rv.Kind() != reflect.Ptr || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("credentials: config must be a non-nil pointer to a struct, got %T", cfg)
	}
	return overrideStruct(rv.Elem(), "")
}

// overrideStruct applies environment overrides to one struct, recursing into
// nested ones. prefix carries the parent's name, already upper-cased.
func overrideStruct(val reflect.Value, prefix string) error {
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		tag := typ.Field(i).Tag.Get("mapstructure")
		if tag == "" || tag == "-" || !field.CanSet() {
			continue
		}

		name := strings.ToUpper(tag)
		if prefix != "" {
			name = prefix + "_" + name
		}

		// A nested struct is a namespace, not a value. time.Duration is an
		// int64 and never reaches here; time.Time would, so structs the setter
		// understands are handled before recursing.
		if field.Kind() == reflect.Struct && !isSettableStruct(field) {
			if err := overrideStruct(field, name); err != nil {
				return err
			}
			continue
		}

		// A nil pointer to a struct is allocated only when something below it
		// is actually set, so an absent section stays absent.
		if field.Kind() == reflect.Ptr && field.Type().Elem().Kind() == reflect.Struct {
			if !hasEnvWithPrefix(name) {
				continue
			}
			if field.IsNil() {
				field.Set(reflect.New(field.Type().Elem()))
			}
			if err := overrideStruct(field.Elem(), name); err != nil {
				return err
			}
			continue
		}

		raw, ok := os.LookupEnv(name)
		if !ok || raw == "" {
			continue
		}
		if err := setField(field, raw); err != nil {
			return fmt.Errorf("credentials: %s=%q: %w", name, raw, err)
		}
	}
	return nil
}

// isSettableStruct reports whether setField knows how to parse this struct from
// a string, in which case it is a value rather than a namespace.
func isSettableStruct(field reflect.Value) bool {
	_, ok := field.Interface().(time.Time)
	return ok
}

// hasEnvWithPrefix reports whether any variable under a namespace is set, so an
// untouched optional section is not materialised.
func hasEnvWithPrefix(prefix string) bool {
	prefix += "_"
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, prefix) {
			return true
		}
	}
	return false
}

func setField(field reflect.Value, raw string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(raw)

	case reflect.Bool:
		// strconv, not raw == "true": "1", "TRUE" and "yes"-style typos should
		// not all quietly mean false.
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("expected a boolean: %w", err)
		}
		field.SetBool(b)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// time.Duration is an int64 with its own textual form ("15m"), so it has
		// to be matched on the concrete type before the integer case.
		if field.Type() == reflect.TypeOf(time.Duration(0)) {
			d, err := time.ParseDuration(raw)
			if err != nil {
				return fmt.Errorf("expected a duration such as 15m or 24h: %w", err)
			}
			field.SetInt(int64(d))
			return nil
		}
		n, err := strconv.ParseInt(raw, 10, field.Type().Bits())
		if err != nil {
			return fmt.Errorf("expected an integer: %w", err)
		}
		field.SetInt(n)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(raw, 10, field.Type().Bits())
		if err != nil {
			return fmt.Errorf("expected a non-negative integer: %w", err)
		}
		field.SetUint(n)

	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(raw, field.Type().Bits())
		if err != nil {
			return fmt.Errorf("expected a number: %w", err)
		}
		field.SetFloat(f)

	case reflect.Struct:
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return fmt.Errorf("expected an RFC3339 timestamp: %w", err)
		}
		field.Set(reflect.ValueOf(t))

	case reflect.Slice:
		if field.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("unsupported slice element type %s", field.Type().Elem())
		}
		parts := strings.Split(raw, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		field.Set(reflect.ValueOf(parts))

	default:
		return fmt.Errorf("unsupported field type %s", field.Kind())
	}
	return nil
}
