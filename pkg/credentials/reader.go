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
	CredentialsFile string
	MasterKeyFile   string

	// AllowLegacy permits reading the old unauthenticated format. ON by
	// default, so upgrading this module never stops an existing file from
	// opening; set CREDENTIALS_ALLOW_LEGACY=0 for strict mode.
	AllowLegacy bool
}

// NewConfigReader builds a reader rooted at configDir, defaulting to "config".
func NewConfigReader(configDir ...string) *ConfigReader {
	dir := "config"
	if len(configDir) > 0 && configDir[0] != "" {
		dir = configDir[0]
	}

	return &ConfigReader{
		CredentialsFile: filepath.Join(dir, "credentials.yml.enc"),
		MasterKeyFile:   filepath.Join(dir, "master.key"),
		AllowLegacy:     legacyAllowed(),
	}
}

// Read decrypts the credentials file, selects the mode's section, and unmarshals
// it into config, which must be a non-nil pointer to a struct. Environment
// variables override what the file supplies.
func (cr *ConfigReader) Read(mode string, config interface{}) error {
	key, err := ReadMasterKey(cr.MasterKeyFile)
	if err != nil {
		return err
	}

	blob, err := os.ReadFile(cr.CredentialsFile)
	if err != nil {
		return fmt.Errorf("credentials: read %s: %w", cr.CredentialsFile, err)
	}

	// One decryption path for the whole package — see crypto.go. A second copy
	// lived here previously, which meant a change to one could silently diverge
	// from the other and only surface as a boot failure in production.
	plaintext, err := openBlob(key, blob, cr.AllowLegacy, cr.CredentialsFile)
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

	if err := v.UnmarshalKey(mode, config); err != nil {
		return fmt.Errorf("credentials: unmarshal %q: %w", mode, err)
	}

	return applyEnvOverrides(config)
}

// applyEnvOverrides lets environment variables win over the file, matching each
// field's mapstructure tag upper-cased.
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

	val := rv.Elem()
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		tag := typ.Field(i).Tag.Get("mapstructure")
		if tag == "" || !field.CanSet() {
			continue
		}

		name := strings.ToUpper(tag)
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
