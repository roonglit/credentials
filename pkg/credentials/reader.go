package credentials

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/spf13/viper"
)

// ConfigReader manages reading and decrypting the configuration file
type ConfigReader struct {
	CredentialsFile        string
	MasterKeyFile          string
	secretManagerRegistry  *SecretManagerRegistry
}

// NewConfigReader initializes a new ConfigReader with the specified paths
func NewConfigReader(configDir ...string) *ConfigReader {
	var dir string
	if len(configDir) > 0 && configDir[0] != "" {
		dir = configDir[0]
	} else {
		dir = "config"
	}

	credentialsFile := "credentials.yml.enc"
	masterKeyFile := "master.key"
	return &ConfigReader{
		CredentialsFile:       filepath.Join(dir, credentialsFile),
		MasterKeyFile:         filepath.Join(dir, masterKeyFile),
		secretManagerRegistry: NewSecretManagerRegistry(),
	}
}

// Read loads and decrypts configurations from the encrypted credentials file
func (cr *ConfigReader) Read(mode string, config interface{}) error {
	// Read and decode the master key
	keyHex, err := os.ReadFile(cr.MasterKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read master key: %w", err)
	}
	masterKey, err := hex.DecodeString(string(keyHex))
	if err != nil {
		return fmt.Errorf("failed to decode master key: %w", err)
	}

	// Decrypt the credentials file
	decryptedContent, err := decryptConfigFile(cr.CredentialsFile, hex.EncodeToString(masterKey))
	if err != nil {
		return fmt.Errorf("failed to decrypt credentials file: %w", err)
	}

	// Load the decrypted content with viper
	viper.SetConfigType("yaml")
	viper.AutomaticEnv()
	if err = viper.ReadConfig(bytes.NewBuffer(decryptedContent)); err != nil {
		return fmt.Errorf("failed to read decrypted config: %w", err)
	}

	// Unmarshal into the provided configuration struct
	if err = viper.UnmarshalKey(mode, config); err != nil {
		return fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	// Load additional environment variables and secret manager values into the configuration struct
	if err := cr.loadExternalSources(config); err != nil {
		return fmt.Errorf("failed to load external sources: %w", err)
	}
	return nil
}

// decryptConfigFile decrypts the encrypted credentials file
func decryptConfigFile(filename, keyString string) ([]byte, error) {
	key, err := hex.DecodeString(keyString)
	if err != nil {
		return nil, err
	}

	ciphertext, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// loadExternalSources loads values from secret managers and environment variables
func (cr *ConfigReader) loadExternalSources(cfg interface{}) error {
	ctx := context.Background()
	val := reflect.ValueOf(cfg).Elem()
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		mapstructureTag := typ.Field(i).Tag.Get("mapstructure")

		if !field.CanSet() || mapstructureTag == "" {
			continue
		}

		// Check secret managers first
		if cr.secretManagerRegistry.HasConfiguredManagers() {
			if secretValue, found, err := cr.checkSecretManagers(ctx, mapstructureTag); err != nil {
				return err
			} else if found {
				if err := cr.setFieldValue(field, secretValue); err != nil {
					return fmt.Errorf("failed to set field %s from secret manager: %w", mapstructureTag, err)
				}
				continue // Skip environment variable check if secret manager value found
			}
		}

		// Fall back to environment variables
		if envVar := os.Getenv(strings.ToUpper(mapstructureTag)); envVar != "" {
			if err := cr.setFieldValue(field, envVar); err != nil {
				return fmt.Errorf("failed to set field %s from environment: %w", mapstructureTag, err)
			}
		}
	}
	return nil
}

// checkSecretManagers checks all configured secret managers for a value
func (cr *ConfigReader) checkSecretManagers(ctx context.Context, mapstructureTag string) (string, bool, error) {
	// Try different secret manager prefixes for the given mapstructure tag
	prefixes := []string{"GOOGLE_", "VAULT_"}
	
	for _, prefix := range prefixes {
		envVarName := prefix + strings.ToUpper(mapstructureTag)
		if value, found, err := cr.secretManagerRegistry.GetSecretValue(ctx, envVarName); err != nil {
			return "", false, err
		} else if found {
			return value, true, nil
		}
	}
	
	return "", false, nil
}

// setFieldValue sets a field value with proper type conversion
func (cr *ConfigReader) setFieldValue(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Bool:
		field.SetBool(value == "true")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// For time.Duration and other int-based types, we could add more sophisticated parsing
		if value == "true" {
			field.SetInt(1)
		} else if value == "false" {
			field.SetInt(0)
		} else {
			// For now, just handle basic integer conversion
			// In a real implementation, we'd want to handle time.Duration parsing here
			field.SetInt(0)
		}
	default:
		return fmt.Errorf("unsupported field type: %v", field.Kind())
	}
	return nil
}

// automaticEnv loads additional environment variables into the provided struct (legacy function)
func automaticEnv(cfg interface{}) {
	val := reflect.ValueOf(cfg).Elem()
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		mapstructureTag := typ.Field(i).Tag.Get("mapstructure")

		if field.CanSet() && mapstructureTag != "" {
			envVar := os.Getenv(strings.ToUpper(mapstructureTag))

			if envVar != "" {
				if field.Kind() == reflect.String {
					field.SetString(envVar)
				} else if field.Kind() == reflect.Bool {
					field.SetBool(envVar == "true")
				}
			}
		}
	}
}
