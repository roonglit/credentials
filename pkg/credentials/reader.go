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
	"strconv"
	"strings"
	"time"

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

	// Check if we should use a specific secret manager for ALL values
	secretManager := cr.secretManagerRegistry.GetActiveSecretManager()
	if secretManager != nil {
		// If a secret manager is active, get ALL values from it
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			mapstructureTag := typ.Field(i).Tag.Get("mapstructure")

			if !field.CanSet() || mapstructureTag == "" {
				continue
			}

			// Try to get value from the active secret manager
			secretValue, err := secretManager.GetSecret(ctx, mapstructureTag)
			if err != nil {
				return fmt.Errorf("failed to get secret %s from secret manager: %w", mapstructureTag, err)
			}

			// Only set the field if we got a non-empty value
			if secretValue != "" {
				if err := cr.setFieldValue(field, secretValue); err != nil {
					return fmt.Errorf("failed to set field %s from secret manager: %w", mapstructureTag, err)
				}
			}
			// If secret manager is active but value is empty, leave field empty (no fallback)
		}
	} else {
		// No secret manager active, use original behavior (environment variables override credentials file)
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			mapstructureTag := typ.Field(i).Tag.Get("mapstructure")

			if !field.CanSet() || mapstructureTag == "" {
				continue
			}

			// Check environment variables
			if envVar := os.Getenv(strings.ToUpper(mapstructureTag)); envVar != "" {
				if err := cr.setFieldValue(field, envVar); err != nil {
					return fmt.Errorf("failed to set field %s from environment: %w", mapstructureTag, err)
				}
			}
		}
	}
	return nil
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
				switch field.Kind() {
				case reflect.String:
					field.SetString(envVar)
				case reflect.Bool:
					field.SetBool(envVar == "true")
				case reflect.Int:
					if val, err := strconv.Atoi(envVar); err == nil {
						field.SetInt(int64(val))
					}
				case reflect.Int64:
					if field.Type() == reflect.TypeOf(time.Duration(0)) {
						if dur, err := time.ParseDuration(envVar); err == nil {
							field.SetInt(int64(dur))
						}
					} else {
						if val, err := strconv.ParseInt(envVar, 10, 64); err == nil {
							field.SetInt(val)
						}
					}
				}
			}
		}
	}
}
