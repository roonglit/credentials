package credentials

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/spf13/viper"
)

type IConfigReader interface {
	UnmarshalKey(key string, rawVal any) error
	ReadConfig(in io.Reader) error
}

type ViperConfigReader struct{}

func (v *ViperConfigReader) UnmarshalKey(key string, rawVal any) error {
	return viper.UnmarshalKey(key, rawVal)
}

func (v *ViperConfigReader) ReadConfig(in io.Reader) error {
	return viper.ReadConfig(in)

}

// ConfigReader manages reading and decrypting the configuration file
type ConfigReader struct {
	CredentialsFile string
	MasterKeyFile   string
	ViperConfig     IConfigReader
}

// NewConfigReader initializes a new ConfigReader with the specified paths
func NewConfigReader(configReader IConfigReader, configDir ...string) *ConfigReader {
	var dir string
	if len(configDir) > 0 && configDir[0] != "" {
		dir = configDir[0]
	} else {
		dir = "config"
	}

	credentialsFile := "credentials.yml.enc"
	masterKeyFile := "master.key"
	return &ConfigReader{
		CredentialsFile: filepath.Join(dir, credentialsFile),
		MasterKeyFile:   filepath.Join(dir, masterKeyFile),
		ViperConfig:     configReader,
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
	myString := string(decryptedContent[:])
	fmt.Print(myString)
	// Unmarshal into the provided configuration struct
	if err = cr.ViperConfig.UnmarshalKey(mode, config); err != nil {
		return fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	// Load additional environment variables into the configuration struct
	automaticEnv(config)
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

// automaticEnv loads additional environment variables into the provided struct
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
