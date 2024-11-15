package credentials

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type MyConfig struct {
	AccessToken string `mapstructure:"access_token"`
}

type Reader struct {
	configPath string
}

func creatConfigReader(reader Reader) *ConfigReader {
	configReader := NewConfigReader(configReader, reader.configPath)
	return configReader
}

func TestRead(t *testing.T) {
	t.Run("master.key can not read", func(t *testing.T) {
		// expect see error
		reader := creatConfigReader(Reader{
			configPath: "./test_support/reader/masterkey_can_not_read",
		})
		var config MyConfig
		err := reader.Read("test", &config)
		require.Error(t, err)
		require.EqualError(t, err, "failed to read master key: open test_support/reader/masterkey_can_not_read/master.key: no such file or directory")
	})

	t.Run("read master.key", func(t *testing.T) {

		t.Run("master key can not decode", func(t *testing.T) {
			reader := creatConfigReader(Reader{
				configPath: "./test_support/reader/masterkey_can_not_decode",
			})
			var config MyConfig
			err := reader.Read("test", &config)
			require.Error(t, err)
			require.EqualError(t, err, "failed to read decrypted config: While parsing config: yaml: invalid trailing UTF-8 octet")
		})

		t.Run("master.key can decrpyt credentials", func(t *testing.T) {

			t.Run("credentail can not load to provide struct", func(t *testing.T) {
				reader := creatConfigReader(Reader{
					configPath: "./test_support/reader/credentail_can_not_provide_struct",
				})
				var config MyConfig
				err := reader.Read("error", &config)
				require.Error(t, err)
				require.EqualError(t, err, "failed to unmarshal configuration: Unmarshal Error")
			})

			t.Run("credentail can load to provide struct", func(t *testing.T) {
				// reader := creatConfigReader(Reader{
				// 	configPath: "./test_support/reader/credentail_can_provide_struct",
				// })
				// var config MyConfig
				// err := reader.Read("test", &config)
				// require.NoError(t, err)
				// require.Equal(t, "token", config.AccessToken)
			})
		})
	})
}
