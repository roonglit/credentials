package credentials

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type Editor struct {
	configPath string
}

func createEditor(editor Editor) *ConfigEditor {
	credentialsFile := "credentials.yml.enc"
	masterKeyFile := "master.key"
	configEditor := NewConfigEditor(
		editor.configPath,
		credentialsFile,
		masterKeyFile,
		"vim",
		executor,
		fileManager,
	)
	return configEditor
}

func TestOpenEditor(t *testing.T) {
	t.Run("there is no credentials", func(t *testing.T) {

		t.Run("master.key exists", func(t *testing.T) {
			// TODO check master.key only to see error
		})

		t.Run("master.key does not exist", func(t *testing.T) {
			// run openEditor
			editor := createEditor(Editor{configPath: "./config"})
			err := editor.Open()
			require.NoError(t, err)

			require.FileExistsf(t, "config/credentials.yml.enc", "this file does not exist")
			require.FileExistsf(t, "config/master.key", "this file does not exist")
		})
	})

	t.Run("credentials file exists", func(t *testing.T) {
		t.Run("there is not master.key", func(t *testing.T) {
			editor := createEditor(Editor{
				configPath: "./test_support/config_editor/credential_only",
			})

			err := editor.Open()
			require.EqualError(t, err, "master.key is missing. Editing is not allowed")
		})

		t.Run("master.key can not decrpyt credentials", func(t *testing.T) {
			editor := createEditor(Editor{
				configPath: "./test_support/config_editor/credential_can_not_decrypt",
			})

			err := editor.Open()
			require.EqualError(t, err, "failed to decrypt credentials: ciphertext too short")
		})

		t.Run("master.key can decrpyt credentials", func(t *testing.T) {
			editor := createEditor(Editor{
				configPath: "./test_support/config_editor/credential_can_decrypt",
			})

			err := editor.Open()
			require.NoError(t, err)
			require.Equal(t, "develop:\n  access_token: token", fileManager.CallWithPlaintext)
		})
	})
}
