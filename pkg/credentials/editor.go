package credentials

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
)

type ConfigEditor struct {
	ConfigDir       string
	CredentialsFile string
	MasterKeyFile   string
	Editor          string
}

func NewConfigEditor(configDir, credentialsFile, masterKeyFile, editor string) *ConfigEditor {
	return &ConfigEditor{
		ConfigDir:       configDir,
		CredentialsFile: filepath.Join(configDir, credentialsFile),
		MasterKeyFile:   filepath.Join(configDir, masterKeyFile),
		Editor:          editor,
	}
}

// OpenEditor decrypts the credentials file, opens it in an editor for modification,
// and then re-encrypts and saves the updated content.
func (ce *ConfigEditor) OpenEditor() error {
	// Ensure the config directory exists
	if err := os.MkdirAll(ce.ConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check for the existence of master.key and credentials.yml.enc
	masterKeyExists := fileExists(ce.MasterKeyFile)
	credentialsExists := fileExists(ce.CredentialsFile)

	// Case 1: Both files are missing - create master.key and initial credentials content
	var masterKey []byte
	var plaintext []byte
	var err error
	if !masterKeyExists && !credentialsExists {
		fmt.Println("No master.key found. Generating a new one...")
		masterKey, err = generateMasterKey(ce.MasterKeyFile)
		if err != nil {
			return fmt.Errorf("failed to generate master key: %w", err)
		}
		// Initial content for the credentials file
		plaintext = []byte("initial: data\n")
		if err := ce.EncryptAndSave(plaintext, hex.EncodeToString(masterKey)); err != nil {
			return fmt.Errorf("failed to create initial credentials file: %w", err)
		}
		fmt.Println("Initial credentials file created. Opening editor...")
	} else if !masterKeyExists && credentialsExists {
		// Case 2: master.key is missing but credentials.yml.enc exists - editing is not allowed
		return fmt.Errorf("master.key is missing. Editing is not allowed")
	} else {
		// Case 3: Both master.key and credentials.yml.enc exist - proceed with decryption and editing
		masterKey, err = readMasterKey(ce.MasterKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read master key: %w", err)
		}

		if credentialsExists {
			// Decrypt existing credentials
			encryptedData, err := os.ReadFile(ce.CredentialsFile)
			if err != nil {
				return fmt.Errorf("failed to read encrypted credentials: %w", err)
			}
			plaintext, err = decryptConfig(encryptedData, hex.EncodeToString(masterKey))
			if err != nil {
				return fmt.Errorf("failed to decrypt credentials: %w", err)
			}
		} else {
			// Initialize with default content if credentials file does not exist
			plaintext = []byte("initial: data\n")
		}
	}

	// Create a temporary file for editing
	tmpfile, err := ioutil.TempFile("", "credentials-*.yml")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpfile.Name())

	// Write decrypted content to the temporary file
	if _, err := tmpfile.Write(plaintext); err != nil {
		return err
	}
	if err := tmpfile.Close(); err != nil {
		return err
	}

	// Open the temporary file in the specified editor
	cmd := exec.Command(ce.Editor, tmpfile.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to open editor: %w", err)
	}

	// Read edited content from the temporary file
	editedText, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		return fmt.Errorf("failed to read edited content: %w", err)
	}

	// Check if changes were made
	if bytes.Equal(editedText, plaintext) {
		fmt.Println("No changes made. Credentials remain the same.")
		return nil
	}

	// Encrypt and save the updated credentials file
	return ce.EncryptAndSave(editedText, hex.EncodeToString(masterKey))
}

// EncryptAndSave encrypts the provided data and writes it to the credentials file.
func (ce *ConfigEditor) EncryptAndSave(data []byte, keyString string) error {
	encryptedData, err := encryptConfig(keyString, data)
	if err != nil {
		return err
	}

	return os.WriteFile(ce.CredentialsFile, encryptedData, 0644)
}

// Helper function to check if a file exists
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}
