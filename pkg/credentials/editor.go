package credentials

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// DefaultEditor is used when no editor is configured and neither $VISUAL nor
// $EDITOR is set.
const DefaultEditor = "vi"

// ConfigEditor decrypts the credentials file, hands it to an editor, and seals
// it again.
type ConfigEditor struct {
	ConfigDir       string
	CredentialsFile string
	MasterKeyFile   string
	Editor          string

	// AllowLegacy permits reading the old unauthenticated format. Off by
	// default: see decrypt in crypto.go for why the fallback is not automatic.
	// `credentials migrate` turns it on for exactly one read.
	AllowLegacy bool
}

// NewConfigEditor builds an editor for the given paths.
//
// An empty editor resolves from the environment at edit time — $VISUAL, then
// $EDITOR, then DefaultEditor — rather than being pinned to one person's
// preference.
func NewConfigEditor(configDir, credentialsFile, masterKeyFile, editor string) *ConfigEditor {
	return &ConfigEditor{
		ConfigDir:       configDir,
		CredentialsFile: filepath.Join(configDir, credentialsFile),
		MasterKeyFile:   filepath.Join(configDir, masterKeyFile),
		Editor:          editor,
	}
}

// OpenEditor decrypts, edits, and re-encrypts the credentials file.
//
// Re-encryption always writes the current format, so a legacy file is migrated
// off unauthenticated CFB simply by being edited.
func (ce *ConfigEditor) OpenEditor() error {
	key, plaintext, err := ce.load()
	if err != nil {
		return err
	}

	edited, err := ce.edit(plaintext)
	if err != nil {
		return err
	}

	if bytes.Equal(edited, plaintext) {
		// Still rewrite a legacy file: the point of this pass is the format, and
		// an unchanged one would otherwise stay unauthenticated forever.
		if blob, readErr := os.ReadFile(ce.CredentialsFile); readErr == nil && isLegacyFormat(blob) {
			fmt.Println("No changes made, but migrating the file to the authenticated format.")
			return ce.EncryptAndSave(edited, key)
		}
		fmt.Println("No changes made. Credentials remain the same.")
		return nil
	}

	return ce.EncryptAndSave(edited, key)
}

// Migrate re-encrypts an existing file in the current format without opening an
// editor, for hosts and CI where there is no terminal to attach.
func (ce *ConfigEditor) Migrate() error {
	blob, err := os.ReadFile(ce.CredentialsFile)
	if err != nil {
		return fmt.Errorf("credentials: read %s: %w", ce.CredentialsFile, err)
	}
	if !isLegacyFormat(blob) {
		fmt.Println("Already in the authenticated format. Nothing to do.")
		return nil
	}

	key, err := ReadMasterKey(ce.MasterKeyFile)
	if err != nil {
		return err
	}

	plaintext, err := decryptLegacy(key, blob)
	if err != nil {
		return err
	}
	if err := ce.EncryptAndSave(plaintext, key); err != nil {
		return err
	}
	fmt.Println("Migrated", ce.CredentialsFile, "to the authenticated format.")
	return nil
}

// open decrypts according to this editor's legacy policy.
func (ce *ConfigEditor) open(key, blob []byte) ([]byte, error) {
	if ce.AllowLegacy {
		return decryptLegacy(key, blob)
	}
	return decrypt(key, blob)
}

// Show returns the decrypted contents.
func (ce *ConfigEditor) Show() ([]byte, error) {
	key, err := ReadMasterKey(ce.MasterKeyFile)
	if err != nil {
		return nil, err
	}

	blob, err := os.ReadFile(ce.CredentialsFile)
	if err != nil {
		return nil, fmt.Errorf("credentials: read %s: %w", ce.CredentialsFile, err)
	}
	return ce.open(key, blob)
}

// EncryptAndSave seals data and writes it to the credentials file.
func (ce *ConfigEditor) EncryptAndSave(data, key []byte) error {
	blob, err := encrypt(key, data)
	if err != nil {
		return err
	}
	// 0644 is fine: the contents are encrypted and authenticated, and the file
	// is meant to be committed. The master key next to it is 0600.
	return os.WriteFile(ce.CredentialsFile, blob, 0o644)
}

// load resolves the key and current plaintext, creating both on first run.
func (ce *ConfigEditor) load() (key, plaintext []byte, err error) {
	if err := os.MkdirAll(ce.ConfigDir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("credentials: create %s: %w", ce.ConfigDir, err)
	}

	keyExists := fileExists(ce.MasterKeyFile)
	credsExist := fileExists(ce.CredentialsFile)

	switch {
	case !keyExists && credsExist:
		// Refusing here is the important case: generating a fresh key would make
		// the existing file permanently unreadable.
		return nil, nil, fmt.Errorf("credentials: %s is missing but %s exists; editing is not allowed",
			ce.MasterKeyFile, ce.CredentialsFile)

	case !keyExists && !credsExist:
		fmt.Println("No master key found. Generating one at", ce.MasterKeyFile)
		key, err = GenerateMasterKey(ce.MasterKeyFile)
		if err != nil {
			return nil, nil, err
		}
		plaintext = []byte("initial: data\n")
		if err := ce.EncryptAndSave(plaintext, key); err != nil {
			return nil, nil, fmt.Errorf("credentials: create initial file: %w", err)
		}
		return key, plaintext, nil

	default:
		key, err = ReadMasterKey(ce.MasterKeyFile)
		if err != nil {
			return nil, nil, err
		}
		if !credsExist {
			return key, []byte("initial: data\n"), nil
		}

		blob, err := os.ReadFile(ce.CredentialsFile)
		if err != nil {
			return nil, nil, fmt.Errorf("credentials: read %s: %w", ce.CredentialsFile, err)
		}
		plaintext, err = ce.open(key, blob)
		if err != nil {
			return nil, nil, err
		}
		return key, plaintext, nil
	}
}

// edit round-trips plaintext through the user's editor.
func (ce *ConfigEditor) edit(plaintext []byte) ([]byte, error) {
	// 0600 from the start: this is the one moment the secrets exist in the
	// clear on disk, and CreateTemp's default is already 0600 — made explicit
	// here so it survives anyone changing the temp strategy.
	tmp, err := os.CreateTemp("", "credentials-*.yml")
	if err != nil {
		return nil, fmt.Errorf("credentials: create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		return nil, err
	}
	if _, err := tmp.Write(plaintext); err != nil {
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	cmd := exec.Command(ce.editorCommand(), tmp.Name())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("credentials: editor exited with an error: %w", err)
	}

	edited, err := os.ReadFile(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("credentials: read edited file: %w", err)
	}
	return edited, nil
}

func (ce *ConfigEditor) editorCommand() string {
	for _, candidate := range []string{ce.Editor, os.Getenv("VISUAL"), os.Getenv("EDITOR")} {
		if candidate != "" {
			return candidate
		}
	}
	return DefaultEditor
}

func fileExists(name string) bool {
	info, err := os.Stat(name)
	return err == nil && !info.IsDir()
}
