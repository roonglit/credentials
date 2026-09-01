package credentials

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	// AllowLegacy permits reading the old unauthenticated format. ON by
	// default, so upgrading the module never stops an existing file from
	// opening; set it false (or CREDENTIALS_ALLOW_LEGACY=0) for strict mode.
	// Writes are always in the current format, so any save migrates the file.
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
		AllowLegacy:     legacyAllowed(),
	}
}

// NewEnvironmentEditor edits ONE environment's credentials, at
// <configDir>/credentials/<environment>.yml.enc with its own key beside it.
//
// Prefer this over NewConfigEditor for anything but development: a key that
// opens only staging cannot also open production.
func NewEnvironmentEditor(configDir, environment, editor string) *ConfigEditor {
	credentialsFile, keyFile := EnvironmentPaths(configDir, environment)

	return &ConfigEditor{
		// The scoped pair lives one directory down, and that is the directory
		// that has to exist before writing.
		ConfigDir:       filepath.Dir(credentialsFile),
		CredentialsFile: credentialsFile,
		MasterKeyFile:   keyFile,
		Editor:          editor,
		AllowLegacy:     legacyAllowed(),
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
			return ce.encryptAndSave(edited, key)
		}
		fmt.Println("No changes made. Credentials remain the same.")
		return nil
	}

	return ce.encryptAndSave(edited, key)
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

	key, err := ce.key()
	if err != nil {
		return err
	}

	plaintext, err := decryptLegacy(key, blob)
	if err != nil {
		return err
	}
	if err := ce.encryptAndSave(plaintext, key); err != nil {
		return err
	}
	fmt.Println("Migrated", ce.CredentialsFile, "to the authenticated format.")
	return nil
}

// key resolves this editor's master key.
//
// It goes through readKey rather than reading the file directly, so
// CREDENTIALS_KEY works for `credentials show` and `credentials edit` exactly as
// it does for the reader. They diverged once: the reader honoured the variable
// and the editor did not, which made `show` quietly fall back to the key on disk
// and look like it had decrypted something it should not have.
func (ce *ConfigEditor) key() ([]byte, error) {
	return readKey(paths{key: ce.MasterKeyFile})
}

// open decrypts according to this editor's legacy policy.
func (ce *ConfigEditor) open(key, blob []byte) ([]byte, error) {
	return openBlob(key, blob, ce.AllowLegacy, ce.CredentialsFile)
}

// Show returns the decrypted contents.
func (ce *ConfigEditor) Show() ([]byte, error) {
	key, err := ce.key()
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
//
// keyString is hex, matching the v1.0.0 signature — this is a published API and
// the format change underneath it is not a reason to break callers.
func (ce *ConfigEditor) EncryptAndSave(data []byte, keyString string) error {
	key, err := hex.DecodeString(strings.TrimSpace(keyString))
	if err != nil {
		return fmt.Errorf("credentials: master key is not valid hex: %w", err)
	}
	return ce.encryptAndSave(data, key)
}

// encryptAndSave is the internal path, taking the key as raw bytes.
func (ce *ConfigEditor) encryptAndSave(data, key []byte) error {
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
		if err := ce.encryptAndSave(plaintext, key); err != nil {
			return nil, nil, fmt.Errorf("credentials: create initial file: %w", err)
		}
		return key, plaintext, nil

	default:
		key, err = ce.key()
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
