package credentials

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// GenerateMasterKey writes a new AES-256 key, hex-encoded, at path.
//
// It refuses to overwrite an existing key: doing so would make every file
// encrypted with the old one unreadable, with no warning and no way back.
func GenerateMasterKey(path string) ([]byte, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("credentials: %s already exists; refusing to overwrite it", path)
	}

	key := make([]byte, keyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("credentials: generate master key: %w", err)
	}

	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		return nil, fmt.Errorf("credentials: write master key: %w", err)
	}
	return key, nil
}

// ReadMasterKey loads and validates the key at path.
func ReadMasterKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("credentials: read master key: %w", err)
	}

	return decodeKey(string(raw), path)
}

// decodeKey validates a hex key from any source — a file or an environment
// variable — so both routes fail the same way.
func decodeKey(raw, source string) ([]byte, error) {
	// Trim first. A key written with `echo $MASTER_KEY > master.key`, or piped
	// through base64 -d in a Dockerfile, carries a trailing newline — which
	// makes hex decoding fail with an error that says nothing about newlines.
	key, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("credentials: key from %s is not valid hex: %w", source, err)
	}

	if err := checkKey(key); err != nil {
		return nil, fmt.Errorf("%w (from %s)", err, source)
	}
	return key, nil
}
