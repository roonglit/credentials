package credentials

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

const masterKeyLength = 32 // 32 bytes for AES-256

// generateMasterKey generates a new AES-256 master key and saves it to the specified path.
func generateMasterKey(path string) ([]byte, error) {
	masterKey := make([]byte, masterKeyLength)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, err
	}

	if err := os.WriteFile(path, []byte(hex.EncodeToString(masterKey)), 0600); err != nil {
		return nil, err
	}
	fmt.Println("New master key generated at", path)
	return masterKey, nil
}

// readMasterKey reads the AES-256 master key from the specified path.
func readMasterKey(path string) ([]byte, error) {
	keyHex, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return hex.DecodeString(string(keyHex))
}
