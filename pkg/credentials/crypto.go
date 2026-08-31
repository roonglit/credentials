package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// On-disk formats.
//
//	v2 (current)  magicV2 || nonce(12) || AES-256-GCM(plaintext) || tag(16)
//	v1 (legacy)   iv(16)  || AES-256-CFB(plaintext)
//
// v1 is READ-ONLY. It is unauthenticated: CFB decrypts as
// P[0] = C[0] XOR E(IV), so anyone who can write the file can flip a chosen
// plaintext bit without ever holding the key, and nothing detects it. Go's own
// stdlib now marks CFB deprecated for exactly this reason.
//
// v2 is authenticated, so tampering fails loudly instead of succeeding quietly.
// Files are migrated the first time they are written — `credentials edit` and
// `credentials migrate` both do it — so no coordinated cutover is needed.
var magicV2 = []byte("CREDS-v2")

const (
	// keyLength is fixed at 32 bytes. aes.NewCipher would happily accept 16 or
	// 24 and silently give AES-128 or AES-192, which is exactly the kind of
	// downgrade a truncated master.key causes.
	keyLength = 32

	gcmNonceSize = 12
)

var (
	// ErrTampered means the ciphertext failed authentication: the file was
	// modified, or the wrong key was supplied. Both are refusals to proceed.
	ErrTampered = errors.New("credentials: ciphertext failed authentication (wrong key, or the file was modified)")

	ErrShortCiphertext  = errors.New("credentials: ciphertext too short")
	ErrInvalidKeyLength = fmt.Errorf("credentials: master key must be %d bytes", keyLength)

	// ErrLegacyFormat means the file is still in the old unauthenticated
	// format. Reading it is opt-in — see decryptLegacy.
	ErrLegacyFormat = errors.New("credentials: file is in the legacy unauthenticated format; run `credentials migrate`")
)

// encrypt seals plaintext in the current format.
func encrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("credentials: read nonce: %w", err)
	}

	out := make([]byte, 0, len(magicV2)+gcmNonceSize+len(plaintext)+aead.Overhead())
	out = append(out, magicV2...)
	out = append(out, nonce...)

	// The magic is passed as additional data, so a v2 file cannot be
	// downgraded to look like something else without failing authentication.
	return aead.Seal(out, nonce, plaintext, magicV2), nil
}

// decrypt opens an authenticated blob. This is the ONLY decryption path used at
// runtime — it used to be duplicated in the reader, where a change to one could
// silently diverge from the other.
//
// It deliberately REFUSES the legacy format rather than falling back to it.
// Dispatching on the magic prefix would mean an attacker could corrupt that one
// prefix and force a v2 file down the unauthenticated path, converting a file
// that detects tampering into one that cannot — a downgrade attack that costs a
// single byte. Legacy files are opened only through decryptLegacy, which a
// caller has to ask for.
func decrypt(key, blob []byte) ([]byte, error) {
	if isLegacyFormat(blob) {
		return nil, ErrLegacyFormat
	}
	return decryptGCM(key, blob)
}

// decryptLegacy opens a pre-v2 file. Callers must opt in, because nothing about
// this path can detect tampering — that is the property the format lacked.
func decryptLegacy(key, blob []byte) ([]byte, error) {
	if !isLegacyFormat(blob) {
		return decryptGCM(key, blob)
	}
	return decryptLegacyCFB(key, blob)
}

// isLegacyFormat reports whether a blob is a pre-v2, unauthenticated file.
//
// A v1 file begins with a random 16-byte IV, so it collides with the 8-byte
// magic with probability 2^-64 — small enough to ignore, and a collision fails
// closed with an authentication error rather than returning wrong plaintext.
func isLegacyFormat(blob []byte) bool {
	return len(blob) < len(magicV2) || string(blob[:len(magicV2)]) != string(magicV2)
}

func decryptGCM(key, blob []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	if len(blob) < len(magicV2)+gcmNonceSize+aead.Overhead() {
		return nil, ErrShortCiphertext
	}

	nonce := blob[len(magicV2) : len(magicV2)+gcmNonceSize]
	sealed := blob[len(magicV2)+gcmNonceSize:]

	plaintext, err := aead.Open(nil, nonce, sealed, magicV2)
	if err != nil {
		// Deliberately opaque: distinguishing "wrong key" from "modified file"
		// tells an attacker which half of the problem they have solved.
		return nil, ErrTampered
	}
	return plaintext, nil
}

// decryptLegacyCFB reads the old unauthenticated format so existing files keep
// working across the upgrade. It is never used for writing.
func decryptLegacyCFB(key, blob []byte) ([]byte, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	if len(blob) < aes.BlockSize {
		return nil, ErrShortCiphertext
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := blob[:aes.BlockSize]
	ciphertext := make([]byte, len(blob)-aes.BlockSize)
	copy(ciphertext, blob[aes.BlockSize:])

	//lint:ignore SA1019 legacy read path only; new files are written with GCM.
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("credentials: new cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("credentials: new gcm: %w", err)
	}
	return aead, nil
}

func checkKey(key []byte) error {
	if len(key) != keyLength {
		return fmt.Errorf("%w, got %d", ErrInvalidKeyLength, len(key))
	}
	return nil
}
