package credentials

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, keyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := testKey(t)

	cases := map[string][]byte{
		"empty":      {},
		"short":      []byte("a"),
		"yaml":       []byte("development:\n  db_uri: postgres://localhost/app\n"),
		"utf8":       []byte("ของยังไม่ถึงเลยค่ะ\n"),
		"multiblock": bytes.Repeat([]byte("secret-value-"), 500),
	}

	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			blob, err := encrypt(key, plaintext)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if isLegacyFormat(blob) {
				t.Fatal("encrypt produced a legacy-format blob")
			}

			got, err := decrypt(key, blob)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("round trip changed the plaintext:\n got %q\nwant %q", got, plaintext)
			}
		})
	}
}

// The reason this package exists in its current form: a modified file must fail
// loudly rather than decrypt to attacker-chosen plaintext. Under the old CFB
// format this test could not pass — flipping a ciphertext bit flipped the
// corresponding plaintext bit and nothing noticed.
func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	key := testKey(t)
	blob, err := encrypt(key, []byte("db_password: hunter2\n"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	for _, offset := range []int{
		0,                           // the magic
		len(magicV2),                // the nonce
		len(magicV2) + gcmNonceSize, // the ciphertext
		len(blob) - 1,               // the auth tag
	} {
		tampered := append([]byte(nil), blob...)
		tampered[offset] ^= 0x20

		if _, err := decrypt(key, tampered); err == nil {
			t.Errorf("byte %d: tampering was accepted", offset)
		}
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	blob, err := encrypt(testKey(t), []byte("secret\n"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := decrypt(testKey(t), blob); !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
}

// A truncated master.key must not silently downgrade AES-256 to AES-128 —
// aes.NewCipher accepts 16 and 24 byte keys quite happily.
func TestRejectsWrongKeyLength(t *testing.T) {
	for _, size := range []int{0, 16, 24, 31, 33} {
		if _, err := encrypt(make([]byte, size), []byte("x")); !errors.Is(err, ErrInvalidKeyLength) {
			t.Errorf("key size %d: err = %v, want ErrInvalidKeyLength", size, err)
		}
	}
}

// Existing files must keep opening across the upgrade, or every consumer breaks
// on the release that changes the format.
func TestDecryptReadsLegacyCFBFiles(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("legacy: true\napi_key: abc123\n")

	legacy := encryptLegacyCFB(t, key, plaintext)
	if !isLegacyFormat(legacy) {
		t.Fatal("fixture is not in the legacy format")
	}

	// The default path refuses it — a corrupted magic must not be a route to
	// the unauthenticated reader.
	if _, err := decrypt(key, legacy); !errors.Is(err, ErrLegacyFormat) {
		t.Fatalf("decrypt(legacy) err = %v, want ErrLegacyFormat", err)
	}

	got, err := decryptLegacy(key, legacy)
	if err != nil {
		t.Fatalf("decryptLegacy: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("got %q, want %q", got, plaintext)
	}
}

func TestDecryptRejectsShortInput(t *testing.T) {
	if _, err := decrypt(testKey(t), []byte("CREDS-v2")); !errors.Is(err, ErrShortCiphertext) {
		t.Fatalf("err = %v, want ErrShortCiphertext", err)
	}
}

// encryptLegacyCFB reproduces the pre-v2 writer, so the compatibility path has a
// real fixture to read rather than a hand-copied blob.
func encryptLegacyCFB(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}

	out := make([]byte, aes.BlockSize+len(plaintext))
	iv := out[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		t.Fatalf("read iv: %v", err)
	}

	//lint:ignore SA1019 deliberately reproducing the old format under test.
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(out[aes.BlockSize:], plaintext)
	return out
}
