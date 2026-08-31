package credentials

import (
	"fmt"
	"os"
	"sync"
)

// Backward compatibility with files written before the format gained
// authentication.
//
// Upgrading the module must never stop an existing credentials file from
// opening — a config loader that refuses to boot is a worse outcome than an
// unauthenticated read, and the operator may not even know which of their
// services is on the old format. So legacy reads are ON by default and warn;
// strict mode is opt-in.
//
// Writes are always in the current format, so `credentials edit` or
// `credentials migrate` fixes a file permanently and the warning stops.

// EnvAllowLegacy toggles legacy reads. Set it to "0" or "false" for strict mode,
// where an unmigrated file is an error instead of a warning.
const EnvAllowLegacy = "CREDENTIALS_ALLOW_LEGACY"

func legacyAllowed() bool {
	switch os.Getenv(EnvAllowLegacy) {
	case "0", "false", "no":
		return false
	default:
		return true
	}
}

var warned sync.Map

// openBlob decrypts according to the caller's legacy policy, warning once per
// file when the old format is actually used.
func openBlob(key, blob []byte, allowLegacy bool, path string) ([]byte, error) {
	if !isLegacyFormat(blob) {
		return decryptGCM(key, blob)
	}

	if !allowLegacy {
		return nil, fmt.Errorf("%w (%s)", ErrLegacyFormat, path)
	}

	// Once per path, to stderr: a warning on every read of a hot config would
	// be noise, and silence would let a file stay unauthenticated forever.
	if _, seen := warned.LoadOrStore(path, true); !seen {
		fmt.Fprintf(os.Stderr,
			"credentials: %s is in the legacy unauthenticated format. "+
				"It cannot detect tampering. Run `credentials migrate` to fix it permanently.\n",
			path)
	}

	return decryptLegacyCFB(key, blob)
}
