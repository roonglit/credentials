package credentials

import (
	"os"
	"path/filepath"
)

// Per-environment credentials, in the shape Rails has used since 6.0:
//
//	config/credentials.yml.enc            + config/master.key             shared
//	config/credentials/staging.yml.enc    + config/credentials/staging.key
//	config/credentials/production.yml.enc + config/credentials/production.key
//
// The point is not tidiness, it is KEY separation. With one file and one master
// key, anyone who can boot the app in development can decrypt production — a new
// hire gets master.key on their first day, and it opens the production database
// URL. Separate files mean separate keys, so a leaked development key leaks only
// development.
//
// Resolution is deliberately forgiving: a project with only the shared file
// keeps working exactly as before, and adopting a per-environment file for
// production alone is a valid halfway state.

// EnvKeyVar overrides the key file entirely, so a container can carry the key in
// its environment instead of on disk — the role RAILS_MASTER_KEY plays in Rails.
const EnvKeyVar = "CREDENTIALS_KEY"

// paths describes which files an environment resolves to.
type paths struct {
	credentials string
	key         string

	// scoped is true when the file belongs to ONE environment, in which case the
	// whole file is that environment's config. The shared file instead holds a
	// section per environment and has to be unmarshalled by key.
	scoped bool
}

// resolve picks the per-environment file when one exists, and the shared file
// otherwise.
func resolve(configDir, environment string, sharedCredentials, sharedKey string) paths {
	if environment != "" {
		scopedCreds := filepath.Join(configDir, "credentials", environment+".yml.enc")
		if fileExists(scopedCreds) {
			return paths{
				credentials: scopedCreds,
				key:         filepath.Join(configDir, "credentials", environment+".key"),
				scoped:      true,
			}
		}
	}

	return paths{credentials: sharedCredentials, key: sharedKey, scoped: false}
}

// readKey loads the master key for these paths, preferring the environment.
func readKey(p paths) ([]byte, error) {
	if hex := os.Getenv(EnvKeyVar); hex != "" {
		return decodeKey(hex, EnvKeyVar)
	}
	return ReadMasterKey(p.key)
}

// EnvironmentPaths reports where a given environment's credentials would live.
// Useful for tooling and error messages; it does not require the files to exist.
func EnvironmentPaths(configDir, environment string) (credentialsFile, keyFile string) {
	if environment == "" {
		return filepath.Join(configDir, "credentials.yml.enc"), filepath.Join(configDir, "master.key")
	}
	return filepath.Join(configDir, "credentials", environment+".yml.enc"),
		filepath.Join(configDir, "credentials", environment+".key")
}
