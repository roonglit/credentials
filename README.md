# credentials

The `credentials` module provides a secure way to manage both sensitive and non-sensitive configurations for Go applications. It supports encrypted configuration files, environment variables, and plain text configuration files, allowing users to easily manage settings securely and flexibly.

## Features

- **Encrypted Credentials**: Store sensitive configuration values (like API keys) in an encrypted file.
- **Environment Variables**: Environment variables can override configurations, providing additional flexibility.
- **Custom Configuration Structs**: Define your own configuration struct and pass it to the module, making it adaptable to any configuration needs.

## Security

Credentials are sealed with **AES-256-GCM**. GCM is authenticated: if the file is
modified by anyone without the master key, decryption fails loudly instead of
returning altered contents.

Versions before `v2` used AES-CFB, which is unauthenticated. Under CFB a
plaintext bit can be flipped by flipping the matching ciphertext bit — no key
required, and nothing detects it. Go's standard library now marks CFB deprecated
for this reason. If your `credentials.yml.enc` predates this change, see
[Migrating](#migrating).

The master key is written `0600`. The encrypted file is written `0644` — it is
meant to be committed; the key beside it never should be, which is what the
bundled `.gitignore` enforces.

## Installation

```sh
go install github.com/roonglit/credentials/cmd/credentials@latest
```

## Commands

```sh
credentials edit      # decrypt, open in $EDITOR, re-encrypt
credentials show      # print the decrypted contents to stdout
credentials migrate   # re-encrypt an old file, no editor needed
```

Environment:

| variable | meaning |
|---|---|
| `CREDENTIALS_DIR` | directory holding `master.key` and `credentials.yml.enc` (default `config`) |
| `VISUAL`, `EDITOR` | editor used by `edit` (default `vi`) |
| `CREDENTIALS_ALLOW_LEGACY` | set to `0` for strict mode: refuse pre-v2 files instead of warning |

`credentials edit` creates both files on first run. It refuses to generate a new
master key when an encrypted file already exists, since that would make the
existing file permanently unreadable.

## Migrating

**Upgrading does not break anything.** Old files still open, the exported API is
unchanged from v1.0.0, and no code change is required to bump the dependency.
Reading a pre-v2 file prints one warning per file:

```
credentials: config/credentials.yml.enc is in the legacy unauthenticated format.
It cannot detect tampering. Run `credentials migrate` to fix it permanently.
```

Migrate once, per project:

```sh
credentials migrate
```

It decrypts with the old format and rewrites with the new one, using the same
master key. Commit the result; the warning stops. `credentials edit` migrates as
a side effect of saving, so a file you were editing anyway needs nothing extra.

Writes are **always** in the current format — there is no way to write a legacy
file, which is what stops the old format lingering.

Set `CREDENTIALS_ALLOW_LEGACY=0` for strict mode, where an unmigrated file is an
error rather than a warning. Worth turning on in CI once you have migrated, so a
file cannot quietly regress.

## Reading Configuration in Your Project

### Install the Credentials Package

Run the following command to install the credentials package into your project:

```sh
go get github.com/roonglit/credentials/pkg/credentials
```

### Define Your Configuration Struct

Define a custom struct with fields that match the configuration keys in `credentials.yml.enc`. Use `mapstructure` tags to map the struct fields to the configuration keys.

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "github.com/roonglit/credentials/pkg/credentials"
)

// Define your custom configuration struct
type MyConfig struct {
    ServerAddress        string        `mapstructure:"SERVER_ADDRESS"`
    DBUri                string        `mapstructure:"DB_URI"`
    AccessTokenDuration  time.Duration `mapstructure:"ACCESS_TOKEN_DURATION"`
    RefreshTokenDuration time.Duration `mapstructure:"REFRESH_TOKEN_DURATION"`
    TokenSymmetricKey    string        `mapstructure:"TOKEN_SYMMETRIC_KEY"`
}
```

### Initialize and Use the `ConfigReader`

Use `ConfigReader` to load and decrypt configurations. The `Read` method will populate your custom struct with values from `credentials.yml.enc` and environment variables.

Here's how to initialize and use the `ConfigReader` with the default configuration folder:

```go
func main() {
    // Initialize the ConfigReader with the default config folder
    reader := credentials.NewConfigReader()

    // User-defined configuration struct
    var config MyConfig

    // Read configuration with mode "debug" or "production"
    if err := reader.Read("debug", &config); err != nil {
        log.Fatalf("Failed to read configuration: %v", err)
    }

    fmt.Printf("Loaded Configuration: %+v\n", config)
}
```

If your configuration folder is different, you can provide the path as an argument:

```go
reader := credentials.NewConfigReader("path/to/config")
```

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! If you have suggestions or improvements, feel free to open a pull request.

