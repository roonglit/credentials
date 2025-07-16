# credentials

The `credentials` module provides a secure way to manage both sensitive and non-sensitive configurations for Go applications. It supports encrypted configuration files, environment variables, and plain text configuration files, allowing users to easily manage settings securely and flexibly.

## Features

- **Encrypted Credentials**: Store sensitive configuration values (like API keys) in an encrypted file.
- **Environment Variables**: Environment variables can override configurations, providing additional flexibility.
- **Custom Configuration Structs**: Define your own configuration struct and pass it to the module, making it adaptable to any configuration needs.

## Installation

To use this module in your project, install it and its dependencies using `go install`.

### 1. Install the Tool Globally

Run the following command to install the `credentials` command-line tool globally:

```sh
go install github.com/roonglit/credentials/cmd/credentials@latest
```

This will install the `credentials` tool to your Go binaries, allowing you to use it anywhere on your system.

## Initialize Configuration Files

To initialize the configuration files, use the `credentials edit` command. This command will generate the `master.key` and create the `credentials.yml.enc` file in the `config` folder if they do not already exist.

- **`master.key`**: This file is used to encrypt and decrypt sensitive data in `credentials.yml.enc`. It will be generated automatically in the `config` folder if it does not exist.
- **`credentials.yml.enc`**: This encrypted file stores sensitive information, such as API keys. It will also be created in the `config` folder.

To edit or initialize the encrypted configuration, run the following command:

```sh
credentials edit
```

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

## Secret Manager Integration

The `credentials` module now supports integration with external secret management systems, including Google Cloud Secret Manager and HashiCorp Vault. This allows you to store sensitive values in secure secret management services while maintaining the same simple configuration interface.

### Supported Secret Managers

1. **Google Cloud Secret Manager**
2. **HashiCorp Vault**

### How It Works

The module supports two modes of operation:

1. **Secret Manager Mode**: When activated, ALL configuration values are loaded from a single secret manager
2. **Default Mode**: Configuration values are loaded from the credentials file and can be overridden by environment variables

### Configuration Priority

The module follows this priority order when loading configuration values:

1. **Secret Manager Mode**: If a secret manager is activated (e.g., `GOOGLE_SECRET` is set), ALL configuration values are retrieved from that secret manager using the `mapstructure` tag names
2. **Default Mode**: If no secret manager is activated:
   - Environment variables override values from the credentials file
   - Values not found in environment variables are loaded from the encrypted credentials file

**Important**: When a secret manager is activated, it overrides ALL other sources. If a configuration value is not found in the secret manager, it will be empty (no fallback to environment variables or credentials file).

### Google Cloud Secret Manager Setup

To use Google Cloud Secret Manager:

1. **Set up authentication**: Ensure you have proper Google Cloud credentials configured
2. **Set required environment variables**:
   ```bash
   export GOOGLE_PROJECT_ID="your-project-id"
   export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
   # OR if running on Google Cloud
   export GOOGLE_CLOUD_PROJECT="your-project-id"
   ```

3. **Activate Google Secret Manager**: Set the activation environment variable:
   ```bash
   export GOOGLE_SECRET="1"
   ```

4. **Create secrets in Google Cloud**: Make sure the secrets exist in your Google Cloud Secret Manager with names matching your configuration struct's `mapstructure` tags (e.g., `DATABASE_URL`, `API_KEY`, `JWT_SECRET`, etc.).

### HashiCorp Vault Setup

To use HashiCorp Vault:

1. **Set up Vault connection**:
   ```bash
   export VAULT_ADDR="https://vault.example.com"
   export VAULT_TOKEN="your-vault-token"
   ```

2. **Activate Vault Secret Manager**: Set the activation environment variable:
   ```bash
   export VAULT_SECRET="1"
   ```

3. **Store secrets in Vault**: Make sure the secrets exist in your Vault instance with names matching your configuration struct's `mapstructure` tags (e.g., `DATABASE_URL`, `API_KEY`, `JWT_SECRET`, etc.).

### Example Usage with Secret Managers

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "github.com/roonglit/credentials/pkg/credentials"
)

type MyConfig struct {
    ServerAddress        string        `mapstructure:"SERVER_ADDRESS"`
    DBPassword           string        `mapstructure:"DB_PASSWORD"`
    APIKey               string        `mapstructure:"API_KEY"`
    AccessTokenDuration  time.Duration `mapstructure:"ACCESS_TOKEN_DURATION"`
}

func main() {
    // Initialize the ConfigReader
    reader := credentials.NewConfigReader()

    var config MyConfig

    // Read configuration - will automatically check secret managers
    // if GOOGLE_SECRET or VAULT_SECRET environment variables are set
    if err := reader.Read("production", &config); err != nil {
        log.Fatalf("Failed to read configuration: %v", err)
    }

    fmt.Printf("Loaded Configuration: %+v\n", config)
    
    // The configuration will be loaded from:
    // 1. Google Secret Manager if GOOGLE_SECRET is set (ALL values from secret manager)
    // 2. Vault if VAULT_SECRET is set (ALL values from secret manager)
    // 3. Environment variables + credentials.yml.enc file if no secret manager is activated
}
```

### Environment Variable Examples

```bash
# Use Google Cloud Secret Manager for ALL configuration values
export GOOGLE_PROJECT_ID="my-project"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
export GOOGLE_SECRET="1"
# Now ALL config values will be loaded from Google Secret Manager
# using the mapstructure tag names (DATABASE_URL, API_KEY, etc.)

# Use Vault for ALL configuration values
export VAULT_ADDR="https://vault.company.com"
export VAULT_TOKEN="hvs.ABC123..."
export VAULT_SECRET="1"
# Now ALL config values will be loaded from Vault
# using the mapstructure tag names (DATABASE_URL, API_KEY, etc.)

# Use default mode (credentials file + environment variables)
export SERVER_ADDRESS="localhost:8080"
export DATABASE_URL="postgres://localhost:5432/mydb"
# Values from environment variables override credentials file
```

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! If you have suggestions or improvements, feel free to open a pull request.

