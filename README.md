# credentials

The `credentials` module provides a secure way to manage both sensitive and non-sensitive configurations for Go applications. It supports encrypted configuration files, environment variables, and plain text configuration files, allowing users to easily manage settings securely and flexibly.

## Features

- **Encrypted Credentials**: Store sensitive configuration values (like API keys) in an encrypted file.
- **Plain Text Configurations**: Manage non-sensitive configurations in a simple YAML file.
- **Environment Variables**: Environment variables can override configurations, providing additional flexibility.
- **Custom Configuration Structs**: Define your own configuration struct and pass it to the module, making it adaptable to any configuration needs.

## Installation

To use this module in your project, first install it and its dependencies.

### 1. Add the Module

Run the following command to add this module to your project:

```sh
go get github.com/yourusername/credentials
```

### 2. Add Dependencies

This module depends on `viper` for configuration management. Install `viper` using:

```sh
go get github.com/spf13/viper
```

After these steps, your `go.mod` should reflect both modules as dependencies.

## Setting Up Your Configuration

### 1. Create `master.key`

The `master.key` file is used to encrypt and decrypt sensitive data in `credentials.yml.enc`. The `master.key` will be generated automatically if it does not exist when running the module for the first time.

### 2. Create Encrypted Configuration File (`credentials.yml.enc`)

Store sensitive information in an encrypted file named `credentials.yml.enc`. Use the module's editor to initialize and manage this file. **Ensure `master.key` is present before editing the file.**

### 3. Create Plain Text Configuration File (`application.yaml`)

For non-sensitive configurations, create an `application.yaml` file in the `config` directory. Here’s an example:

```yaml
debug:
  ServerAddress: "localhost:8080"
  DBUri: "mongodb://localhost:27017"
production:
  ServerAddress: "prodserver:8080"
  DBUri: "mongodb://prodserver:27017"
```

## Usage

### Define Your Configuration Struct

Define a custom struct with fields that match the configuration keys in `application.yaml` and `credentials.yml.enc`. Use `mapstructure` tags to map the struct fields to the configuration keys.

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "github.com/yourusername/credentials/pkg/credentials"
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

Use `ConfigReader` to load and decrypt configurations. The `Read` method will populate your custom struct with values from `application.yaml`, `credentials.yml.enc`, and environment variables.

```go
func main() {
    configDir := "config"
    credentialsFile := "credentials.yml.enc"
    masterKeyFile := "master.key"
    applicationConfig := "config/application.yaml"

    reader := credentials.NewConfigReader(configDir, credentialsFile, masterKeyFile, applicationConfig)

    // User-defined configuration struct
    var config MyConfig

    // Read configuration with mode "debug" or "production"
    if err := reader.Read("debug", &config); err != nil {
        log.Fatalf("Failed to read configuration: %v", err)
    }

    fmt.Printf("Loaded Configuration: %+v\n", config)
}
```

### Running the Application

## Installing the Credentials Command-Line Tool

To use the `credentials` command-line tool, you can install it using `go install`:

1. **Install the Tool Globally**:

   Run the following command to install the `credentials` command-line tool globally:

   ```sh
   go install github.com/yourusername/credentials/cmd/credentials@latest
   ```

   This will install the `credentials` tool to your Go binaries, allowing you to use it anywhere on your system.

2. **Edit Encrypted Configuration**:
   If this is the first time setting up, the `master.key` will be generated automatically if it does not exist. Then, use the `credentials` command-line tool to open and edit `credentials.yml.enc`.

   ```sh
   credentials edit
   ```

1. **Edit Encrypted Configuration**:
   If this is the first time setting up, the `master.key` will be generated automatically if it does not exist. Then, use the built `credentials` command-line tool to open and edit `credentials.yml.enc`.

   ```sh
   ./credentials edit
   ```

## Example Commands

- **Edit Encrypted Configuration**: Use the installed `credentials` command-line tool to edit the encrypted configuration.

  ```sh
  credentials edit
  ```

- **Read Configuration**: Read and display decrypted configurations. This command decrypts and loads values into the struct provided to `Read`.

  ```go
  ./credentials read
  ```

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! If you have suggestions or improvements, feel free to open a pull request.

