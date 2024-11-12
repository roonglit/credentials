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

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! If you have suggestions or improvements, feel free to open a pull request.

