package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/roonglit/credentials/pkg/credentials"
)

type ExampleConfig struct {
	ServerAddress        string        `mapstructure:"SERVER_ADDRESS"`
	DatabaseURL          string        `mapstructure:"DATABASE_URL"`
	APIKey               string        `mapstructure:"API_KEY"`
	JWTSecret            string        `mapstructure:"JWT_SECRET"`
	AccessTokenDuration  time.Duration `mapstructure:"ACCESS_TOKEN_DURATION"`
	Debug                bool          `mapstructure:"DEBUG"`
}

func main() {
	fmt.Println("Credentials Secret Manager Integration Example")
	fmt.Println("============================================")

	// Initialize the ConfigReader
	reader := credentials.NewConfigReader()

	var config ExampleConfig

	// Read configuration - will automatically check secret managers
	if err := reader.Read("development", &config); err != nil {
		log.Fatalf("Failed to read configuration: %v", err)
	}

	fmt.Printf("Loaded Configuration:\n")
	fmt.Printf("  Server Address: %s\n", config.ServerAddress)
	fmt.Printf("  Database URL: %s\n", maskSensitive(config.DatabaseURL))
	fmt.Printf("  API Key: %s\n", maskSensitive(config.APIKey))
	fmt.Printf("  JWT Secret: %s\n", maskSensitive(config.JWTSecret))
	fmt.Printf("  Access Token Duration: %v\n", config.AccessTokenDuration)
	fmt.Printf("  Debug: %v\n", config.Debug)

	fmt.Println("\nSecret Manager Configuration:")
	fmt.Printf("  Google Project ID: %s\n", os.Getenv("GOOGLE_PROJECT_ID"))
	fmt.Printf("  Google Application Credentials: %s\n", maskSensitive(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")))
	fmt.Printf("  Vault Address: %s\n", os.Getenv("VAULT_ADDR"))
	fmt.Printf("  Vault Token: %s\n", maskSensitive(os.Getenv("VAULT_TOKEN")))

	fmt.Println("\nSecret Manager Activation:")
	fmt.Printf("  GOOGLE_SECRET: %s\n", os.Getenv("GOOGLE_SECRET"))
	fmt.Printf("  VAULT_SECRET: %s\n", os.Getenv("VAULT_SECRET"))

	fmt.Println("\nExample usage:")
	fmt.Println("  # To use Google Cloud Secret Manager for ALL configuration values:")
	fmt.Println("  export GOOGLE_PROJECT_ID=\"my-project\"")
	fmt.Println("  export GOOGLE_APPLICATION_CREDENTIALS=\"/path/to/service-account.json\"")
	fmt.Println("  export GOOGLE_SECRET=\"1\"  # This activates Google Secret Manager")
	fmt.Println("  # Now all config values will be loaded from Google Secret Manager")
	fmt.Println("  # using the mapstructure tag names (DATABASE_URL, API_KEY, etc.)")
	fmt.Println("")
	fmt.Println("  # To use HashiCorp Vault for ALL configuration values:")
	fmt.Println("  export VAULT_ADDR=\"https://vault.example.com\"")
	fmt.Println("  export VAULT_TOKEN=\"hvs.ABC123...\"")
	fmt.Println("  export VAULT_SECRET=\"1\"  # This activates Vault Secret Manager")
	fmt.Println("  # Now all config values will be loaded from Vault")
	fmt.Println("  # using the mapstructure tag names (DATABASE_URL, API_KEY, etc.)")
	fmt.Println("")
	fmt.Println("  # Without GOOGLE_SECRET or VAULT_SECRET:")
	fmt.Println("  # Configuration will be loaded from credentials file + environment variables")
}

func maskSensitive(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return "***"
	}
	return value[:4] + "***" + value[len(value)-4:]
}