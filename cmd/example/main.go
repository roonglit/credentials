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

	fmt.Println("\nSecret Manager Environment Variables:")
	secretManagerEnvs := []string{
		"GOOGLE_DATABASE_URL",
		"GOOGLE_API_KEY",
		"GOOGLE_JWT_SECRET",
		"VAULT_DATABASE_URL",
		"VAULT_API_KEY",
		"VAULT_JWT_SECRET",
	}

	for _, envVar := range secretManagerEnvs {
		if value := os.Getenv(envVar); value != "" {
			fmt.Printf("  %s: %s\n", envVar, maskSensitive(value))
		}
	}

	fmt.Println("\nExample usage:")
	fmt.Println("  # To use Google Cloud Secret Manager:")
	fmt.Println("  export GOOGLE_PROJECT_ID=\"my-project\"")
	fmt.Println("  export GOOGLE_APPLICATION_CREDENTIALS=\"/path/to/service-account.json\"")
	fmt.Println("  export GOOGLE_DATABASE_URL=\"db-connection-secret\"")
	fmt.Println("  export GOOGLE_API_KEY=\"api-key-secret\"")
	fmt.Println("")
	fmt.Println("  # To use HashiCorp Vault:")
	fmt.Println("  export VAULT_ADDR=\"https://vault.example.com\"")
	fmt.Println("  export VAULT_TOKEN=\"hvs.ABC123...\"")
	fmt.Println("  export VAULT_DATABASE_URL=\"secret/data/database/url\"")
	fmt.Println("  export VAULT_API_KEY=\"secret/data/api/key\"")
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