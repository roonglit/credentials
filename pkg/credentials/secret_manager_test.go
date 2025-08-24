package credentials

import (
	"context"
	"os"
	"testing"
)

// MockSecretManager for testing
type MockSecretManager struct {
	configured bool
	prefix     string
	secrets    map[string]string
}

func NewMockSecretManager(prefix string, configured bool) *MockSecretManager {
	return &MockSecretManager{
		configured: configured,
		prefix:     prefix,
		secrets:    make(map[string]string),
	}
}

func (m *MockSecretManager) IsConfigured() bool {
	return m.configured
}

func (m *MockSecretManager) GetPrefix() string {
	return m.prefix
}

func (m *MockSecretManager) GetSecret(ctx context.Context, secretName string) (string, error) {
	if value, exists := m.secrets[secretName]; exists {
		return value, nil
	}
	return "", nil
}

func (m *MockSecretManager) SetSecret(name, value string) {
	m.secrets[name] = value
}

func TestSecretManagerRegistry(t *testing.T) {
	registry := &SecretManagerRegistry{}
	
	// Test with mock secret manager
	mockManager := NewMockSecretManager("GOOGLE_", true)
	mockManager.SetSecret("DATABASE_URL", "postgres://localhost:5432/test")
	mockManager.SetSecret("API_KEY", "secret-api-key")
	registry.managers = append(registry.managers, mockManager)
	
	// Test without GOOGLE_SECRET environment variable - should return nil
	activeManager := registry.GetActiveSecretManager()
	if activeManager != nil {
		t.Error("Expected no active secret manager without GOOGLE_SECRET set")
	}
	
	// Test with GOOGLE_SECRET environment variable - should return the manager
	os.Setenv("GOOGLE_SECRET", "1")
	defer os.Unsetenv("GOOGLE_SECRET")
	
	activeManager = registry.GetActiveSecretManager()
	if activeManager == nil {
		t.Error("Expected active secret manager with GOOGLE_SECRET set")
	}
	
	if activeManager.GetPrefix() != "GOOGLE_" {
		t.Errorf("Expected prefix 'GOOGLE_', got '%s'", activeManager.GetPrefix())
	}
}

func TestConfigReaderWithSecretManager(t *testing.T) {
	// Create a test config struct
	type TestConfig struct {
		DatabaseURL string `mapstructure:"DATABASE_URL"`
		APIKey      string `mapstructure:"API_KEY"`
	}
	
	// Create a ConfigReader with mock secret manager
	reader := &ConfigReader{
		secretManagerRegistry: &SecretManagerRegistry{},
	}
	
	mockManager := NewMockSecretManager("GOOGLE_", true)
	mockManager.SetSecret("DATABASE_URL", "postgres://localhost:5432/test")
	// Note: API_KEY is not set in secret manager
	reader.secretManagerRegistry.managers = append(reader.secretManagerRegistry.managers, mockManager)
	
	// Set up environment variables
	os.Setenv("GOOGLE_SECRET", "1")  // Activate Google Secret Manager
	os.Setenv("API_KEY", "regular-env-var")  // This should be ignored when secret manager is active
	defer func() {
		os.Unsetenv("GOOGLE_SECRET")
		os.Unsetenv("API_KEY")
	}()
	
	var config TestConfig
	err := reader.loadExternalSources(&config)
	
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	
	if config.DatabaseURL != "postgres://localhost:5432/test" {
		t.Errorf("Expected database URL from secret manager, got '%s'", config.DatabaseURL)
	}
	
	// API_KEY should be empty because it's not in the secret manager and secret manager is active
	if config.APIKey != "" {
		t.Errorf("Expected empty API key (not found in secret manager), got '%s'", config.APIKey)
	}
}

func TestConfigReaderWithoutSecretManager(t *testing.T) {
	// Create a test config struct
	type TestConfig struct {
		DatabaseURL string `mapstructure:"DATABASE_URL"`
		APIKey      string `mapstructure:"API_KEY"`
	}
	
	// Create a ConfigReader with mock secret manager
	reader := &ConfigReader{
		secretManagerRegistry: &SecretManagerRegistry{},
	}
	
	mockManager := NewMockSecretManager("GOOGLE_", true)
	mockManager.SetSecret("DATABASE_URL", "postgres://localhost:5432/test")
	reader.secretManagerRegistry.managers = append(reader.secretManagerRegistry.managers, mockManager)
	
	// Set up environment variables but don't activate secret manager
	os.Setenv("DATABASE_URL", "postgres://localhost:5432/env")
	os.Setenv("API_KEY", "regular-env-var")
	defer func() {
		os.Unsetenv("DATABASE_URL")
		os.Unsetenv("API_KEY")
	}()
	
	var config TestConfig
	err := reader.loadExternalSources(&config)
	
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	
	// Should use environment variables since secret manager is not active
	if config.DatabaseURL != "postgres://localhost:5432/env" {
		t.Errorf("Expected database URL from environment variable, got '%s'", config.DatabaseURL)
	}
	
	if config.APIKey != "regular-env-var" {
		t.Errorf("Expected API key from environment variable, got '%s'", config.APIKey)
	}
}

func TestGoogleSecretManagerConfiguration(t *testing.T) {
	// Test without configuration
	gsm := NewGoogleSecretManager()
	if gsm.IsConfigured() {
		t.Error("Expected Google Secret Manager to not be configured")
	}
	
	// Test with configuration
	os.Setenv("GOOGLE_PROJECT_ID", "test-project")
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/path/to/credentials.json")
	defer func() {
		os.Unsetenv("GOOGLE_PROJECT_ID")
		os.Unsetenv("GOOGLE_APPLICATION_CREDENTIALS")
	}()
	
	gsm = NewGoogleSecretManager()
	if !gsm.IsConfigured() {
		t.Error("Expected Google Secret Manager to be configured")
	}
	
	if gsm.GetPrefix() != "GOOGLE_" {
		t.Errorf("Expected prefix 'GOOGLE_', got '%s'", gsm.GetPrefix())
	}
}

func TestVaultSecretManagerConfiguration(t *testing.T) {
	// Test without configuration
	vault := NewVaultSecretManager()
	if vault.IsConfigured() {
		t.Error("Expected Vault to not be configured")
	}
	
	// Test with configuration
	os.Setenv("VAULT_ADDR", "https://vault.example.com")
	os.Setenv("VAULT_TOKEN", "test-token")
	defer func() {
		os.Unsetenv("VAULT_ADDR")
		os.Unsetenv("VAULT_TOKEN")
	}()
	
	vault = NewVaultSecretManager()
	if !vault.IsConfigured() {
		t.Error("Expected Vault to be configured")
	}
	
	if vault.GetPrefix() != "VAULT_" {
		t.Errorf("Expected prefix 'VAULT_', got '%s'", vault.GetPrefix())
	}
}