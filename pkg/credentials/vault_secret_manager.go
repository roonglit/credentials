package credentials

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/hashicorp/vault/api"
)

// VaultSecretManager implements SecretManager for HashiCorp Vault
type VaultSecretManager struct {
	address string
	token   string
	client  *api.Client
	mu      sync.RWMutex
}

// NewVaultSecretManager creates a new Vault Secret Manager instance
func NewVaultSecretManager() *VaultSecretManager {
	return &VaultSecretManager{
		address: os.Getenv("VAULT_ADDR"),
		token:   os.Getenv("VAULT_TOKEN"),
	}
}

// IsConfigured checks if Vault is properly configured
func (v *VaultSecretManager) IsConfigured() bool {
	return v.address != "" && v.token != ""
}

// GetPrefix returns the environment variable prefix for Vault
func (v *VaultSecretManager) GetPrefix() string {
	return "VAULT_"
}

// GetSecret retrieves a secret from HashiCorp Vault
func (v *VaultSecretManager) GetSecret(ctx context.Context, secretPath string) (string, error) {
	if !v.IsConfigured() {
		return "", fmt.Errorf("Vault is not configured")
	}
	
	if err := v.ensureClient(); err != nil {
		return "", fmt.Errorf("failed to initialize Vault client: %w", err)
	}
	
	// Read the secret from Vault
	secret, err := v.client.Logical().ReadWithContext(ctx, secretPath)
	if err != nil {
		return "", fmt.Errorf("failed to read secret from Vault: %w", err)
	}
	
	if secret == nil {
		return "", fmt.Errorf("secret not found at path: %s", secretPath)
	}
	
	// For KV v2, the data is nested under "data"
	if data, ok := secret.Data["data"]; ok {
		if dataMap, ok := data.(map[string]interface{}); ok {
			// Try to get the "value" field first, then try the key name itself
			if value, exists := dataMap["value"]; exists {
				if strValue, ok := value.(string); ok {
					return strValue, nil
				}
			}
			// If no "value" field, try to get the first string value
			for _, v := range dataMap {
				if strValue, ok := v.(string); ok {
					return strValue, nil
				}
			}
		}
	}
	
	// For KV v1, the data is at the top level
	if value, exists := secret.Data["value"]; exists {
		if strValue, ok := value.(string); ok {
			return strValue, nil
		}
	}
	
	// If no "value" field, try to get the first string value
	for _, v := range secret.Data {
		if strValue, ok := v.(string); ok {
			return strValue, nil
		}
	}
	
	return "", fmt.Errorf("no valid string value found in secret at path: %s", secretPath)
}

// ensureClient initializes the Vault client if not already done
func (v *VaultSecretManager) ensureClient() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	
	if v.client != nil {
		return nil
	}
	
	config := api.DefaultConfig()
	config.Address = v.address
	
	client, err := api.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}
	
	client.SetToken(v.token)
	v.client = client
	return nil
}