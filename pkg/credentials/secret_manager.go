package credentials

import (
	"context"
	"os"
)

// SecretManager interface for different secret management systems
type SecretManager interface {
	GetSecret(ctx context.Context, secretName string) (string, error)
	IsConfigured() bool
	GetPrefix() string
}

// SecretManagerRegistry holds all available secret managers
type SecretManagerRegistry struct {
	managers []SecretManager
}

// NewSecretManagerRegistry creates a new registry with all available secret managers
func NewSecretManagerRegistry() *SecretManagerRegistry {
	registry := &SecretManagerRegistry{}
	
	// Add Google Cloud Secret Manager if configured
	if gsm := NewGoogleSecretManager(); gsm.IsConfigured() {
		registry.managers = append(registry.managers, gsm)
	}
	
	// Add Vault Secret Manager if configured
	if vault := NewVaultSecretManager(); vault.IsConfigured() {
		registry.managers = append(registry.managers, vault)
	}
	
	return registry
}

// GetActiveSecretManager returns the active secret manager if one is configured via environment variables
func (r *SecretManagerRegistry) GetActiveSecretManager() SecretManager {
	// Check for Google Secret Manager activation
	if os.Getenv("GOOGLE_SECRET") != "" {
		for _, manager := range r.managers {
			if manager.GetPrefix() == "GOOGLE_" {
				return manager
			}
		}
	}
	
	// Check for Vault Secret Manager activation
	if os.Getenv("VAULT_SECRET") != "" {
		for _, manager := range r.managers {
			if manager.GetPrefix() == "VAULT_" {
				return manager
			}
		}
	}
	
	return nil
}

// HasConfiguredManagers returns true if any secret managers are configured
func (r *SecretManagerRegistry) HasConfiguredManagers() bool {
	return len(r.managers) > 0
}