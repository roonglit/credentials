package credentials

import (
	"context"
	"fmt"
	"os"
	"strings"
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

// GetSecretValue checks all configured secret managers for a secret
func (r *SecretManagerRegistry) GetSecretValue(ctx context.Context, envVarName string) (string, bool, error) {
	for _, manager := range r.managers {
		prefix := manager.GetPrefix()
		if strings.HasPrefix(envVarName, prefix) {
			// Check if there's an environment variable with this prefix
			if secretName := os.Getenv(envVarName); secretName != "" {
				value, err := manager.GetSecret(ctx, secretName)
				if err != nil {
					return "", false, fmt.Errorf("failed to get secret from %s: %w", prefix, err)
				}
				return value, true, nil
			}
		}
	}
	return "", false, nil
}

// HasConfiguredManagers returns true if any secret managers are configured
func (r *SecretManagerRegistry) HasConfiguredManagers() bool {
	return len(r.managers) > 0
}