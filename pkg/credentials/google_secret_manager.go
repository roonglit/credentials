package credentials

import (
	"context"
	"fmt"
	"os"
	"sync"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// GoogleSecretManager implements SecretManager for Google Cloud Secret Manager
type GoogleSecretManager struct {
	projectID string
	client    *secretmanager.Client
	mu        sync.RWMutex
}

// NewGoogleSecretManager creates a new Google Cloud Secret Manager instance
func NewGoogleSecretManager() *GoogleSecretManager {
	return &GoogleSecretManager{
		projectID: os.Getenv("GOOGLE_PROJECT_ID"),
	}
}

// IsConfigured checks if Google Secret Manager is properly configured
func (g *GoogleSecretManager) IsConfigured() bool {
	// Check for required environment variables
	return g.projectID != "" && (os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" || 
		os.Getenv("GOOGLE_CLOUD_PROJECT") != "" ||
		// Check if running in Google Cloud environment
		os.Getenv("GOOGLE_CLOUD_PROJECT_ID") != "")
}

// GetPrefix returns the environment variable prefix for Google Secret Manager
func (g *GoogleSecretManager) GetPrefix() string {
	return "GOOGLE_"
}

// GetSecret retrieves a secret from Google Cloud Secret Manager
func (g *GoogleSecretManager) GetSecret(ctx context.Context, secretName string) (string, error) {
	if !g.IsConfigured() {
		return "", fmt.Errorf("Google Secret Manager is not configured")
	}
	
	if err := g.ensureClient(ctx); err != nil {
		return "", fmt.Errorf("failed to initialize Google Secret Manager client: %w", err)
	}
	
	// Build the request
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", g.projectID, secretName),
	}
	
	// Call the API
	result, err := g.client.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to access secret %s: %w", secretName, err)
	}
	
	return string(result.Payload.Data), nil
}

// ensureClient initializes the Google Cloud Secret Manager client if not already done
func (g *GoogleSecretManager) ensureClient(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	if g.client != nil {
		return nil
	}
	
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return err
	}
	
	g.client = client
	return nil
}

// Close closes the Google Secret Manager client
func (g *GoogleSecretManager) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	if g.client != nil {
		return g.client.Close()
	}
	return nil
}