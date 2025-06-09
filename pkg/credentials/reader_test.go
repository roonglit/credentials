package credentials

import (
	"testing"
	"time"
)

type Config struct {
	Name                 string        `mapstructure:"name"`
	Enabled              bool          `mapstructure:"enabled"`
	RequestTimeout       time.Duration `mapstructure:"request_timeout"`
	RefreshTokenDuration time.Duration `mapstructure:"refresh_token_duration"`
	MaxRetries           int           `mapstructure:"max_retries"`
	LimitSize            int64         `mapstructure:"limit_size"`
}

func TestAutomaticEnv(t *testing.T) {
	t.Setenv("NAME", "test-service")
	t.Setenv("ENABLED", "true")
	t.Setenv("REQUEST_TIMEOUT", "15m")
	t.Setenv("REFRESH_TOKEN_DURATION", "24h")
	t.Setenv("MAX_RETRIES", "5")
	t.Setenv("LIMIT_SIZE", "1000")

	cfg := &Config{}
	automaticEnv(cfg)

	if cfg.Name != "test-service" {
		t.Errorf("expected Name to be 'test-service', got '%s'", cfg.Name)
	}
	if cfg.Enabled != true {
		t.Errorf("expected Enabled to be true, got %v", cfg.Enabled)
	}

	expectedDuration := 15 * time.Minute
	if cfg.RequestTimeout != expectedDuration {
		t.Errorf("expected RequestTimeout to be %v, got %v", expectedDuration, cfg.RequestTimeout)
	}

	expectedRefreshTokenDuration := 24 * time.Hour
	if cfg.RefreshTokenDuration != expectedRefreshTokenDuration {
		t.Errorf("expected RefreshTokenDuration to be %v, got %v", expectedRefreshTokenDuration, cfg.RefreshTokenDuration)
	}

	if cfg.MaxRetries != 5 {
		t.Errorf("expected MaxRetries to be 5, got %v", cfg.MaxRetries)
	}

	if cfg.LimitSize != int64(1000) {
		t.Errorf("expected LimitSize to be 1000, got %d", cfg.LimitSize)
	}
}
