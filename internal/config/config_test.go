package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("MONGO_URI", "mongodb://localhost:27017")
	t.Setenv("MONGO_DB_NAME", "bomtanstack")
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_FROM", "no-reply@example.com")
	t.Setenv("APP_BASE_URL", "https://app.example.com")
}

func TestLoad_DefaultsWhenOptionalUnset(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()

	require.NoError(t, err)
	assert.Equal(t, "8080", cfg.Port)
	assert.Equal(t, 15*time.Minute, cfg.AccessTokenTTL)
	assert.Equal(t, 720*time.Hour, cfg.RefreshTokenTTL)
	assert.Equal(t, 30*time.Minute, cfg.ResetTokenTTL)
	assert.Equal(t, "", cfg.SeedAdminEmail)
}

func TestLoad_MissingRequiredVarFails(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("JWT_SECRET", "")

	_, err := Load()

	require.Error(t, err)
}

func TestLoad_InvalidSMTPPortFails(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SMTP_PORT", "not-a-number")

	_, err := Load()

	require.Error(t, err)
}
