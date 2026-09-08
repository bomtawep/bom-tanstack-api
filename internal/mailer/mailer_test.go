package mailer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildPasswordResetEmail_IncludesLink(t *testing.T) {
	subject, body := BuildPasswordResetEmail("https://app.example.com/reset-password?token=abc123")

	assert.NotEmpty(t, subject)
	assert.Contains(t, body, "https://app.example.com/reset-password?token=abc123")
}
