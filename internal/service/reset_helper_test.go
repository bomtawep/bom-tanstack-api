package service

import (
	"context"
	"testing"
	"time"

	"bom-tanstack-api/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type fakeResetTokenRepo struct {
	created *model.PasswordResetToken
}

func (f *fakeResetTokenRepo) Create(ctx context.Context, t *model.PasswordResetToken) error {
	f.created = t
	return nil
}

type fakeMailer struct {
	to, subject, body string
}

func (f *fakeMailer) Send(ctx context.Context, to, subject, body string) error {
	f.to, f.subject, f.body = to, subject, body
	return nil
}

func TestIssuePasswordResetToken_StoresHashAndEmailsRawToken(t *testing.T) {
	repo := &fakeResetTokenRepo{}
	m := &fakeMailer{}
	userID := primitive.NewObjectID()

	err := issuePasswordResetToken(context.Background(), repo, m, userID, "user@example.com", 30*time.Minute, "https://app.example.com")

	require.NoError(t, err)
	require.NotNil(t, repo.created)
	assert.Equal(t, userID, repo.created.UserID)
	assert.NotEmpty(t, repo.created.TokenHash)
	assert.Equal(t, "user@example.com", m.to)
	assert.Contains(t, m.body, "https://app.example.com/reset-password?token=")
	assert.NotContains(t, m.body, repo.created.TokenHash)
}
