//go:build integration

package repository

import (
	"context"
	"testing"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func newTestResetToken(userID primitive.ObjectID, hash string) *model.PasswordResetToken {
	now := time.Now().UTC()
	return &model.PasswordResetToken{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: now.Add(30 * time.Minute),
		CreatedAt: now,
	}
}

func TestPasswordResetTokenRepository_CreateAndFindActiveByHash(t *testing.T) {
	repo := NewPasswordResetTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	rt := newTestResetToken(primitive.NewObjectID(), "reset-hash-1")

	require.NoError(t, repo.Create(ctx, rt))

	found, err := repo.FindActiveByHash(ctx, "reset-hash-1")
	require.NoError(t, err)
	assert.Equal(t, rt.ID, found.ID)
}

func TestPasswordResetTokenRepository_UsedTokenNotFoundAsActive(t *testing.T) {
	repo := NewPasswordResetTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	rt := newTestResetToken(primitive.NewObjectID(), "reset-hash-2")
	require.NoError(t, repo.Create(ctx, rt))

	require.NoError(t, repo.MarkUsed(ctx, rt.ID))

	_, err := repo.FindActiveByHash(ctx, "reset-hash-2")
	require.ErrorIs(t, err, apperr.ErrTokenInvalid)
}

func TestPasswordResetTokenRepository_ExpiredTokenNotFoundAsActive(t *testing.T) {
	repo := NewPasswordResetTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	rt := newTestResetToken(primitive.NewObjectID(), "reset-hash-3")
	rt.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	require.NoError(t, repo.Create(ctx, rt))

	_, err := repo.FindActiveByHash(ctx, "reset-hash-3")
	require.ErrorIs(t, err, apperr.ErrTokenInvalid)
}
