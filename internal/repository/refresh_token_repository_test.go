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

func newTestRefreshToken(userID primitive.ObjectID, hash string) *model.RefreshToken {
	now := time.Now().UTC()
	return &model.RefreshToken{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		TokenHash: hash,
		UserAgent: "test-agent",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
}

func TestRefreshTokenRepository_CreateAndFindActiveByHash(t *testing.T) {
	repo := NewRefreshTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	userID := primitive.NewObjectID()
	rt := newTestRefreshToken(userID, "hash-1")

	require.NoError(t, repo.Create(ctx, rt))

	found, err := repo.FindActiveByHash(ctx, "hash-1")
	require.NoError(t, err)
	assert.Equal(t, rt.ID, found.ID)
}

func TestRefreshTokenRepository_RevokedTokenNotFoundAsActive(t *testing.T) {
	repo := NewRefreshTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	rt := newTestRefreshToken(primitive.NewObjectID(), "hash-2")
	require.NoError(t, repo.Create(ctx, rt))

	require.NoError(t, repo.Revoke(ctx, rt.ID))

	_, err := repo.FindActiveByHash(ctx, "hash-2")
	require.ErrorIs(t, err, apperr.ErrTokenInvalid)
}

func TestRefreshTokenRepository_ExpiredTokenNotFoundAsActive(t *testing.T) {
	repo := NewRefreshTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	rt := newTestRefreshToken(primitive.NewObjectID(), "hash-3")
	rt.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	require.NoError(t, repo.Create(ctx, rt))

	_, err := repo.FindActiveByHash(ctx, "hash-3")
	require.ErrorIs(t, err, apperr.ErrTokenInvalid)
}

func TestRefreshTokenRepository_RevokeAllForUser(t *testing.T) {
	repo := NewRefreshTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	userID := primitive.NewObjectID()
	require.NoError(t, repo.Create(ctx, newTestRefreshToken(userID, "hash-4")))
	require.NoError(t, repo.Create(ctx, newTestRefreshToken(userID, "hash-5")))

	require.NoError(t, repo.RevokeAllForUser(ctx, userID))

	_, err := repo.FindActiveByHash(ctx, "hash-4")
	assert.ErrorIs(t, err, apperr.ErrTokenInvalid)
	_, err = repo.FindActiveByHash(ctx, "hash-5")
	assert.ErrorIs(t, err, apperr.ErrTokenInvalid)
}
