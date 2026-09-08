//go:build integration

package repository

import (
	"context"
	"testing"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/db"
	"bom-tanstack-api/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcmongodb "github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func newTestDatabase(t *testing.T) *mongo.Database {
	t.Helper()
	ctx := context.Background()

	container, err := tcmongodb.Run(ctx, "mongo:7")
	require.NoError(t, err)
	t.Cleanup(func() { container.Terminate(ctx) })

	uri, err := container.ConnectionString(ctx)
	require.NoError(t, err)

	client, err := db.Connect(ctx, uri)
	require.NoError(t, err)
	t.Cleanup(func() { client.Disconnect(ctx) })

	database := client.Database("testdb")
	require.NoError(t, db.EnsureIndexes(ctx, database))
	return database
}

func newTestUser(email string) *model.User {
	now := time.Now().UTC()
	return &model.User{
		ID:           primitive.NewObjectID(),
		Email:        email,
		PasswordHash: "hash",
		Name:         "Test User",
		Role:         "admin",
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func TestUserRepository_CreateAndFindByEmail(t *testing.T) {
	repo := NewUserRepository(newTestDatabase(t))
	ctx := context.Background()
	u := newTestUser("alice@example.com")

	require.NoError(t, repo.Create(ctx, u))

	found, err := repo.FindByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, u.ID, found.ID)
}

func TestUserRepository_CreateDuplicateEmailFails(t *testing.T) {
	repo := NewUserRepository(newTestDatabase(t))
	ctx := context.Background()
	require.NoError(t, repo.Create(ctx, newTestUser("bob@example.com")))

	err := repo.Create(ctx, newTestUser("bob@example.com"))

	require.ErrorIs(t, err, apperr.ErrEmailAlreadyExists)
}

func TestUserRepository_FindByEmailNotFoundReturnsDomainError(t *testing.T) {
	repo := NewUserRepository(newTestDatabase(t))

	_, err := repo.FindByEmail(context.Background(), "nobody@example.com")

	require.ErrorIs(t, err, apperr.ErrUserNotFound)
}

func TestUserRepository_ExistsActiveAdmin(t *testing.T) {
	repo := NewUserRepository(newTestDatabase(t))
	ctx := context.Background()

	exists, err := repo.ExistsActiveAdmin(ctx)
	require.NoError(t, err)
	assert.False(t, exists)

	require.NoError(t, repo.Create(ctx, newTestUser("admin@example.com")))

	exists, err = repo.ExistsActiveAdmin(ctx)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestUserRepository_UpdateChangesFields(t *testing.T) {
	repo := NewUserRepository(newTestDatabase(t))
	ctx := context.Background()
	u := newTestUser("carol@example.com")
	require.NoError(t, repo.Create(ctx, u))

	require.NoError(t, repo.Update(ctx, u.ID, bson.M{"active": false}))

	found, err := repo.FindByID(ctx, u.ID)
	require.NoError(t, err)
	assert.False(t, found.Active)
}
