// internal/bootstrap/seed_admin_test.go
package bootstrap

import (
	"context"
	"testing"

	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAdminRepo struct {
	hasAdmin bool
	created  *model.User
}

func (f *fakeAdminRepo) ExistsActiveAdmin(ctx context.Context) (bool, error) {
	return f.hasAdmin, nil
}

func (f *fakeAdminRepo) Create(ctx context.Context, u *model.User) error {
	f.created = u
	return nil
}

func TestSeedAdmin_CreatesAdminWhenNoneExists(t *testing.T) {
	repo := &fakeAdminRepo{hasAdmin: false}

	err := SeedAdmin(context.Background(), repo, "admin@example.com", "s3cure-password")

	require.NoError(t, err)
	require.NotNil(t, repo.created)
	assert.Equal(t, "admin@example.com", repo.created.Email)
	assert.Equal(t, string(auth.RoleAdmin), repo.created.Role)
	assert.True(t, auth.ComparePassword(repo.created.PasswordHash, "s3cure-password"))
}

func TestSeedAdmin_NoOpWhenAdminAlreadyExists(t *testing.T) {
	repo := &fakeAdminRepo{hasAdmin: true}

	err := SeedAdmin(context.Background(), repo, "admin@example.com", "s3cure-password")

	require.NoError(t, err)
	assert.Nil(t, repo.created)
}

func TestSeedAdmin_NoOpWhenCredentialsEmpty(t *testing.T) {
	repo := &fakeAdminRepo{hasAdmin: false}

	err := SeedAdmin(context.Background(), repo, "", "")

	require.NoError(t, err)
	assert.Nil(t, repo.created)
}
