package service

import (
	"context"
	"testing"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (f *fakeUserRepo) Create(ctx context.Context, u *model.User) error {
	if _, exists := f.byEmail[u.Email]; exists {
		return apperr.ErrEmailAlreadyExists
	}
	f.add(u)
	return nil
}

func (f *fakeUserRepo) List(ctx context.Context, limit, skip int64) ([]*model.User, error) {
	f.lastListLimit = limit
	f.lastListSkip = skip
	var out []*model.User
	for _, u := range f.byID {
		out = append(out, u)
	}
	if int64(len(out)) > limit {
		out = out[:limit]
	}
	return out, nil
}

func newTestUserService(users *fakeUserRepo, resetTokens *fakeResetTokenRepoFull, m *fakeMailer) *UserService {
	return NewUserService(users, resetTokens, m, 30*time.Minute, "https://app.example.com")
}

func TestUserService_CreateUser_SendsResetEmailAndNoUsablePasswordIsReturned(t *testing.T) {
	users := newFakeUserRepo()
	m := &fakeMailer{}
	svc := newTestUserService(users, newFakeResetTokenRepoFull(), m)

	u, err := svc.CreateUser(context.Background(), "newstaff@example.com", "New Staff", "staff")

	require.NoError(t, err)
	assert.Equal(t, "newstaff@example.com", m.to)
	assert.NotEmpty(t, u.PasswordHash)
	assert.False(t, auth.ComparePassword(u.PasswordHash, ""))
}

func TestUserService_CreateUser_DuplicateEmailFails(t *testing.T) {
	users := newFakeUserRepo()
	users.add(activeUser("existing@example.com", "irrelevant"))
	svc := newTestUserService(users, newFakeResetTokenRepoFull(), &fakeMailer{})

	_, err := svc.CreateUser(context.Background(), "existing@example.com", "Someone", "staff")

	require.ErrorIs(t, err, apperr.ErrEmailAlreadyExists)
}

func TestUserService_ListUsers_CapsPageSizeAtMax(t *testing.T) {
	users := newFakeUserRepo()
	svc := newTestUserService(users, newFakeResetTokenRepoFull(), &fakeMailer{})

	_, err := svc.ListUsers(context.Background(), 1000, 0)

	require.NoError(t, err)
	assert.Equal(t, int64(100), users.lastListLimit)
}

func TestUserService_ListUsers_DefaultsWhenLimitNotPositive(t *testing.T) {
	users := newFakeUserRepo()
	svc := newTestUserService(users, newFakeResetTokenRepoFull(), &fakeMailer{})

	_, err := svc.ListUsers(context.Background(), 0, 0)

	require.NoError(t, err)
	assert.Equal(t, int64(20), users.lastListLimit)
}

func TestUserService_DeactivateUser_SetsInactive(t *testing.T) {
	users := newFakeUserRepo()
	u := activeUser("alice@example.com", "password123")
	users.add(u)
	svc := newTestUserService(users, newFakeResetTokenRepoFull(), &fakeMailer{})

	require.NoError(t, svc.DeactivateUser(context.Background(), u.ID))

	assert.False(t, users.byID[u.ID].Active)
}
