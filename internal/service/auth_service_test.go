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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type fakeUserRepo struct {
	byEmail       map[string]*model.User
	byID          map[primitive.ObjectID]*model.User
	lastListLimit int64
	lastListSkip  int64
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{byEmail: map[string]*model.User{}, byID: map[primitive.ObjectID]*model.User{}}
}

func (f *fakeUserRepo) add(u *model.User) {
	f.byEmail[u.Email] = u
	f.byID[u.ID] = u
}

func (f *fakeUserRepo) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return nil, apperr.ErrUserNotFound
	}
	return u, nil
}

func (f *fakeUserRepo) FindByID(ctx context.Context, id primitive.ObjectID) (*model.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return nil, apperr.ErrUserNotFound
	}
	return u, nil
}

func (f *fakeUserRepo) Update(ctx context.Context, id primitive.ObjectID, update bson.M) error {
	u, ok := f.byID[id]
	if !ok {
		return apperr.ErrUserNotFound
	}
	if v, ok := update["password_hash"].(string); ok {
		u.PasswordHash = v
	}
	if v, ok := update["active"].(bool); ok {
		u.Active = v
	}
	return nil
}

type fakeRefreshTokenRepo struct {
	byHash map[string]*model.RefreshToken
}

func newFakeRefreshTokenRepo() *fakeRefreshTokenRepo {
	return &fakeRefreshTokenRepo{byHash: map[string]*model.RefreshToken{}}
}

func (f *fakeRefreshTokenRepo) Create(ctx context.Context, rt *model.RefreshToken) error {
	f.byHash[rt.TokenHash] = rt
	return nil
}

func (f *fakeRefreshTokenRepo) FindActiveByHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	rt, ok := f.byHash[hash]
	if !ok || rt.RevokedAt != nil || rt.ExpiresAt.Before(time.Now()) {
		return nil, apperr.ErrTokenInvalid
	}
	return rt, nil
}

func (f *fakeRefreshTokenRepo) Revoke(ctx context.Context, id primitive.ObjectID) error {
	for _, rt := range f.byHash {
		if rt.ID == id {
			now := time.Now().UTC()
			rt.RevokedAt = &now
		}
	}
	return nil
}

func (f *fakeRefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID primitive.ObjectID) error {
	now := time.Now().UTC()
	for _, rt := range f.byHash {
		if rt.UserID == userID {
			rt.RevokedAt = &now
		}
	}
	return nil
}

type fakeResetTokenRepoFull struct {
	byHash map[string]*model.PasswordResetToken
}

func newFakeResetTokenRepoFull() *fakeResetTokenRepoFull {
	return &fakeResetTokenRepoFull{byHash: map[string]*model.PasswordResetToken{}}
}

func (f *fakeResetTokenRepoFull) Create(ctx context.Context, t *model.PasswordResetToken) error {
	f.byHash[t.TokenHash] = t
	return nil
}

func (f *fakeResetTokenRepoFull) FindActiveByHash(ctx context.Context, hash string) (*model.PasswordResetToken, error) {
	t, ok := f.byHash[hash]
	if !ok || t.UsedAt != nil || t.ExpiresAt.Before(time.Now()) {
		return nil, apperr.ErrTokenInvalid
	}
	return t, nil
}

func (f *fakeResetTokenRepoFull) MarkUsed(ctx context.Context, id primitive.ObjectID) error {
	for _, t := range f.byHash {
		if t.ID == id {
			now := time.Now().UTC()
			t.UsedAt = &now
		}
	}
	return nil
}

func newTestAuthService(users *fakeUserRepo, refreshTokens *fakeRefreshTokenRepo, resetTokens *fakeResetTokenRepoFull, m *fakeMailer) *AuthService {
	return NewAuthService(users, refreshTokens, resetTokens, m, "test-secret", 15*time.Minute, 720*time.Hour, 30*time.Minute, "https://app.example.com")
}

func activeUser(email, password string) *model.User {
	hash, _ := auth.HashPassword(password)
	return &model.User{ID: primitive.NewObjectID(), Email: email, PasswordHash: hash, Role: "admin", Active: true}
}

func TestAuthService_Login_Success(t *testing.T) {
	users := newFakeUserRepo()
	u := activeUser("alice@example.com", "password123")
	users.add(u)
	svc := newTestAuthService(users, newFakeRefreshTokenRepo(), newFakeResetTokenRepoFull(), &fakeMailer{})

	access, refresh, err := svc.Login(context.Background(), "alice@example.com", "password123", "test-agent")

	require.NoError(t, err)
	assert.NotEmpty(t, access)
	assert.NotEmpty(t, refresh)
}

func TestAuthService_Login_WrongPasswordFails(t *testing.T) {
	users := newFakeUserRepo()
	users.add(activeUser("alice@example.com", "password123"))
	svc := newTestAuthService(users, newFakeRefreshTokenRepo(), newFakeResetTokenRepoFull(), &fakeMailer{})

	_, _, err := svc.Login(context.Background(), "alice@example.com", "wrong-password", "test-agent")

	require.ErrorIs(t, err, apperr.ErrInvalidCredentials)
}

func TestAuthService_Login_InactiveUserFails(t *testing.T) {
	users := newFakeUserRepo()
	u := activeUser("alice@example.com", "password123")
	u.Active = false
	users.add(u)
	svc := newTestAuthService(users, newFakeRefreshTokenRepo(), newFakeResetTokenRepoFull(), &fakeMailer{})

	_, _, err := svc.Login(context.Background(), "alice@example.com", "password123", "test-agent")

	require.ErrorIs(t, err, apperr.ErrUserInactive)
}

func TestAuthService_Refresh_RotatesTokenAndRejectsReuse(t *testing.T) {
	users := newFakeUserRepo()
	users.add(activeUser("alice@example.com", "password123"))
	refreshTokens := newFakeRefreshTokenRepo()
	svc := newTestAuthService(users, refreshTokens, newFakeResetTokenRepoFull(), &fakeMailer{})
	_, firstRefresh, err := svc.Login(context.Background(), "alice@example.com", "password123", "agent-a")
	require.NoError(t, err)

	_, secondRefresh, err := svc.Refresh(context.Background(), firstRefresh, "agent-a")
	require.NoError(t, err)
	assert.NotEqual(t, firstRefresh, secondRefresh)

	_, _, err = svc.Refresh(context.Background(), firstRefresh, "agent-a")
	require.ErrorIs(t, err, apperr.ErrTokenInvalid)
}

func TestAuthService_ForgotPassword_UnknownEmailReturnsNilSilently(t *testing.T) {
	svc := newTestAuthService(newFakeUserRepo(), newFakeRefreshTokenRepo(), newFakeResetTokenRepoFull(), &fakeMailer{})

	err := svc.ForgotPassword(context.Background(), "nobody@example.com")

	require.NoError(t, err)
}

func TestAuthService_ResetPassword_RevokesAllSessions(t *testing.T) {
	users := newFakeUserRepo()
	u := activeUser("alice@example.com", "password123")
	users.add(u)
	refreshTokens := newFakeRefreshTokenRepo()
	resetTokens := newFakeResetTokenRepoFull()
	m := &fakeMailer{}
	svc := newTestAuthService(users, refreshTokens, resetTokens, m)
	_, refreshToken, err := svc.Login(context.Background(), "alice@example.com", "password123", "agent-a")
	require.NoError(t, err)
	require.NoError(t, svc.ForgotPassword(context.Background(), "alice@example.com"))

	rawResetToken := extractTokenFromLink(t, m.body)
	require.NoError(t, svc.ResetPassword(context.Background(), rawResetToken, "new-password-456"))

	_, _, err = svc.Refresh(context.Background(), refreshToken, "agent-a")
	assert.ErrorIs(t, err, apperr.ErrTokenInvalid)

	_, _, err = svc.Login(context.Background(), "alice@example.com", "new-password-456", "agent-a")
	assert.NoError(t, err)
}

func TestAuthService_ChangePassword_WrongOldPasswordFails(t *testing.T) {
	users := newFakeUserRepo()
	u := activeUser("alice@example.com", "password123")
	users.add(u)
	svc := newTestAuthService(users, newFakeRefreshTokenRepo(), newFakeResetTokenRepoFull(), &fakeMailer{})

	err := svc.ChangePassword(context.Background(), u.ID, "wrong-old-password", "new-password-456")

	require.ErrorIs(t, err, apperr.ErrInvalidCredentials)
}

func TestAuthService_ChangePassword_RevokesAllOtherSessions(t *testing.T) {
	users := newFakeUserRepo()
	u := activeUser("alice@example.com", "password123")
	users.add(u)
	refreshTokens := newFakeRefreshTokenRepo()
	resetTokens := newFakeResetTokenRepoFull()
	m := &fakeMailer{}
	svc := newTestAuthService(users, refreshTokens, resetTokens, m)
	_, refreshToken, err := svc.Login(context.Background(), "alice@example.com", "password123", "agent-a")
	require.NoError(t, err)

	require.NoError(t, svc.ChangePassword(context.Background(), u.ID, "password123", "new-password-456"))

	_, _, err = svc.Refresh(context.Background(), refreshToken, "agent-a")
	assert.ErrorIs(t, err, apperr.ErrTokenInvalid)
}

func extractTokenFromLink(t *testing.T, body string) string {
	t.Helper()
	const marker = "token="
	idx := indexOf(body, marker)
	require.GreaterOrEqual(t, idx, 0, "expected a reset link with a token in the email body")
	return body[idx+len(marker) : idx+len(marker)+64]
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
