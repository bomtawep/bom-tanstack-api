package service

import (
	"context"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/mailer"
	"bom-tanstack-api/internal/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type userRepository interface {
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	FindByID(ctx context.Context, id primitive.ObjectID) (*model.User, error)
	Update(ctx context.Context, id primitive.ObjectID, update bson.M) error
}

type refreshTokenRepository interface {
	Create(ctx context.Context, rt *model.RefreshToken) error
	FindActiveByHash(ctx context.Context, hash string) (*model.RefreshToken, error)
	Revoke(ctx context.Context, id primitive.ObjectID) error
	RevokeAllForUser(ctx context.Context, userID primitive.ObjectID) error
}

type passwordResetTokenRepository interface {
	Create(ctx context.Context, t *model.PasswordResetToken) error
	FindActiveByHash(ctx context.Context, hash string) (*model.PasswordResetToken, error)
	MarkUsed(ctx context.Context, id primitive.ObjectID) error
}

type AuthService struct {
	users         userRepository
	refreshTokens refreshTokenRepository
	resetTokens   passwordResetTokenRepository
	mailer        mailer.Mailer
	jwtSecret     string
	accessTTL     time.Duration
	refreshTTL    time.Duration
	resetTTL      time.Duration
	baseURL       string
}

func NewAuthService(
	users userRepository,
	refreshTokens refreshTokenRepository,
	resetTokens passwordResetTokenRepository,
	m mailer.Mailer,
	jwtSecret string,
	accessTTL, refreshTTL, resetTTL time.Duration,
	baseURL string,
) *AuthService {
	return &AuthService{
		users: users, refreshTokens: refreshTokens, resetTokens: resetTokens, mailer: m,
		jwtSecret: jwtSecret, accessTTL: accessTTL, refreshTTL: refreshTTL, resetTTL: resetTTL,
		baseURL: baseURL,
	}
}

func (s *AuthService) issueTokenPair(ctx context.Context, u *model.User, userAgent string) (string, string, error) {
	accessToken, err := auth.GenerateAccessToken(u.ID.Hex(), u.Role, s.jwtSecret, s.accessTTL)
	if err != nil {
		return "", "", err
	}

	raw, err := auth.GenerateRandomToken()
	if err != nil {
		return "", "", err
	}
	now := time.Now().UTC()
	rt := &model.RefreshToken{
		ID:        primitive.NewObjectID(),
		UserID:    u.ID,
		TokenHash: auth.HashToken(raw),
		UserAgent: userAgent,
		ExpiresAt: now.Add(s.refreshTTL),
		CreatedAt: now,
	}
	if err := s.refreshTokens.Create(ctx, rt); err != nil {
		return "", "", err
	}
	return accessToken, raw, nil
}

func (s *AuthService) Login(ctx context.Context, email, password, userAgent string) (string, string, error) {
	u, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return "", "", apperr.ErrInvalidCredentials
	}
	if !u.Active {
		return "", "", apperr.ErrUserInactive
	}
	if !auth.ComparePassword(u.PasswordHash, password) {
		return "", "", apperr.ErrInvalidCredentials
	}
	return s.issueTokenPair(ctx, u, userAgent)
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken, userAgent string) (string, string, error) {
	hash := auth.HashToken(refreshToken)
	rt, err := s.refreshTokens.FindActiveByHash(ctx, hash)
	if err != nil {
		return "", "", err
	}
	if err := s.refreshTokens.Revoke(ctx, rt.ID); err != nil {
		return "", "", err
	}

	u, err := s.users.FindByID(ctx, rt.UserID)
	if err != nil {
		return "", "", err
	}
	if !u.Active {
		return "", "", apperr.ErrUserInactive
	}
	return s.issueTokenPair(ctx, u, userAgent)
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	hash := auth.HashToken(refreshToken)
	rt, err := s.refreshTokens.FindActiveByHash(ctx, hash)
	if err != nil {
		return nil
	}
	return s.refreshTokens.Revoke(ctx, rt.ID)
}

func (s *AuthService) LogoutAll(ctx context.Context, userID primitive.ObjectID) error {
	return s.refreshTokens.RevokeAllForUser(ctx, userID)
}

func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	u, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return nil
	}
	if !u.Active {
		return nil
	}
	return issuePasswordResetToken(ctx, s.resetTokens, s.mailer, u.ID, u.Email, s.resetTTL, s.baseURL)
}

func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	hash := auth.HashToken(token)
	rt, err := s.resetTokens.FindActiveByHash(ctx, hash)
	if err != nil {
		return err
	}

	hashedPW, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.users.Update(ctx, rt.UserID, bson.M{"password_hash": hashedPW}); err != nil {
		return err
	}
	if err := s.resetTokens.MarkUsed(ctx, rt.ID); err != nil {
		return err
	}
	return s.refreshTokens.RevokeAllForUser(ctx, rt.UserID)
}

func (s *AuthService) ChangePassword(ctx context.Context, userID primitive.ObjectID, oldPassword, newPassword string) error {
	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if !auth.ComparePassword(u.PasswordHash, oldPassword) {
		return apperr.ErrInvalidCredentials
	}
	hashedPW, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.users.Update(ctx, userID, bson.M{"password_hash": hashedPW}); err != nil {
		return err
	}
	return s.refreshTokens.RevokeAllForUser(ctx, userID)
}

func (s *AuthService) Me(ctx context.Context, userID primitive.ObjectID) (*model.User, error) {
	return s.users.FindByID(ctx, userID)
}
