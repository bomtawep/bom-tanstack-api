package service

import (
	"context"
	"fmt"
	"time"

	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/mailer"
	"bom-tanstack-api/internal/model"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type resetTokenRepository interface {
	Create(ctx context.Context, t *model.PasswordResetToken) error
}

func issuePasswordResetToken(
	ctx context.Context,
	repo resetTokenRepository,
	m mailer.Mailer,
	userID primitive.ObjectID,
	email string,
	ttl time.Duration,
	baseURL string,
) error {
	raw, err := auth.GenerateRandomToken()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	token := &model.PasswordResetToken{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		TokenHash: auth.HashToken(raw),
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
	if err := repo.Create(ctx, token); err != nil {
		return err
	}

	resetLink := fmt.Sprintf("%s/reset-password?token=%s", baseURL, raw)
	subject, body := mailer.BuildPasswordResetEmail(resetLink)
	return m.Send(ctx, email, subject, body)
}
