package bootstrap

import (
	"context"
	"time"

	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/model"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type adminRepository interface {
	ExistsActiveAdmin(ctx context.Context) (bool, error)
	Create(ctx context.Context, u *model.User) error
}

func SeedAdmin(ctx context.Context, repo adminRepository, email, password string) error {
	if email == "" || password == "" {
		return nil
	}

	exists, err := repo.ExistsActiveAdmin(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	return repo.Create(ctx, &model.User{
		ID:           primitive.NewObjectID(),
		Email:        email,
		PasswordHash: hash,
		Name:         "Admin",
		Role:         string(auth.RoleAdmin),
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
}
