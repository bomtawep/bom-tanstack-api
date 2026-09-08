package service

import (
	"context"
	"time"

	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/mailer"
	"bom-tanstack-api/internal/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	defaultPageSize = 20
	maxPageSize     = 100
)

type userManagementRepository interface {
	Create(ctx context.Context, u *model.User) error
	FindByID(ctx context.Context, id primitive.ObjectID) (*model.User, error)
	List(ctx context.Context, limit, skip int64) ([]*model.User, error)
	Update(ctx context.Context, id primitive.ObjectID, update bson.M) error
}

type UserService struct {
	users       userManagementRepository
	resetTokens resetTokenRepository
	mailer      mailer.Mailer
	resetTTL    time.Duration
	baseURL     string
}

func NewUserService(users userManagementRepository, resetTokens resetTokenRepository, m mailer.Mailer, resetTTL time.Duration, baseURL string) *UserService {
	return &UserService{users: users, resetTokens: resetTokens, mailer: m, resetTTL: resetTTL, baseURL: baseURL}
}

func (s *UserService) CreateUser(ctx context.Context, email, name, role string) (*model.User, error) {
	unusable, err := auth.GenerateRandomToken()
	if err != nil {
		return nil, err
	}
	passwordHash, err := auth.HashPassword(unusable)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	u := &model.User{
		ID:           primitive.NewObjectID(),
		Email:        email,
		PasswordHash: passwordHash,
		Name:         name,
		Role:         role,
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}

	if err := issuePasswordResetToken(ctx, s.resetTokens, s.mailer, u.ID, u.Email, s.resetTTL, s.baseURL); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *UserService) ListUsers(ctx context.Context, limit, skip int64) ([]*model.User, error) {
	if limit <= 0 {
		limit = defaultPageSize
	}
	if limit > maxPageSize {
		limit = maxPageSize
	}
	if skip < 0 {
		skip = 0
	}
	return s.users.List(ctx, limit, skip)
}

func (s *UserService) GetUser(ctx context.Context, id primitive.ObjectID) (*model.User, error) {
	return s.users.FindByID(ctx, id)
}

func (s *UserService) UpdateUser(ctx context.Context, id primitive.ObjectID, name, email, role *string) (*model.User, error) {
	update := bson.M{}
	if name != nil {
		update["name"] = *name
	}
	if email != nil {
		update["email"] = *email
	}
	if role != nil {
		update["role"] = *role
	}
	if len(update) > 0 {
		if err := s.users.Update(ctx, id, update); err != nil {
			return nil, err
		}
	}
	return s.users.FindByID(ctx, id)
}

func (s *UserService) DeactivateUser(ctx context.Context, id primitive.ObjectID) error {
	return s.users.Update(ctx, id, bson.M{"active": false})
}
