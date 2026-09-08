package repository

import (
	"context"
	"errors"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type PasswordResetTokenRepository struct {
	col *mongo.Collection
}

func NewPasswordResetTokenRepository(database *mongo.Database) *PasswordResetTokenRepository {
	return &PasswordResetTokenRepository{col: database.Collection("password_reset_tokens")}
}

func (r *PasswordResetTokenRepository) Create(ctx context.Context, t *model.PasswordResetToken) error {
	_, err := r.col.InsertOne(ctx, t)
	return err
}

func (r *PasswordResetTokenRepository) FindActiveByHash(ctx context.Context, hash string) (*model.PasswordResetToken, error) {
	var t model.PasswordResetToken
	filter := bson.M{
		"token_hash": hash,
		"used_at":    bson.M{"$exists": false},
		"expires_at": bson.M{"$gt": time.Now().UTC()},
	}
	err := r.col.FindOne(ctx, filter).Decode(&t)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, apperr.ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *PasswordResetTokenRepository) MarkUsed(ctx context.Context, id primitive.ObjectID) error {
	now := time.Now().UTC()
	_, err := r.col.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"used_at": now}})
	return err
}
