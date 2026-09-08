package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type PasswordResetToken struct {
	ID        primitive.ObjectID `bson:"_id" json:"id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"userId"`
	TokenHash string             `bson:"token_hash" json:"-"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expiresAt"`
	UsedAt    *time.Time         `bson:"used_at,omitempty" json:"usedAt,omitempty"`
	CreatedAt time.Time          `bson:"created_at" json:"createdAt"`
}
