// cmd/api/main.go
package main

import (
	"context"
	"log"
	"time"

	"bom-tanstack-api/internal/bootstrap"
	"bom-tanstack-api/internal/config"
	"bom-tanstack-api/internal/db"
	"bom-tanstack-api/internal/handler"
	"bom-tanstack-api/internal/mailer"
	"bom-tanstack-api/internal/repository"
	"bom-tanstack-api/internal/router"
	"bom-tanstack-api/internal/service"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := db.Connect(ctx, cfg.MongoURI)
	if err != nil {
		log.Fatalf("mongo connect: %v", err)
	}
	database := client.Database(cfg.MongoDBName)

	if err := db.EnsureIndexes(ctx, database); err != nil {
		log.Fatalf("ensure indexes: %v", err)
	}

	userRepo := repository.NewUserRepository(database)
	refreshTokenRepo := repository.NewRefreshTokenRepository(database)
	resetTokenRepo := repository.NewPasswordResetTokenRepository(database)

	if err := bootstrap.SeedAdmin(ctx, userRepo, cfg.SeedAdminEmail, cfg.SeedAdminPassword); err != nil {
		log.Fatalf("seed admin: %v", err)
	}
	adminExists, err := userRepo.ExistsActiveAdmin(ctx)
	if err != nil {
		log.Fatalf("check existing admin: %v", err)
	}
	if !adminExists {
		log.Println("warning: no active admin exists and SEED_ADMIN_EMAIL/SEED_ADMIN_PASSWORD were not both set — /api/v1/users is unreachable until an admin is created")
	}

	mailerClient := mailer.NewSMTPMailer(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom)

	authService := service.NewAuthService(
		userRepo, refreshTokenRepo, resetTokenRepo, mailerClient,
		cfg.JWTSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.ResetTokenTTL, cfg.AppBaseURL,
	)
	userService := service.NewUserService(userRepo, resetTokenRepo, mailerClient, cfg.ResetTokenTTL, cfg.AppBaseURL)

	authHandler := handler.NewAuthHandler(authService)
	userHandler := handler.NewUserHandler(userService)

	e := router.New(cfg.JWTSecret, authHandler, userHandler)

	// Echo v5's Start blocks the whole request/response/graceful-shutdown
	// lifecycle internally: it installs its own SIGINT/SIGTERM handler and
	// only returns once the HTTP server has finished a graceful shutdown
	// (or failed to start in the first place). There is no separate
	// e.Shutdown to call from application code — unlike Echo v4, no
	// goroutine/signal.Notify/manual-Shutdown dance is needed or possible.
	if err := e.Start(":" + cfg.Port); err != nil {
		log.Printf("server stopped: %v", err)
	}

	disconnectCtx, disconnectCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer disconnectCancel()
	if err := client.Disconnect(disconnectCtx); err != nil {
		log.Printf("mongo disconnect: %v", err)
	}
}
