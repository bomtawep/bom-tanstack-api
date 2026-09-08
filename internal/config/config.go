package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port              string
	MongoURI          string
	MongoDBName       string
	JWTSecret         string
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
	ResetTokenTTL     time.Duration
	SMTPHost          string
	SMTPPort          int
	SMTPUsername      string
	SMTPPassword      string
	SMTPFrom          string
	AppBaseURL        string
	SeedAdminEmail    string
	SeedAdminPassword string
}

func Load() (*Config, error) {
	cfg := &Config{
		Port:              getEnvDefault("PORT", "8080"),
		MongoURI:          os.Getenv("MONGO_URI"),
		MongoDBName:       os.Getenv("MONGO_DB_NAME"),
		JWTSecret:         os.Getenv("JWT_SECRET"),
		SMTPHost:          os.Getenv("SMTP_HOST"),
		SMTPUsername:      os.Getenv("SMTP_USERNAME"),
		SMTPPassword:      os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:          os.Getenv("SMTP_FROM"),
		AppBaseURL:        os.Getenv("APP_BASE_URL"),
		SeedAdminEmail:    os.Getenv("SEED_ADMIN_EMAIL"),
		SeedAdminPassword: os.Getenv("SEED_ADMIN_PASSWORD"),
	}

	for name, val := range map[string]string{
		"MONGO_URI":     cfg.MongoURI,
		"MONGO_DB_NAME": cfg.MongoDBName,
		"JWT_SECRET":    cfg.JWTSecret,
		"SMTP_HOST":     cfg.SMTPHost,
		"SMTP_FROM":     cfg.SMTPFrom,
		"APP_BASE_URL":  cfg.AppBaseURL,
	} {
		if val == "" {
			return nil, fmt.Errorf("config: required env var %s is not set", name)
		}
	}

	port, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if err != nil {
		return nil, fmt.Errorf("config: invalid SMTP_PORT: %w", err)
	}
	cfg.SMTPPort = port

	cfg.AccessTokenTTL, err = parseDurationDefault("ACCESS_TOKEN_TTL", 15*time.Minute)
	if err != nil {
		return nil, err
	}
	cfg.RefreshTokenTTL, err = parseDurationDefault("REFRESH_TOKEN_TTL", 720*time.Hour)
	if err != nil {
		return nil, err
	}
	cfg.ResetTokenTTL, err = parseDurationDefault("RESET_TOKEN_TTL", 30*time.Minute)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseDurationDefault(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: invalid %s: %w", key, err)
	}
	return d, nil
}
