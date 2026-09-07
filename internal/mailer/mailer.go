package mailer

import (
	"context"
	"fmt"
)

type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

func BuildPasswordResetEmail(resetLink string) (subject, body string) {
	subject = "Reset your password"
	body = fmt.Sprintf(
		"We received a request to reset your password.\n\nClick the link below to choose a new one:\n%s\n\nIf you did not request this, you can ignore this email.",
		resetLink,
	)
	return subject, body
}
