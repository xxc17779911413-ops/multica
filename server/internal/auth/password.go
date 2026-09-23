package auth

import (
	"errors"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// Password policy shared by every password entry point: registration, the
// pre-password bridge, change-password, and the admin CLI. bcrypt hashes at
// most 72 bytes of input, so longer passwords are rejected rather than
// silently truncated.
const (
	MinPasswordRunes = 8
	MaxPasswordBytes = 72
	PasswordHashCost = 12
)

func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < MinPasswordRunes {
		return errors.New("password must be at least 8 characters")
	}
	if len(password) > MaxPasswordBytes {
		return errors.New("password must be at most 72 bytes")
	}
	return nil
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), PasswordHashCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
