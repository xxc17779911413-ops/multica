package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/multica-ai/multica/server/internal/auth"
	"golang.org/x/term"
)

// runAdmin backs `server admin <command> ...`, the operator escape hatch for
// credentialed operations that must work inside the deployed container even
// when the HTTP server is down or refusing to boot.
func runAdmin(args []string) int {
	if len(args) == 0 {
		adminUsage()
		return 2
	}
	switch args[0] {
	case "reset-password":
		return runAdminResetPassword(args[1:])
	case "help", "-h", "--help":
		adminUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown admin command: %s\n\n", args[0])
		adminUsage()
		return 2
	}
}

func adminUsage() {
	fmt.Fprint(os.Stderr, `Usage:
  server admin <command> [arguments]

Commands:
  reset-password <email> [--password <new-password>]
      Replace the account's password. Without --password the new password
      is read from an interactive prompt (hidden, entered twice).
`)
}

func runAdminResetPassword(args []string) int {
	fs := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	password := fs.String("password", "", "new password (omit to enter interactively)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: server admin reset-password <email> [--password <new-password>]")
		return 2
	}
	email := strings.ToLower(strings.TrimSpace(fs.Arg(0)))
	if email == "" {
		fmt.Fprintln(os.Stderr, "email is required")
		return 2
	}

	newPassword := *password
	if newPassword == "" {
		entered, err := promptNewPassword()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read password: %v\n", err)
			return 1
		}
		newPassword = entered
	}
	if err := auth.ValidatePassword(newPassword); err != nil {
		fmt.Fprintf(os.Stderr, "invalid password: %v\n", err)
		return 2
	}
	if err := resetPasswordInDB(email, newPassword); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	fmt.Printf("Password updated for %s.\n", email)
	return 0
}

func resetPasswordInDB(email, newPassword string) error {
	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dbURL == "" {
		return errors.New("DATABASE_URL is not set; run this inside the backend container, e.g. docker exec -it <backend> /app/server admin reset-password")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()

	var userID string
	err = pool.QueryRow(ctx, `SELECT id FROM "user" WHERE email = $1`, email).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("no user with email %s", email)
	}
	if err != nil {
		return fmt.Errorf("look up user: %w", err)
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE "user" SET password_hash = $1, updated_at = now() WHERE id = $2`,
		hash, userID); err != nil {
		return fmt.Errorf("save password: %w", err)
	}
	return nil
}

func promptNewPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("stdin is not a terminal; pass --password instead")
	}
	fmt.Fprint(os.Stderr, "New password: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Repeat new password: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", errors.New("passwords do not match")
	}
	return string(first), nil
}
