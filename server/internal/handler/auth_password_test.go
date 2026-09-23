package handler

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/testutil"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"golang.org/x/crypto/bcrypt"
)

func TestValidatePassword(t *testing.T) {
	long := strings.Repeat("a", 73)
	for _, tc := range []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"eight characters is enough", "hunter2!secure", false},
		{"too short", "short7!", true},
		{"over bcrypt byte limit", long, true},
		{"eight CJK runes pass (multi-byte)", "密码密码密码密码", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := auth.ValidatePassword(tc.password)
			if tc.wantErr && err == nil {
				t.Fatalf("validatePassword(%q) = nil, want error", tc.password)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validatePassword(%q) = %v, want nil", tc.password, err)
			}
		})
	}
}

// An unknown email must fail exactly like a wrong password so the response
// cannot be used to enumerate accounts.
func TestLoginUnknownEmailIsRejected(t *testing.T) {
	h := newTestHandler(Config{})
	h.Queries = db.New(&mockDB{getUserErr: pgx.ErrNoRows})

	req := testutil.JSONRequest(http.MethodPost, "/auth/login", map[string]any{
		"email":    "nobody@example.com",
		"password": "hunter2!secure",
	})
	testutil.Call(t, h.Login, req).Want(http.StatusUnauthorized)
}

// Registration via code must carry a password; the code proves the mailbox and
// the password becomes the account's only email sign-in path.
func TestPasswordRegistrationAndLogin(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database fixture unavailable")
	}
	ctx := context.Background()
	email := fmt.Sprintf("pw-register-%d@multica.ai", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = testPool.Exec(ctx, `DELETE FROM "user" WHERE email = $1`, email)
		_, _ = testPool.Exec(ctx, `DELETE FROM verification_code WHERE email = $1`, email)
	})

	insertCode := func(code string) {
		t.Helper()
		if _, err := testPool.Exec(ctx,
			`INSERT INTO verification_code (email, code, expires_at) VALUES ($1, $2, now() + interval '10 minutes')`,
			email, code); err != nil {
			t.Fatalf("seed verification code: %v", err)
		}
	}

	// 1. Verify without a password → structured rejection.
	insertCode("111111")
	req := testutil.JSONRequest(http.MethodPost, "/auth/verify-code", map[string]any{
		"email": email, "code": "111111",
	})
	resp := testutil.Call(t, testHandler.VerifyCode, req).Want(http.StatusBadRequest)
	if code, _ := resp.Map()["code"].(string); code != "password_required" {
		t.Fatalf("verify without password code = %q, want password_required (body %s)", code, resp.Text())
	}

	// 2. Verify with a password → account created, hash persisted.
	insertCode("222222")
	req = testutil.JSONRequest(http.MethodPost, "/auth/verify-code", map[string]any{
		"email": email, "code": "222222", "password": "hunter2!secure",
	})
	resp = testutil.Call(t, testHandler.VerifyCode, req).Want(http.StatusOK)
	var login LoginResponse
	resp.JSON(&login)
	if login.Token == "" || login.MustSetPassword {
		t.Fatalf("register response token=%q must_set=%v, want token without must_set_password", login.Token, login.MustSetPassword)
	}
	var hash string
	if err := testPool.QueryRow(ctx, `SELECT password_hash FROM "user" WHERE email = $1`, email).Scan(&hash); err != nil {
		t.Fatalf("load password hash: %v", err)
	}
	if hash == "" || strings.Contains(hash, "hunter2") {
		t.Fatalf("stored hash = %q, want a bcrypt digest (never plaintext)", hash)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("hunter2!secure")); err != nil {
		t.Fatalf("stored hash does not validate the password: %v", err)
	}

	// 3. Password login: correct pair succeeds, wrong pair does not.
	req = testutil.JSONRequest(http.MethodPost, "/auth/login", map[string]any{
		"email": email, "password": "hunter2!secure",
	})
	testutil.Call(t, testHandler.Login, req).Want(http.StatusOK)
	req = testutil.JSONRequest(http.MethodPost, "/auth/login", map[string]any{
		"email": email, "password": "wrong-password!",
	})
	testutil.Call(t, testHandler.Login, req).Want(http.StatusUnauthorized)

	// 4. Code login is closed for password accounts.
	insertCode("333333")
	req = testutil.JSONRequest(http.MethodPost, "/auth/verify-code", map[string]any{
		"email": email, "code": "333333",
	})
	resp = testutil.Call(t, testHandler.VerifyCode, req).Want(http.StatusConflict)
	if code, _ := resp.Map()["code"].(string); code != "password_login_required" {
		t.Fatalf("code login for password account code = %q, want password_login_required", code)
	}
}

// Pre-password accounts sign in with a code exactly once; the response forces
// the set-password screen and afterwards password login is the only path.
func TestLegacyAccountMustSetPassword(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database fixture unavailable")
	}
	ctx := context.Background()
	email := fmt.Sprintf("pw-legacy-%d@multica.ai", time.Now().UnixNano())
	var userID string
	if err := testPool.QueryRow(ctx,
		`INSERT INTO "user" (email, name) VALUES ($1, $2) RETURNING id`,
		email, "Legacy User").Scan(&userID); err != nil {
		t.Fatalf("seed legacy user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(ctx, `DELETE FROM "user" WHERE email = $1`, email)
		_, _ = testPool.Exec(ctx, `DELETE FROM verification_code WHERE email = $1`, email)
	})

	if _, err := testPool.Exec(ctx,
		`INSERT INTO verification_code (email, code, expires_at) VALUES ($1, '444444', now() + interval '10 minutes')`,
		email); err != nil {
		t.Fatalf("seed verification code: %v", err)
	}
	req := testutil.JSONRequest(http.MethodPost, "/auth/verify-code", map[string]any{
		"email": email, "code": "444444",
	})
	resp := testutil.Call(t, testHandler.VerifyCode, req).Want(http.StatusOK)
	var login LoginResponse
	resp.JSON(&login)
	if !login.MustSetPassword {
		t.Fatalf("legacy verify must_set_password = false, want true")
	}

	// Set the password with the fresh session (X-User-ID stands in for the
	// middleware in handler tests).
	req = testutil.JSONRequest(http.MethodPost, "/api/auth/set-password", map[string]any{
		"password": "bridged!pass9",
	})
	req.Header.Set("X-User-ID", userID)
	testutil.Call(t, testHandler.SetPassword, req).Want(http.StatusOK)

	req = testutil.JSONRequest(http.MethodPost, "/auth/login", map[string]any{
		"email": email, "password": "bridged!pass9",
	})
	testutil.Call(t, testHandler.Login, req).Want(http.StatusOK)
}

// Change-password requires the current password (a borrowed session must not
// be able to lock the owner out), rejects policy violations, and rotates the
// credential every login path then uses.
func TestChangePassword(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database fixture unavailable")
	}
	ctx := context.Background()
	email := fmt.Sprintf("pw-change-%d@multica.ai", time.Now().UnixNano())
	seedHash, err := auth.HashPassword("original!pass9")
	if err != nil {
		t.Fatalf("hash seed password: %v", err)
	}
	var userID string
	if err := testPool.QueryRow(ctx,
		`INSERT INTO "user" (email, name, password_hash) VALUES ($1, $2, $3) RETURNING id`,
		email, "Change User", seedHash).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(ctx, `DELETE FROM "user" WHERE email = $1`, email)
	})

	// 1. Wrong current password → 401 invalid_password.
	req := testutil.JSONRequest(http.MethodPost, "/api/auth/change-password", map[string]any{
		"current_password": "wrong!pass9", "new_password": "rotated!pass9",
	})
	req.Header.Set("X-User-ID", userID)
	resp := testutil.Call(t, testHandler.ChangePassword, req).Want(http.StatusUnauthorized)
	if code, _ := resp.Map()["code"].(string); code != "invalid_password" {
		t.Fatalf("wrong current code = %q, want invalid_password (body %s)", code, resp.Text())
	}

	// 2. Policy violation → 400.
	req = testutil.JSONRequest(http.MethodPost, "/api/auth/change-password", map[string]any{
		"current_password": "original!pass9", "new_password": "short7!",
	})
	req.Header.Set("X-User-ID", userID)
	testutil.Call(t, testHandler.ChangePassword, req).Want(http.StatusBadRequest)

	// 3. New must differ from current → 400 password_unchanged.
	req = testutil.JSONRequest(http.MethodPost, "/api/auth/change-password", map[string]any{
		"current_password": "original!pass9", "new_password": "original!pass9",
	})
	req.Header.Set("X-User-ID", userID)
	resp = testutil.Call(t, testHandler.ChangePassword, req).Want(http.StatusBadRequest)
	if code, _ := resp.Map()["code"].(string); code != "password_unchanged" {
		t.Fatalf("same-password code = %q, want password_unchanged (body %s)", code, resp.Text())
	}

	// 4. Happy path → the old password is dead, the new one signs in.
	req = testutil.JSONRequest(http.MethodPost, "/api/auth/change-password", map[string]any{
		"current_password": "original!pass9", "new_password": "rotated!pass9",
	})
	req.Header.Set("X-User-ID", userID)
	testutil.Call(t, testHandler.ChangePassword, req).Want(http.StatusOK)
	req = testutil.JSONRequest(http.MethodPost, "/auth/login", map[string]any{
		"email": email, "password": "original!pass9",
	})
	testutil.Call(t, testHandler.Login, req).Want(http.StatusUnauthorized)
	req = testutil.JSONRequest(http.MethodPost, "/auth/login", map[string]any{
		"email": email, "password": "rotated!pass9",
	})
	testutil.Call(t, testHandler.Login, req).Want(http.StatusOK)

	// 5. Pre-password account (empty hash) may set one without proving the
	// (nonexistent) current password.
	email2 := fmt.Sprintf("pw-nohash-%d@multica.ai", time.Now().UnixNano())
	var userID2 string
	if err := testPool.QueryRow(ctx,
		`INSERT INTO "user" (email, name) VALUES ($1, $2) RETURNING id`,
		email2, "No Hash User").Scan(&userID2); err != nil {
		t.Fatalf("seed hashless user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(ctx, `DELETE FROM "user" WHERE email = $1`, email2)
	})
	req = testutil.JSONRequest(http.MethodPost, "/api/auth/change-password", map[string]any{
		"current_password": "whatever!9", "new_password": "brandnew!pass9",
	})
	req.Header.Set("X-User-ID", userID2)
	testutil.Call(t, testHandler.ChangePassword, req).Want(http.StatusOK)
	req = testutil.JSONRequest(http.MethodPost, "/auth/login", map[string]any{
		"email": email2, "password": "brandnew!pass9",
	})
	testutil.Call(t, testHandler.Login, req).Want(http.StatusOK)
}
