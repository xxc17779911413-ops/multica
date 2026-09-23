package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/logger"
	"golang.org/x/crypto/bcrypt"
)

// loginTimingPadding is compared against when the email is unknown so an
// attacker cannot distinguish "no such account" from "wrong password" by
// timing. Generated once per process.
var loginTimingPadding, _ = bcrypt.GenerateFromPassword(
	[]byte("multica-login-timing-padding"), auth.PasswordHashCost)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Login authenticates an email + password pair. Accounts created before
// passwords existed get a structured `password_not_set` rejection so the
// client can route them through the one-time verification-code bridge.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	if auth.IsTemporarilyDisabledUserEmail(email) {
		writeError(w, http.StatusForbidden, auth.TemporarilyDisabledUserError)
		return
	}

	user, err := h.Queries.GetUserByEmail(r.Context(), email)
	if err != nil {
		if isNotFound(err) {
			_ = bcrypt.CompareHashAndPassword(loginTimingPadding, []byte(req.Password))
			writeError(w, http.StatusUnauthorized, "invalid email or password")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	if auth.IsTemporarilyDisabledUser(uuidToString(user.ID), user.Email) {
		writeError(w, http.StatusForbidden, auth.TemporarilyDisabledUserError)
		return
	}

	if user.PasswordHash == "" {
		// Pre-password account: one verification-code sign-in sets a
		// password; after that this branch is unreachable for it.
		writeJSON(w, http.StatusConflict, map[string]any{
			"code":  "password_not_set",
			"error": "this account has no password yet; sign in with a code to set one",
		})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	tokenString, err := h.issueJWT(user)
	if err != nil {
		if errors.Is(err, auth.ErrTemporarilyDisabledUser) {
			writeError(w, http.StatusForbidden, auth.TemporarilyDisabledUserError)
			return
		}
		slog.Warn("login failed", append(logger.RequestAttrs(r), "error", err, "email", email)...)
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	if err := auth.SetAuthCookies(w, tokenString); err != nil {
		slog.Warn("failed to set auth cookies", "error", err)
	}
	if h.CFSigner != nil {
		for _, cookie := range h.CFSigner.SignedCookies(time.Now().Add(auth.AuthTokenTTL())) {
			http.SetCookie(w, cookie)
		}
	}

	slog.Info("user logged in with password", append(logger.RequestAttrs(r), "user_id", uuidToString(user.ID), "email", user.Email)...)
	writeJSON(w, http.StatusOK, LoginResponse{
		Token: tokenString,
		User:  h.userToResponse(user),
	})
}

type SetPasswordRequest struct {
	Password string `json:"password"`
}

// SetPassword stores the caller's password. It backs the one-time migration
// bridge for accounts created before passwords existed; re-setting an existing
// password is allowed because possession of an authenticated session is the
// authorization.
func (h *Handler) SetPassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	var req SetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	if _, err := h.DB.Exec(r.Context(),
		`UPDATE "user" SET password_hash = $1, updated_at = now() WHERE id = $2`,
		hash, parseUUID(userID)); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save password")
		return
	}
	slog.Info("password set", append(logger.RequestAttrs(r), "user_id", userID)...)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePassword rotates the caller's password. Session possession is the
// authorization, but the current password is still required so a borrowed
// session cannot lock the owner out of their own account.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "current and new password are required")
		return
	}
	if err := auth.ValidatePassword(req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var currentHash string
	if err := h.DB.QueryRow(r.Context(),
		`SELECT password_hash FROM "user" WHERE id = $1`, parseUUID(userID)).Scan(&currentHash); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	// Pre-password accounts (bridge not completed yet) may set one freely:
	// an authenticated session is the only proof they can present.
	if currentHash != "" {
		if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"code":  "invalid_password",
				"error": "current password is incorrect",
			})
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.NewPassword)) == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"code":  "password_unchanged",
				"error": "new password must differ from the current one",
			})
			return
		}
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	if _, err := h.DB.Exec(r.Context(),
		`UPDATE "user" SET password_hash = $1, updated_at = now() WHERE id = $2`,
		hash, parseUUID(userID)); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save password")
		return
	}
	slog.Info("password changed", append(logger.RequestAttrs(r), "user_id", userID)...)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
