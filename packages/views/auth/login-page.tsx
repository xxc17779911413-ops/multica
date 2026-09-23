"use client";

import { useState, useEffect, useCallback, useRef, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from "@multica/ui/components/ui/card";
import { Alert, AlertDescription } from "@multica/ui/components/ui/alert";
import { Input } from "@multica/ui/components/ui/input";
import { Button } from "@multica/ui/components/ui/button";
import { Label } from "@multica/ui/components/ui/label";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@multica/ui/components/ui/input-otp";
import { useAuthStore } from "@multica/core/auth";
import { workspaceKeys } from "@multica/core/workspace/queries";
import { api, ApiError } from "@multica/core/api";
import type { User } from "@multica/core/types";
import { useT } from "../i18n";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CliCallbackConfig {
  /** Validated localhost callback URL */
  url: string;
  /** Opaque state to pass back to CLI */
  state: string;
}

interface LoginPageProps {
  /** Logo element rendered above the title */
  logo?: ReactNode;
  /** Called after successful login. The workspace list is seeded into React
   *  Query before this fires, so the caller can compute a destination URL. */
  onSuccess: () => void;
  /** CLI callback config for authorizing CLI tools. */
  cliCallback?: CliCallbackConfig;
  /** Called after a token is obtained (e.g. to set cookies). */
  onTokenObtained?: () => void;
  /** Slot rendered at the bottom of the sign-in card, below the
   *  Google button. The web shell uses it for a "Prefer the desktop
   *  app?" prompt; desktop omits it (a download prompt inside the app
   *  would be absurd). */
  extra?: ReactNode;
  /**
   * Which step opens first. Production shells use the password form; tests
   * and non-password forks can open directly on the code flow.
   */
  defaultStep?: "login" | "email";
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function redirectToCliCallback(url: string, token: string, state: string) {
  const separator = url.includes("?") ? "&" : "?";
  window.location.href = `${url}${separator}token=${encodeURIComponent(token)}&state=${encodeURIComponent(state)}`;
}

/**
 * Validate that a CLI callback URL points to a safe host over HTTP.
 * Allows localhost and private/LAN IPs (RFC 1918) to support self-hosted setups
 * on local VMs while blocking arbitrary public hosts.
 */
export function validateCliCallback(cliCallback: string): boolean {
  try {
    const cbUrl = new URL(cliCallback);
    if (cbUrl.protocol !== "http:") return false;
    const h = cbUrl.hostname;
    if (h === "localhost" || h === "127.0.0.1") return true;
    // Allow RFC 1918 private IPs: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    if (/^10\./.test(h)) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
    if (/^192\.168\./.test(h)) return true;
    return false;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function LoginPage({
  logo,
  onSuccess,
  cliCallback,
  onTokenObtained,
  extra,
  defaultStep = "login",
}: LoginPageProps) {
  const { t } = useT("auth");
  const qc = useQueryClient();
  const [step, setStep] = useState<
    "login" | "email" | "code" | "set_password" | "cli_confirm"
  >(defaultStep);
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [cooldown, setCooldown] = useState(0);
  const [existingUser, setExistingUser] = useState<User | null>(null);
  // Password-first sign-in: "login" is the password form, "email"/"code"
  // carry registration and the one-time pre-password bridge, "set_password"
  // is the forced screen after a bridged code login.
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  // Revealed on the code step when the server says this email registers
  // (password_required) — the code stays valid because the server only
  // spends it once every gate has passed.
  const [needPassword, setNeedPassword] = useState(false);
  // Tracks how the existing session was detected so handleCliAuthorize
  // uses the matching token source (cookie → issueCliToken, localStorage → direct).
  const authSourceRef = useRef<"cookie" | "localStorage">("cookie");
  // The last session ended because the server rejected its credential, not
  // because the user asked to leave. Without saying so, landing here reads as
  // the app having lost their work for no reason.
  const sessionExpired = useAuthStore((state) => state.expired);

  // Check for existing session when CLI callback is present.
  // Prioritises cookie auth (= current browser session) to avoid authorising
  // the CLI with a stale or mismatched localStorage token.
  useEffect(() => {
    if (!cliCallback) return;

    // Snapshot the token before probing. The probe below is *expected* to 401
    // for a token-mode session, and a 401 ends the session — clearing this
    // very key — so reading it after the probe would always come back null
    // and the fallback could never run.
    const storedToken = localStorage.getItem("multica_token");

    // Ensure no stale bearer token interferes — we want to test the cookie first.
    api.setToken(null);

    api
      .getMe()
      .then((user) => {
        authSourceRef.current = "cookie";
        setExistingUser(user);
        setStep("cli_confirm");
      })
      .catch(() => {
        // Cookie auth failed — fall back to the token this browser had.
        if (!storedToken) return;

        localStorage.setItem("multica_token", storedToken);
        api.setToken(storedToken);
        api
          .getMe()
          .then((user) => {
            authSourceRef.current = "localStorage";
            setExistingUser(user);
            setStep("cli_confirm");
          })
          .catch(() => {
            api.setToken(null);
            localStorage.removeItem("multica_token");
          });
      });
  }, [cliCallback]);

  // Cooldown timer for resend
  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  const handleSendCode = useCallback(
    async (e?: React.FormEvent) => {
      e?.preventDefault();
      if (!email) {
        setError(t(($) => $.common.email_required));
        return;
      }
      setLoading(true);
      setError("");
      try {
        await useAuthStore.getState().sendCode(email);
        setStep("code");
        setCode("");
        setCooldown(60);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : `${t(($) => $.errors.send_failed)} ${t(($) => $.errors.server_unreachable)}`,
        );
      } finally {
        setLoading(false);
      }
    },
    [email, t],
  );

  const handleVerify = useCallback(
    async (value: string) => {
      if (value.length !== 6) return;
      setLoading(true);
      setError("");
      try {
        if (cliCallback) {
          // CLI path: get token directly for the redirect URL
          const { token } = await api.verifyCode(
            email,
            value,
            needPassword ? password : undefined,
          );
          localStorage.setItem("multica_token", token);
          api.setToken(token);
          onTokenObtained?.();
          redirectToCliCallback(cliCallback.url, token, cliCallback.state);
          return;
        }

        // Normal path: seed the workspace list into the Query cache so the
        // caller's onSuccess can read it synchronously to compute a destination
        // URL (first workspace's slug, or /workspaces/new for zero-workspace
        // users).
        await useAuthStore
          .getState()
          .verifyCode(email, value, needPassword ? password : undefined);
        if (useAuthStore.getState().mustSetPassword) {
          // Pre-password account: the session is live but unusable until a
          // password exists, which is what the next screen collects.
          setStep("set_password");
          setCode("");
          setPassword("");
          setConfirmPassword("");
          setLoading(false);
          return;
        }
        const wsList = await api.listWorkspaces();
        qc.setQueryData(workspaceKeys.list(), wsList);
        onTokenObtained?.();
        onSuccess();
      } catch (err) {
        if (
          err instanceof ApiError &&
          err.body &&
          typeof err.body === "object" &&
          (err.body as { code?: unknown }).code === "password_required"
        ) {
          // New email: keep the same code and reveal the password fields.
          setNeedPassword(true);
          setError(t(($) => $.verify.password_hint));
          setLoading(false);
          return;
        }
        setError(
          err instanceof Error
            ? err.message
            : t(($) => $.errors.code_invalid),
        );
        setCode("");
        setLoading(false);
      }
    },
    [email, needPassword, password, onSuccess, cliCallback, onTokenObtained, qc, t],
  );

  const handleLogin = useCallback(async () => {
    if (!email) {
      setError(t(($) => $.common.email_required));
      return;
    }
    if (!password) {
      setError(t(($) => $.signin.password_required));
      return;
    }
    setLoading(true);
    setError("");
    try {
      await useAuthStore.getState().login(email, password);
      const wsList = await api.listWorkspaces();
      qc.setQueryData(workspaceKeys.list(), wsList);
      onTokenObtained?.();
      onSuccess();
    } catch (err) {
      if (
        err instanceof ApiError &&
        err.body &&
        typeof err.body === "object" &&
        (err.body as { code?: unknown }).code === "password_not_set"
      ) {
        // Pre-password account: the code bridge is the only way in, and it
        // is also what sets the password.
        setError(t(($) => $.signin.password_not_set));
        setStep("email");
        setPassword("");
        setLoading(false);
        return;
      }
      setError(err instanceof Error ? err.message : t(($) => $.errors.login_failed));
      setLoading(false);
    }
  }, [email, password, onSuccess, onTokenObtained, qc, t]);

  const handleSetPassword = useCallback(async () => {
    if (password.length < 8) {
      setError(t(($) => $.set_password.too_short));
      return;
    }
    if (password !== confirmPassword) {
      setError(t(($) => $.set_password.mismatch));
      return;
    }
    setLoading(true);
    setError("");
    try {
      await useAuthStore.getState().setPassword(password);
      const wsList = await api.listWorkspaces();
      qc.setQueryData(workspaceKeys.list(), wsList);
      onTokenObtained?.();
      onSuccess();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : t(($) => $.set_password.failed),
      );
      setLoading(false);
    }
  }, [password, confirmPassword, onSuccess, onTokenObtained, qc, t]);

  const handleResend = async () => {
    if (cooldown > 0) return;
    setError("");
    try {
      await useAuthStore.getState().sendCode(email);
      setCooldown(60);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : t(($) => $.errors.resend_failed),
      );
    }
  };

  const handleCliAuthorize = async () => {
    if (!cliCallback) return;
    setLoading(true);

    try {
      let token: string;

      if (authSourceRef.current === "localStorage") {
        // Session was detected via localStorage — reuse that token directly.
        const stored = localStorage.getItem("multica_token");
        if (!stored) throw new Error("token missing");
        token = stored;
      } else {
        // Session was detected via cookie — obtain a bearer token from the server.
        const res = await api.issueCliToken();
        token = res.token;
      }

      onTokenObtained?.();
      redirectToCliCallback(cliCallback.url, token, cliCallback.state);
    } catch {
      setError(t(($) => $.errors.cli_auth_failed));
      setExistingUser(null);
      setStep("email");
      setLoading(false);
    }
  };

  // -------------------------------------------------------------------------
  // CLI confirm step
  // -------------------------------------------------------------------------

  if (step === "cli_confirm" && existingUser) {
    return (
      <div className="flex min-h-svh items-center justify-center">
        <Card className="w-full max-w-sm">
          <CardHeader className="text-center">
            {logo && <div className="mx-auto mb-4">{logo}</div>}
            <CardTitle className="text-display-sm">
              {t(($) => $.cli.title)}
            </CardTitle>
            <CardDescription>
              {t(($) => $.cli.description, { email: existingUser.email })}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <Button
              onClick={handleCliAuthorize}
              disabled={loading}
              className="w-full"
              size="lg"
            >
              {loading
                ? t(($) => $.cli.authorizing)
                : t(($) => $.cli.authorize)}
            </Button>
            <Button
              variant="ghost"
              className="w-full"
              onClick={() => {
                setExistingUser(null);
                setStep("email");
              }}
            >
              {t(($) => $.cli.different_account)}
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  // -------------------------------------------------------------------------
  // Password step
  // -------------------------------------------------------------------------

  if (step === "login") {
    return (
      <div className="flex min-h-svh items-center justify-center">
        <Card className="w-full max-w-sm">
          <CardHeader className="text-center">
            {logo && <div className="mx-auto mb-4">{logo}</div>}
            <CardTitle className="text-display-sm">
              {t(($) => $.signin.title)}
            </CardTitle>
            <CardDescription>
              {t(($) => $.signin.password_description)}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {sessionExpired && (
              <Alert>
                <AlertDescription>
                  {t(($) => $.errors.session_expired)}
                </AlertDescription>
              </Alert>
            )}
            <form
              id="password-login-form"
              onSubmit={(event) => {
                event.preventDefault();
                handleLogin();
              }}
              className="space-y-4"
            >
              <div className="space-y-2">
                <Label htmlFor="login-email-pw">{t(($) => $.common.email)}</Label>
                <Input
                  id="login-email-pw"
                  type="email"
                  placeholder={t(($) => $.common.email_placeholder)}
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoFocus
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="login-password">{t(($) => $.signin.password)}</Label>
                <Input
                  id="login-password"
                  type="password"
                  placeholder={t(($) => $.signin.password_placeholder)}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
              {error && <p className="text-body text-destructive">{error}</p>}
            </form>
          </CardContent>
          <CardFooter className="flex flex-col gap-3">
            <Button
              type="submit"
              form="password-login-form"
              className="w-full"
              size="lg"
              disabled={!email || !password || loading}
            >
              {loading ? t(($) => $.signin.signing_in) : t(($) => $.signin.sign_in)}
            </Button>
            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={() => {
                setStep("email");
                setError("");
                setPassword("");
              }}
            >
              {t(($) => $.signin.use_code)}
            </Button>
            {extra && <div className="w-full pt-1 text-center">{extra}</div>}
          </CardFooter>
        </Card>
      </div>
    );
  }

  // -------------------------------------------------------------------------
  // Code verification step
  // -------------------------------------------------------------------------

  if (step === "code") {
    return (
      <div className="flex min-h-svh items-center justify-center">
        <Card className="w-full max-w-sm">
          <CardHeader className="text-center">
            {logo && <div className="mx-auto mb-4">{logo}</div>}
            <CardTitle className="text-display-sm">
              {t(($) => $.verify.title)}
            </CardTitle>
            <CardDescription>
              {t(($) => $.verify.description, { email })}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col items-center gap-4">
            <InputOTP
              autoFocus
              maxLength={6}
              value={code}
              onChange={(value) => {
                setCode(value);
                if (value.length === 6) handleVerify(value);
              }}
              disabled={loading}
            >
              <InputOTPGroup>
                <InputOTPSlot index={0} />
                <InputOTPSlot index={1} />
                <InputOTPSlot index={2} />
                <InputOTPSlot index={3} />
                <InputOTPSlot index={4} />
                <InputOTPSlot index={5} />
              </InputOTPGroup>
            </InputOTP>
            {needPassword && (
              <div className="w-full space-y-2 text-left">
                <p className="text-caption text-muted-foreground">
                  {t(($) => $.verify.password_hint)}
                </p>
                <Input
                  type="password"
                  placeholder={t(($) => $.verify.password)}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={loading}
                />
                <Input
                  type="password"
                  placeholder={t(($) => $.verify.confirm_password)}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  disabled={loading}
                />
                <Button
                  type="button"
                  className="w-full"
                  disabled={
                    loading || !password || password !== confirmPassword
                  }
                  onClick={() => handleVerify(code)}
                >
                  {loading
                    ? t(($) => $.signin.signing_in)
                    : t(($) => $.verify.submit_password)}
                </Button>
              </div>
            )}
            {error && (
              <p className="text-body text-destructive">{error}</p>
            )}
            <div className="flex items-center gap-2 text-body text-muted-foreground">
              <button
                type="button"
                onClick={handleResend}
                disabled={cooldown > 0}
                className="text-primary underline-offset-4 hover:underline disabled:text-muted-foreground disabled:no-underline disabled:cursor-not-allowed"
              >
                {cooldown > 0
                  ? t(($) => $.verify.resend_cooldown, { seconds: cooldown })
                  : t(($) => $.verify.resend)}
              </button>
            </div>
          </CardContent>
          <CardFooter>
            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={() => {
                setStep("email");
                setCode("");
                setError("");
              }}
            >
              {t(($) => $.common.back)}
            </Button>
          </CardFooter>
        </Card>
      </div>
    );
  }

  // -------------------------------------------------------------------------
  // Forced set-password step (pre-password account bridged by code)
  // -------------------------------------------------------------------------

  if (step === "set_password") {
    return (
      <div className="flex min-h-svh items-center justify-center">
        <Card className="w-full max-w-sm">
          <CardHeader className="text-center">
            {logo && <div className="mx-auto mb-4">{logo}</div>}
            <CardTitle className="text-display-sm">
              {t(($) => $.set_password.title)}
            </CardTitle>
            <CardDescription>
              {t(($) => $.set_password.description)}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form
              id="set-password-form"
              onSubmit={(event) => {
                event.preventDefault();
                handleSetPassword();
              }}
              className="space-y-4"
            >
              <div className="space-y-2">
                <Label htmlFor="set-password">
                  {t(($) => $.set_password.password)}
                </Label>
                <Input
                  id="set-password"
                  type="password"
                  autoFocus
                  minLength={8}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="set-password-confirm">
                  {t(($) => $.set_password.confirm)}
                </Label>
                <Input
                  id="set-password-confirm"
                  type="password"
                  minLength={8}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                />
              </div>
              {error && <p className="text-body text-destructive">{error}</p>}
            </form>
          </CardContent>
          <CardFooter>
            <Button
              type="submit"
              form="set-password-form"
              className="w-full"
              size="lg"
              disabled={!password || !confirmPassword || loading}
            >
              {loading
                ? t(($) => $.set_password.submitting)
                : t(($) => $.set_password.submit)}
            </Button>
          </CardFooter>
        </Card>
      </div>
    );
  }

  // -------------------------------------------------------------------------
  // Email step
  // -------------------------------------------------------------------------

  return (
    <div className="flex min-h-svh items-center justify-center">
      <Card className="w-full max-w-sm">
        <CardHeader className="text-center">
          {logo && <div className="mx-auto mb-4">{logo}</div>}
          <CardTitle className="text-display-sm">
            {t(($) => $.signin.title)}
          </CardTitle>
          <CardDescription>
            {t(($) => $.signin.description)}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {sessionExpired && (
            <Alert>
              <AlertDescription>
                {t(($) => $.errors.session_expired)}
              </AlertDescription>
            </Alert>
          )}
          <form id="login-form" onSubmit={handleSendCode} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="login-email">{t(($) => $.common.email)}</Label>
              <Input
                id="login-email"
                type="email"
                placeholder={t(($) => $.common.email_placeholder)}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoFocus
                required
              />
            </div>
            {error && (
              <p className="text-body text-destructive">{error}</p>
            )}
          </form>
        </CardContent>
        <CardFooter className="flex flex-col gap-3">
          <Button
            type="submit"
            form="login-form"
            className="w-full"
            size="lg"
            disabled={!email || loading}
          >
            {loading
              ? t(($) => $.signin.sending)
              : t(($) => $.signin.continue)}
          </Button>
          <Button
            type="button"
            variant="ghost"
            className="w-full"
            onClick={() => {
              setStep("login");
              setError("");
            }}
          >
            {t(($) => $.signin.use_password)}
          </Button>
          {extra && <div className="w-full pt-1 text-center">{extra}</div>}
        </CardFooter>
      </Card>
    </div>
  );
}
