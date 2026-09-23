"use client";

import { useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "@multica/core/api";
import { useWorkspaceId } from "@multica/core/hooks";
import { Button } from "@multica/ui/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@multica/ui/components/ui/select";
import { cn } from "@multica/ui/lib/utils";
import { toast } from "sonner";
import { useT } from "../../i18n";
import { PAGE_GUTTER } from "../../layout/page-header";

export function RestrictedIssueAccess({ issueId, identifier, leading }: {
  issueId: string;
  identifier: string;
  /**
   * Host-supplied way back, mirroring `IssueNotFound.leading`. A host that
   * handed its whole screen to this page (the inbox, on a phone) has no bar of
   * its own left, so the trip back has to live in here.
   */
  leading?: ReactNode;
}) {
  const { t } = useT("issues");
  const workspaceId = useWorkspaceId();
  const [role, setRole] = useState("viewer");
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const roles = useQuery({
    queryKey: ["task-permission-roles", workspaceId, "restricted"],
    queryFn: () => api.listTaskPermissionRoles(),
    enabled: !!workspaceId,
  });
  const requests = useQuery({
    queryKey: ["issue-access-requests", workspaceId, issueId, "mine"],
    queryFn: () => api.listIssueAccessRequests(issueId, true),
    enabled: !!workspaceId,
  });

  const submit = async () => {
    setSubmitting(true);
    try {
      await api.createIssueAccessRequest(issueId, {
        requested_role: role,
        reason: reason.trim() || undefined,
        idempotency_key: crypto.randomUUID(),
      });
      await requests.refetch();
      setReason("");
      toast.success(t(($) => $.detail.access_request_submitted));
    } catch { toast.error(t(($) => $.detail.access_request_failed)); }
    finally { setSubmitting(false); }
  };

  const cancel = async (requestId: string) => {
    try {
      await api.cancelIssueAccessRequest(issueId, requestId);
      await requests.refetch();
    } catch {
      toast.error(t(($) => $.detail.access_request_cancel_failed));
    }
  };

  const roleLabel = (roleKey: string) => {
    switch (roleKey) {
      case "viewer":
        return t(($) => $.detail.access_request_role_viewer);
      case "member":
        return t(($) => $.detail.access_request_role_editor);
      case "manager":
        return t(($) => $.detail.access_request_role_manager);
      default:
        return t(($) => $.detail.access_request_unknown_role);
    }
  };

  const statusLabel = (status: string) => {
    switch (status) {
      case "pending":
        return t(($) => $.detail.access_request_status_pending);
      case "approved":
        return t(($) => $.detail.access_request_status_approved);
      case "rejected":
        return t(($) => $.detail.access_request_status_rejected);
      case "cancelled":
        return t(($) => $.detail.access_request_status_cancelled);
      case "expired":
        return t(($) => $.detail.access_request_status_expired);
      default:
        return t(($) => $.detail.access_request_unknown_status);
    }
  };

  return (
    <div className="flex flex-1 min-h-0 flex-col">
      {leading && (
        <div className={cn("flex h-12 shrink-0 items-center gap-2 border-b", PAGE_GUTTER)}>{leading}</div>
      )}
      <main
        className="mx-auto flex min-h-[60vh] w-full max-w-xl flex-col justify-center gap-5 p-6"
        aria-labelledby="restricted-task-title"
      >
      <div>
        <p className="text-caption text-muted-foreground">{identifier}</p>
        <h1 id="restricted-task-title" className="text-title-lg font-semibold">
          {t(($) => $.detail.access_denied_title)}
        </h1>
        <p className="mt-2 text-body text-muted-foreground">
          {t(($) => $.detail.access_denied_description)}
        </p>
      </div>
      <div className="space-y-3 rounded-lg border p-4">
        <label className="block text-body font-medium" htmlFor="access-role">
          {t(($) => $.detail.requested_role)}
        </label>
        <Select
          items={(roles.data?.roles ?? []).map((item) => ({ value: item.key, label: item.name }))}
          value={role}
          onValueChange={(value) => setRole(value || "viewer")}
        >
          <SelectTrigger id="access-role" aria-label={t(($) => $.detail.requested_role)}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {roles.data?.roles.map((item) => (
              <SelectItem key={item.key} value={item.key}>
                {item.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <label className="block text-body font-medium" htmlFor="access-reason">
          {t(($) => $.detail.request_reason)}
        </label>
        <textarea
          id="access-reason"
          className="min-h-24 w-full rounded-md border bg-background p-2 text-body"
          maxLength={2000}
          value={reason}
          onChange={(event) => setReason(event.target.value)}
        />
        <Button onClick={() => void submit()} disabled={submitting || !role}>
          {submitting ? t(($) => $.detail.request_submitting) : t(($) => $.detail.request_access)}
        </Button>
      </div>
      {requests.data?.items.length ? (
        <section className="space-y-2">
          <h2 className="font-medium">{t(($) => $.detail.my_access_requests)}</h2>
          {requests.data.items.map((request) => (
            <div key={request.id} className="flex items-center gap-2 rounded-md border p-3">
              <span className="flex-1">
                {roleLabel(request.requested_role)} · {statusLabel(request.status)}
              </span>
              {request.status === "pending" ? (
                <Button variant="outline" size="sm" onClick={() => void cancel(request.id)}>
                  {t(($) => $.detail.cancel_request)}
                </Button>
              ) : null}
            </div>
          ))}
        </section>
      ) : null}
      </main>
    </div>
  );
}

/**
 * Resolve a task reference, then render the restricted surface for it.
 *
 * Two hosts can hold a task the reader may not view — the issue route (an
 * identifier from the URL) and the inbox (the UUID an access-request
 * notification points at) — and neither may report that as "task deleted".
 * The endpoint accepts either spelling and answers with the canonical
 * `{id, identifier}` pair, so the caller only passes whatever segment it has.
 *
 * 2026-09-20 coder(lq): 收件箱里被拒绝的任务不再误报“任务已删除”，与路由页共用同一套兜底。
 */
export function RestrictedIssueAccessFallback({
  targetId,
  loading = null,
  notFound,
  leading,
}: {
  /** UUID or human identifier of the task the reader was denied. */
  targetId: string;
  /** Frame to hold while the task reference resolves. */
  loading?: ReactNode;
  /** Shown only when the task itself is gone (404); never for a denial. */
  notFound: ReactNode;
  /** Host-supplied way back, forwarded to the restricted page. */
  leading?: ReactNode;
}) {
  const { t } = useT("issues");
  const workspaceId = useWorkspaceId();
  const target = useQuery({
    queryKey: ["issue-access-request-target", workspaceId, targetId],
    queryFn: () => api.getIssueAccessRequestTarget(targetId),
    // Retries are off on purpose: the host keeps rendering this while the task
    // stays unresolved, so a retry policy here turns one denial into a loop.
    retry: false,
  });

  if (target.isLoading) return <>{loading}</>;
  if (target.data) {
    return <RestrictedIssueAccess issueId={target.data.id} identifier={target.data.identifier} leading={leading} />;
  }
  // Only a 404 means the task is really gone. Any other failure is an
  // infrastructure problem, and saying "deleted" there would be a lie.
  if (target.isError && (!(target.error instanceof ApiError) || target.error.status !== 404)) {
    return (
      <div className="flex flex-1 min-h-0 flex-col items-center justify-center gap-3 text-body text-muted-foreground">
        <p>{t(($) => $.detail.access_check_failed)}</p>
        <Button variant="outline" size="sm" onClick={() => void target.refetch()}>
          {t(($) => $.detail.try_again)}
        </Button>
      </div>
    );
  }
  return <>{notFound}</>;
}
