"use client";

/* eslint-disable i18next/no-literal-string -- Task permissions use canonical policy codes in API payloads and previews. */
/* eslint-disable no-restricted-syntax -- This isolated administration surface ships its fallback copy with the feature. */

import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { Copy, ShieldCheck, UserMinus, Users } from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@multica/core/api";
import { useWorkspaceId } from "@multica/core/hooks";
import { memberListOptions } from "@multica/core/workspace/queries";
import type { IssueAccessControlDerivedGrant, IssueAccessControlGrant, IssueAccessRequest, TaskAccessMode } from "@multica/core/types";
import { Button } from "@multica/ui/components/ui/button";
import { Checkbox } from "@multica/ui/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@multica/ui/components/ui/dialog";
import { Input } from "@multica/ui/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@multica/ui/components/ui/select";
import { Tooltip, TooltipContent, TooltipTrigger } from "@multica/ui/components/ui/tooltip";
import { cn } from "@multica/ui/lib/utils";
import { toast } from "sonner";
import { useT } from "../../i18n";
import { ProjectMemberMultiSelect } from "../../projects/components/project-member-multi-select";
import { ProjectPermissionOrganizationTreeSelect } from "../../projects/components/project-permission-organization-tree-select";

type IssueAccessGrantsDialogProps = {
  issueId: string;
  projectId?: string | null;
  defaultOpen?: boolean;
  /**
   * Access request the host wants this dialog to land on. Set when a task
   * access notification is opened from the inbox: the request is centred in
   * the pending list and can no longer be approved/rejected once it left the
   * pending state.
   */
  focusRequestId?: string | null;
  /**
   * Bumped by the host to replay the landing when the same notification is
   * clicked again. A fresh mount replays it by itself; this token is for the
   * click that swaps the focused request without remounting the dialog.
   */
  focusRequestToken?: number;
};

// Where a permission comes from is a layer before it is a source: this task's own
// facts (creator, assignee, a mention), an inherited project grant, an inherited
// parent-task grant, or the workspace-owner bypass. The source names say which,
// but a reader comparing rows should not have to know that "项目部门授权" is a
// project grant while "任务部门授权" is not.
type AccessLayer = "task" | "project" | "parent" | "workspace";

/** One rendered row of "My access": a permission, where it comes from, and what granted it there. */
type AccessSummaryRow = { key: string; permission: string; layer: AccessLayer | null; sources: string[] };


const ACCESS_SOURCE_LAYER: Record<string, AccessLayer> = {
  creator: "task",
  assignee: "task",
  delegated_originator: "task",
  mention: "task",
  issue_direct: "task",
  issue_organization: "task",
  issue_everyone: "task",
  access_request: "task",
  project_direct: "project",
  project_organization: "project",
  project_everyone: "project",
  parent_issue: "parent",
  workspace_owner_bypass: "workspace",
};

function sameTaskGrant(left: IssueAccessControlGrant, right: IssueAccessControlGrant) {
  return left.subject_type === right.subject_type && left.subject_id === right.subject_id && left.role === right.role;
}

function mergeTaskGrants(current: IssueAccessControlGrant[], additions: IssueAccessControlGrant[]) {
  if (!additions.length) return current;
  return [
    ...current.filter((item) => !additions.some((candidate) => sameTaskGrant(candidate, item))),
    ...additions,
  ];
}

/** Task ACL editor plus a read-only resolver explanation for the current user. */
export function IssueAccessGrantsDialog({ issueId, projectId, defaultOpen = false, focusRequestId = null, focusRequestToken }: IssueAccessGrantsDialogProps) {
  const { t } = useT("projects");
  const workspaceId = useWorkspaceId();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(defaultOpen);
  const [selectedUserIds, setSelectedUserIds] = useState<ReadonlySet<string>>(new Set());
  const [selectedOrganizationIds, setSelectedOrganizationIds] = useState<ReadonlySet<string>>(new Set());
  const [selectedEveryone, setSelectedEveryone] = useState(false);
  const [role, setRole] = useState("member");
  const [expiresAt, setExpiresAt] = useState("");
  const [mode, setMode] = useState<TaskAccessMode>("inherit");
  const [grants, setGrants] = useState<IssueAccessControlGrant[]>([]);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [shareUrl, setShareUrl] = useState("");
  const [grantsOpen, setGrantsOpen] = useState(false);
  const [focusedRequestId, setFocusedRequestId] = useState<string | null>(null);
  const [focusRingNonce, setFocusRingNonce] = useState(0);
  const focusRowRef = useRef<HTMLDivElement | null>(null);
  // Tracks the last landing we already honoured. A plain token ref would skip
  // the very first render when the host passes no token, so the key carries
  // both the request id and the token.
  const lastFocusKeyRef = useRef<string | undefined>(undefined);

  const controlQuery = useQuery({ queryKey: ["issue-access-control", workspaceId, issueId], queryFn: () => api.getIssueAccessControl(issueId), enabled: open, retry: false });
  const effectiveQuery = useQuery({ queryKey: ["issue-effective-access", workspaceId, issueId], queryFn: () => api.getIssueEffectiveAccess(issueId), enabled: open, retry: false });
  const rolesQuery = useQuery({ queryKey: ["task-permission-roles", workspaceId], queryFn: () => api.listTaskPermissionRoles(), enabled: open && !!workspaceId });
  const directoryQuery = useQuery({ queryKey: ["project-permission-organizations", workspaceId], queryFn: () => api.listProjectAuthorizationOrganizations(workspaceId), enabled: open && !!workspaceId, staleTime: 60_000 });
  const membersQuery = useQuery({ ...memberListOptions(workspaceId), enabled: open && !!workspaceId });
  const requestsQuery = useQuery({ queryKey: ["issue-access-requests", workspaceId, issueId], queryFn: () => api.listIssueAccessRequests(issueId), enabled: open && !!controlQuery.data, retry: false });

  useEffect(() => {
    if (!controlQuery.data || dirty) return;
    setMode(controlQuery.data.project_access_mode);
    setGrants(controlQuery.data.grants);
  }, [controlQuery.data, dirty]);

  useEffect(() => {
    if (!open || typeof window === "undefined") return;
    setShareUrl(window.location.href);
  }, [open]);

  // 2026-09-20 coder(lq): 从收件箱点击“任务权限申请”通知时，直接打开本弹窗并定位到该申请，
  // 不再要求审批人自己在一长串申请里找。首次挂载与 token 变化各触发一次。
  useEffect(() => {
    if (!focusRequestId) return;
    const focusKey = `${focusRequestId}:${focusRequestToken ?? "initial"}`;
    if (lastFocusKeyRef.current === focusKey) return;
    lastFocusKeyRef.current = focusKey;
    setOpen(true);
    setFocusRingNonce((current) => current + 1);
  }, [focusRequestId, focusRequestToken]);

  // Centre the focused row once the request list has it, and ring it briefly
  // so the reader sees which request the notification pointed at. The ring is
  // transient on purpose: it marks the landing, it is not a second state.
  useEffect(() => {
    if (!open || !focusRequestId) {
      setFocusedRequestId(null);
      return;
    }
    if (!requestsQuery.data?.items.some((item) => item.id === focusRequestId)) return;
    setFocusedRequestId(focusRequestId);
    focusRowRef.current?.scrollIntoView?.({ block: "center" });
    const timer = setTimeout(() => setFocusedRequestId(null), 2400);
    return () => clearTimeout(timer);
  }, [open, focusRequestId, focusRingNonce, requestsQuery.data]);

  const members = useMemo(() => membersQuery.data ?? [], [membersQuery.data]);
  const organizations = useMemo(() => directoryQuery.data?.organizations ?? [], [directoryQuery.data?.organizations]);
  const memberByUser = useMemo(() => new Map(members.map((member) => [member.user_id, member])), [members]);
  const organizationById = useMemo(() => new Map(organizations.map((organization) => [organization.id, organization])), [organizations]);
  const availableRoles = rolesQuery.data?.roles ?? [];
  const canManage = !!controlQuery.data;
  const effectivePermissions = useMemo(() => new Set(effectiveQuery.data?.permissions ?? []), [effectiveQuery.data?.permissions]);
  const permissionLabel = (permission: string) => {
    switch (permission) {
      case "project.view": return t(($) => $.permissions.view_task);
      case "project.edit": return t(($) => $.permissions.edit_task);
      case "project.issue.child.create": return t(($) => $.permissions.create_related_tasks);
      case "project.issue.comment": return t(($) => $.permissions.comment_task);
      case "project.issue.manage": return t(($) => $.permissions.manage_task);
      case "project.issue.archive": return t(($) => $.permissions.archive_task);
      case "project.agent.use": return t(($) => $.permissions.use_agent);
      default: return permission;
    }
  };
  const taskRoleLabel = (roleKey: string, fallback?: string) => {
    switch (roleKey) {
      case "viewer": return t(($) => $.permissions.task_access_level_viewer);
      case "member": return t(($) => $.permissions.task_access_level_editor);
      case "manager": return t(($) => $.permissions.task_access_level_manager);
      default: return fallback || roleKey;
    }
  };
  const requestStatusLabel = (status: string) => {
    switch (status) {
      case "pending": return t(($) => $.permissions.task_request_status_pending);
      case "approved": return t(($) => $.permissions.task_request_status_approved);
      case "rejected": return t(($) => $.permissions.task_request_status_rejected);
      case "cancelled": return t(($) => $.permissions.task_request_status_cancelled);
      case "expired": return t(($) => $.permissions.task_request_status_expired);
      default: return status;
    }
  };
  const accessSummary = [
    { permission: "project.view", label: t(($) => $.permissions.view_task) },
    { permission: "project.edit", label: t(($) => $.permissions.edit_task) },
    { permission: "project.issue.manage", label: t(($) => $.permissions.manage_task) },
  ];
  // 2026-09-20 coder(lq): Only a 403 means "you may not manage this task". Any
  // other failure — a 5xx, a timeout, an offline client — used to render the very
  // same "only a manager can change sharing" panel, so a broken request was
  // indistinguishable from a permission decision and pointed the reader at the
  // wrong problem.
  const controlFailedToLoad = controlQuery.isError
    && !(controlQuery.error instanceof ApiError && controlQuery.error.status === 403);
  const readonlyReason = controlFailedToLoad
    ? t(($) => $.permissions.task_permissions_load_failed)
    : t(($) => $.permissions.task_permissions_readonly_manage);
  const taskPolicyDescription = projectId
    ? t(($) => $.permissions.task_policy_project_task, { version: controlQuery.data?.policy_version ?? "—" })
    : t(($) => $.permissions.task_policy_projectless_task, { version: controlQuery.data?.policy_version ?? "—" });
  const selectedCount = selectedEveryone ? 1 : selectedUserIds.size + selectedOrganizationIds.size;
  const pendingGrants = useMemo(() => {
    const expiry = expiresAt ? { expires_at: new Date(expiresAt).toISOString() } : {};
    // 2026-09-16 coder(lq): Preserve picker selections while "everyone" is on,
    // but save only the workspace-wide grant to avoid redundant ACL rows.
    if (selectedEveryone) return [{ subject_type: "everyone", role, scope: "task", ...expiry } satisfies IssueAccessControlGrant];
    return [
      ...[...selectedUserIds].map((subjectId): IssueAccessControlGrant => ({ subject_type: "user", subject_id: subjectId, role, scope: "task", ...expiry })),
      ...[...selectedOrganizationIds].map((subjectId): IssueAccessControlGrant => ({ subject_type: "organization", subject_id: subjectId, role, scope: "task", ...expiry })),
    ];
  }, [expiresAt, role, selectedEveryone, selectedOrganizationIds, selectedUserIds]);
  const grantsForSave = useMemo(() => mergeTaskGrants(grants, pendingGrants), [grants, pendingGrants]);
  const subjectName = (grant: IssueAccessControlGrant) => grant.subject_type === "everyone"
    ? t(($) => $.permissions.current_workspace_everyone)
    : grant.subject_type === "user"
      ? memberByUser.get(grant.subject_id || "")?.name || memberByUser.get(grant.subject_id || "")?.email || grant.subject_id || "—"
      : organizationById.get(grant.subject_id || "")?.name || grant.subject_id || "—";
  // 2026-09-20 coder(lq): Mentions, assignment and creation grant real task access
  // without ever appearing in the manual ACL, so a dialog that only counted manual
  // rows told a manager "0 granted" while a mentioned teammate could open the task.
  // These are shown read-only: the source that granted them is the only thing that
  // can take them away.
  const derivedGrants = controlQuery.data?.derived_grants ?? [];
  // 2026-09-20 coder(lq): One vocabulary for "why does this person have access",
  // shared by the table's source column and the reader's own permission line. The
  // resolver names its sources (creator, mention, project_direct, …) and a stored
  // grant carries the narrower storage token (organization, everyone, migration),
  // so both spellings land on the same label. These are the keys the
  // effective-access dashboard used before it was removed.
  const taskSourceLabel = (source: string) => {
    switch (source) {
      case "creator": return t(($) => $.permissions.task_source_creator);
      case "assignee": return t(($) => $.permissions.task_source_assignee);
      case "mention": return t(($) => $.permissions.task_source_mention);
      case "delegated_originator": return t(($) => $.permissions.task_source_delegated_originator);
      case "workspace_owner_bypass": return t(($) => $.permissions.task_source_workspace_owner_bypass);
      case "issue_direct": return t(($) => $.permissions.task_source_issue_direct);
      case "organization":
      case "issue_organization": return t(($) => $.permissions.task_source_issue_organization);
      case "everyone":
      case "issue_everyone": return t(($) => $.permissions.task_source_issue_everyone);
      case "project_direct": return t(($) => $.permissions.task_source_project_direct);
      case "project_organization": return t(($) => $.permissions.task_source_project_organization);
      case "project_everyone": return t(($) => $.permissions.task_source_project_everyone);
      case "parent_issue": return t(($) => $.permissions.task_source_parent_issue);
      case "access_request": return t(($) => $.permissions.task_source_access_request);
      case "migration": return t(($) => $.permissions.task_source_migration);
      default: return source;
    }
  };
  const derivedSourceLabel = (grant: IssueAccessControlDerivedGrant) => taskSourceLabel(grant.reason || grant.source);
  // 2026-09-21 coder(lq): Name the source of EACH permission. One merged line
  // answered "why do I have access", but not "why do I have THIS permission",
  // which is the question that matters once two of them arrive from different
  // places — the task's creator, a mention, a project grant.
  const accessLayerLabel = (layer: AccessLayer) => {
    switch (layer) {
      case "project": return t(($) => $.permissions.access_layer_project);
      case "parent": return t(($) => $.permissions.access_layer_parent);
      case "workspace": return t(($) => $.permissions.access_layer_workspace);
      default: return t(($) => $.permissions.access_layer_task);
    }
  };
  // Grouped by layer, because "why do I have access" is answered one layer at a
  // time: this task makes you its creator, the project grants you the rest. Within
  // a layer the permission leads and what granted it follows.
  const myAccess = (() => {
    const order: AccessLayer[] = ["task", "project", "parent", "workspace"];
    const byLayer = new Map<AccessLayer, Map<string, AccessSummaryRow>>();
    for (const item of accessSummary) {
      if (!effectivePermissions.has(item.permission)) continue;
      const seen = new Set<string>();
      for (const source of effectiveQuery.data?.sources ?? []) {
        if (source.permission !== item.permission || seen.has(source.source)) continue;
        seen.add(source.source);
        // Inheriting from a parent task is that task's own access, relabelled, so
        // the kind of access it handed down is only visible underneath.
        const label = source.source === "parent_issue" && source.underlying_source
          ? `${taskSourceLabel(source.source)}（${taskSourceLabel(source.underlying_source)}）`
          : taskSourceLabel(source.source);
        const layer = ACCESS_SOURCE_LAYER[source.source] ?? "task";
        const rows = byLayer.get(layer) ?? new Map<string, AccessSummaryRow>();
        const row = rows.get(item.permission) ?? { key: item.permission, permission: item.label, layer, sources: [] };
        row.sources.push(label);
        rows.set(item.permission, row);
        byLayer.set(layer, rows);
      }
    }
    return order
      .filter((layer) => byLayer.has(layer))
      .map((layer) => ({ layer, rows: [...byLayer.get(layer)!] }));
  })();
  const derivedSubjectName = (grant: IssueAccessControlDerivedGrant) => grant.subject_type === "everyone"
    ? t(($) => $.permissions.current_workspace_everyone)
    : grant.subject_type === "user"
      ? memberByUser.get(grant.subject_id || "")?.name || memberByUser.get(grant.subject_id || "")?.email || grant.subject_id || "—"
      : organizationById.get(grant.subject_id || "")?.name || grant.subject_id || "—";
  const resetPicker = () => { setSelectedUserIds(new Set()); setSelectedOrganizationIds(new Set()); setSelectedEveryone(false); setExpiresAt(""); };

  // 2026-09-20 coder(lq): 定位场景下，已处理的申请也要跟着通知一起出现在列表里，
  // 否则审批人点开通知只能看到空白或别人的申请，无法确认这条通知的结果。
  const pendingRequests = (requestsQuery.data?.items ?? []).filter((item) => item.status === "pending");
  const focusedRequest = focusRequestId
    ? requestsQuery.data?.items.find((item) => item.id === focusRequestId)
    : undefined;
  const visibleRequests = focusedRequest && focusedRequest.status !== "pending"
    ? [...pendingRequests, focusedRequest]
    : pendingRequests;

  const copyShareLink = async () => {
    if (!shareUrl) return;
    try {
      await navigator.clipboard.writeText(shareUrl);
      toast.success(t(($) => $.permissions.task_link_copied));
    } catch {
      toast.error(t(($) => $.permissions.task_link_copy_failed));
    }
  };

  // 2026-09-21 coder(lq): Every change to the manual ACL now persists where it is
  // made. Removing a row used to only mark the dialog dirty, so deleting it in the
  // list and closing left the grant untouched: the list says it manages manual
  // access, while the write lived in the other window.
  const persistGrants = async (nextGrants: IssueAccessControlGrant[], successMessage: string) => {
    if (!controlQuery.data) return;
    setSaving(true);
    try {
      const update = { expected_version: controlQuery.data.policy_version, project_access_mode: mode, grants: nextGrants };
      await api.updateIssueAccessControl(issueId, update);
      setGrants(nextGrants);
      resetPicker();
      setDirty(false);
      await Promise.all([queryClient.invalidateQueries({ queryKey: ["issue-access-control", workspaceId, issueId] }), queryClient.invalidateQueries({ queryKey: ["issue-effective-access", workspaceId, issueId] })]);
      toast.success(successMessage);
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) { setDirty(false); await controlQuery.refetch(); toast.error(t(($) => $.permissions.task_changed_reload)); }
      else toast.error(t(($) => $.permissions.task_save_failed));
    } finally { setSaving(false); }
  };

  const save = async () => {
    if (!controlQuery.data) return;
    await persistGrants(grantsForSave, t(($) => $.permissions.task_update_success));
  };

  const removeManualGrant = async (grant: IssueAccessControlGrant) => {
    await persistGrants(
      grantsForSave.filter((item) => !sameTaskGrant(item, grant)),
      t(($) => $.permissions.task_update_success),
    );
  };

  // A mention is not a manual grant, so withdrawing it is its own call: the server
  // records the decision, which is what keeps the next reconciliation from handing
  // the access straight back.
  const revokeMentionGrant = async (grant: IssueAccessControlDerivedGrant) => {
    if (!grant.subject_id) return;
    setSaving(true);
    try {
      const state = await api.revokeIssueMentionAccess(issueId, grant.subject_id);
      queryClient.setQueryData(["issue-access-control", workspaceId, issueId], state);
      await Promise.all([queryClient.invalidateQueries({ queryKey: ["issue-access-control", workspaceId, issueId] }), queryClient.invalidateQueries({ queryKey: ["issue-effective-access", workspaceId, issueId] })]);
      toast.success(t(($) => $.permissions.task_mention_revoked));
    } catch {
      toast.error(t(($) => $.permissions.task_mention_revoke_failed));
    } finally { setSaving(false); }
  };

  const review = async (requestId: string, action: "approve" | "reject") => {
    const request = requestsQuery.data?.items.find((item) => item.id === requestId);
    try {
      const reviewed = await api.reviewIssueAccessRequest(issueId, requestId, { action });
      queryClient.setQueryData<{ items: IssueAccessRequest[] }>(["issue-access-requests", workspaceId, issueId], (current) => ({
        items: (current?.items ?? []).map((item) => item.id === requestId ? { ...item, ...reviewed, status: reviewed.status } : item),
      }));
      if (action === "approve" && request) {
        const approvedGrant: IssueAccessControlGrant = {
          subject_type: "user",
          subject_id: request.requester_user_id,
          role: request.requested_role,
          scope: "task",
          ...(request.expires_at ? { expires_at: request.expires_at } : {}),
        };
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: ["issue-access-control", workspaceId, issueId] }),
          queryClient.invalidateQueries({ queryKey: ["issue-effective-access", workspaceId, issueId] }),
        ]);
        setGrants((current) => [
          ...current.filter((item) => !(item.subject_type === approvedGrant.subject_type && item.subject_id === approvedGrant.subject_id && item.role === approvedGrant.role)),
          approvedGrant,
        ]);
      }
      await requestsQuery.refetch();
      toast.success(action === "approve" ? t(($) => $.permissions.task_request_approved) : t(($) => $.permissions.task_request_rejected));
    }
    catch { toast.error(t(($) => $.permissions.task_request_review_failed)); }
  };

  return <>
    <Tooltip>
      <TooltipTrigger
        render={(
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1.5 px-2 text-caption"
            onClick={() => setOpen(true)}
            aria-label={t(($) => $.permissions.task_permissions_action)}
          >
            <ShieldCheck className="size-3.5" />
            <span>{t(($) => $.permissions.task_permissions_action)}</span>
          </Button>
        )}
      />
      <TooltipContent side="top">{t(($) => $.permissions.task_permissions_action)}</TooltipContent>
    </Tooltip>
    <Dialog open={open} onOpenChange={(next) => { setOpen(next); if (!next) { setDirty(false); setGrantsOpen(false); } }}><DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-4xl">
      <DialogHeader><DialogTitle>{t(($) => $.permissions.task_permissions_title)}</DialogTitle><DialogDescription>{t(($) => $.permissions.task_permissions_description)}</DialogDescription></DialogHeader>
      <section className="space-y-2">
        <h3 className="font-medium">{t(($) => $.permissions.task_link)}</h3>
        <div className="flex flex-col gap-2 sm:flex-row">
          <Input readOnly value={shareUrl} aria-label={t(($) => $.permissions.task_link)} className="font-mono text-caption" />
          <Button variant="outline" onClick={() => void copyShareLink()} className="sm:w-32"><Copy className="size-4" />{t(($) => $.permissions.copy_task_link)}</Button>
        </div>
      </section>
      {canManage ? <>
        <section className="space-y-3 border-t pt-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="font-medium">{t(($) => $.permissions.add_task_access)}</h3>
              <p className="text-caption text-muted-foreground">{t(($) => $.permissions.add_task_access_description)}</p>
            </div>
            <Button variant="outline" size="sm" onClick={() => setGrantsOpen(true)}><Users className="size-4" />{t(($) => $.permissions.direct_access_count, { count: grants.length + derivedGrants.length })}</Button>
          </div>
          <div className="rounded-lg border bg-muted/10 p-3">
            <div className="space-y-3">
              <div className="text-caption font-medium text-muted-foreground">{t(($) => $.permissions.task_permission_object)}</div>
              <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
                <div className="space-y-1.5">
                  <div className="text-caption text-muted-foreground">{t(($) => $.permissions.user)}</div>
                  <div className="min-w-0"><ProjectMemberMultiSelect members={members} selectedIds={selectedUserIds} onToggle={(id) => setSelectedUserIds((current) => { const next = new Set(current); if (next.has(id)) next.delete(id); else next.add(id); return next; })} onSelectAll={(ids) => setSelectedUserIds(new Set(ids))} onClear={() => setSelectedUserIds(new Set())} placeholder={t(($) => $.permissions.task_permission_select_people)} selectedLabel={t(($) => $.permissions.task_permission_people_selected)} selectAllLabel={t(($) => $.permissions.select_all)} clearLabel={t(($) => $.permissions.clear_selection)} noResultsLabel={t(($) => $.permissions.no_results)} loadingLabel={t(($) => $.permissions.loading)} errorLabel={t(($) => $.permissions.workspace_members_failed)} removeLabel={t(($) => $.permissions.task_permission_remove_selected)} isLoading={membersQuery.isLoading} hasError={membersQuery.isError} disabled={selectedEveryone} ariaLabel={t(($) => $.permissions.task_permission_select_people)} /></div>
                </div>
                <div className="space-y-1.5">
                  <div className="text-caption text-muted-foreground">{t(($) => $.permissions.organization)}</div>
                  <div className="min-w-0"><ProjectPermissionOrganizationTreeSelect organizations={organizations} selectedIds={selectedOrganizationIds} onToggle={(id) => setSelectedOrganizationIds((current) => { const next = new Set(current); if (next.has(id)) next.delete(id); else next.add(id); return next; })} onSelectAll={(ids) => setSelectedOrganizationIds(new Set(ids))} onClear={() => setSelectedOrganizationIds(new Set())} placeholder={t(($) => $.permissions.task_permission_select_departments)} selectedLabel={t(($) => $.permissions.task_permission_organizations_selected)} selectAllLabel={t(($) => $.permissions.select_all)} clearLabel={t(($) => $.permissions.clear_selection)} noResultsLabel={t(($) => $.permissions.no_organizations)} loadingLabel={t(($) => $.permissions.loading)} errorLabel={t(($) => $.permissions.no_organizations)} removeLabel={t(($) => $.permissions.task_permission_remove_selected)} isLoading={directoryQuery.isLoading} hasError={directoryQuery.isError} disabled={selectedEveryone} ariaLabel={t(($) => $.permissions.task_permission_select_departments)} /></div>
                </div>
                <label className="flex min-h-9 cursor-pointer items-center gap-2 self-end rounded-md border bg-background px-3 py-2 md:whitespace-nowrap">
                  <Checkbox checked={selectedEveryone} onCheckedChange={(checked) => setSelectedEveryone(checked === true)} aria-label={t(($) => $.permissions.everyone)} />
                  <span className="font-medium">{t(($) => $.permissions.everyone)}</span>
                  <span className="text-caption text-muted-foreground">{t(($) => $.permissions.current_workspace_everyone)}</span>
                </label>
              </div>
              <div className="grid gap-3 border-t pt-3 md:grid-cols-[10rem_18rem]">
                <div className="space-y-1.5">
                  <div className="text-caption font-medium text-muted-foreground">{t(($) => $.permissions.task_grant_settings)}</div>
                  <Select modal={false} items={availableRoles.map((item) => ({ value: item.key, label: taskRoleLabel(item.key, item.name) }))} value={role} onValueChange={(value) => setRole(value || "member")}><SelectTrigger aria-label={t(($) => $.permissions.task_role)}><SelectValue /></SelectTrigger><SelectContent>{availableRoles.map((item) => <SelectItem key={item.key} value={item.key}>{taskRoleLabel(item.key, item.name)}</SelectItem>)}</SelectContent></Select>
                </div>
                <div className="space-y-1.5">
                  <div className="text-caption font-medium text-muted-foreground">{t(($) => $.permissions.task_grant_expiry)}</div>
                  <Input type="datetime-local" aria-label={t(($) => $.permissions.task_grant_expiry)} value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
                </div>
              </div>
            </div>
          </div>
        </section>
        <section className="space-y-3 border-t pt-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="font-medium">{t(($) => $.permissions.task_policy)}</h3>
              <p className="text-caption text-muted-foreground">{taskPolicyDescription}</p>
            </div>
            <Select modal={false} items={[{ value: "inherit", label: t(($) => $.permissions.task_policy_inherit) }, { value: "restricted", label: t(($) => $.permissions.task_policy_restricted) }]} value={mode} onValueChange={(value) => { setMode(value as TaskAccessMode); setDirty(true); }}><SelectTrigger className="w-48" aria-label={t(($) => $.permissions.task_project_access_mode)}><SelectValue /></SelectTrigger><SelectContent><SelectItem value="inherit">{t(($) => $.permissions.task_policy_inherit)}</SelectItem><SelectItem value="restricted">{t(($) => $.permissions.task_policy_restricted)}</SelectItem></SelectContent></Select>
          </div>
        </section>
        {visibleRequests.length ? (
          <section className="space-y-2 border-t pt-4">
            <h3 className="font-medium">
              {pendingRequests.length
                ? t(($) => $.permissions.task_pending_requests)
                : t(($) => $.permissions.task_request_section_title)}
            </h3>
            {visibleRequests.map((request) => {
              const isPending = request.status === "pending";
              const isFocused = request.id === focusRequestId;
              return (
                <div
                  key={request.id}
                  ref={isFocused ? focusRowRef : undefined}
                  data-request-id={request.id}
                  className={cn(
                    "flex flex-wrap items-center gap-2 rounded-md border p-2",
                    focusedRequestId === request.id && "border-primary ring-1 ring-primary",
                  )}
                >
                  <code>{request.requester_user_id}</code>
                  <span>{t(($) => $.permissions.task_request_role, { role: taskRoleLabel(request.requested_role) })}</span>
                  <span className="flex-1 text-muted-foreground">{request.reason}</span>
                  {isFocused && isPending ? (
                    <span className="text-caption text-muted-foreground">
                      {t(($) => $.permissions.task_request_focus_hint)}
                    </span>
                  ) : null}
                  {isPending ? (
                    <>
                      <Button size="sm" variant="brandSubtle" onClick={() => void review(request.id, "approve")}>{t(($) => $.permissions.task_request_approve)}</Button>
                      <Button size="sm" variant="outline" onClick={() => void review(request.id, "reject")}>{t(($) => $.permissions.task_request_reject)}</Button>
                    </>
                  ) : (
                    // A notification outlives the decision it announces: show what
                    // was decided instead of an empty list, and never re-offer an
                    // approve/reject pair for a request that already left pending.
                    <span className="text-caption font-medium">
                      {t(($) => $.permissions.task_request_already_handled, { status: requestStatusLabel(request.status) })}
                    </span>
                  )}
                </div>
              );
            })}
          </section>
        ) : null}
      </> : <div className="flex flex-wrap items-center gap-2 rounded-md border p-3 text-caption text-muted-foreground"><span>{readonlyReason}</span>{controlFailedToLoad ? <Button variant="outline" size="sm" onClick={() => void controlQuery.refetch()}>{t(($) => $.permissions.retry)}</Button> : null}</div>}
      <section className="border-t pt-3">
        <div className="flex flex-wrap items-start gap-x-3 gap-y-1 text-caption text-muted-foreground">
          <span className="font-medium text-foreground">{t(($) => $.permissions.task_access_summary_title)}</span>
          {myAccess.length ? (
            /* Aligned columns: a run of "permission 来源: …" sentences reads as one
               paragraph once the sources are long, and the reader is comparing
               rows, not reading prose. */
            <div className="space-y-2">
              {myAccess.map((group) => (
                <div key={group.layer}>
                  <div className="text-caption font-medium text-muted-foreground">{accessLayerLabel(group.layer)}</div>
                  <dl className="grid grid-cols-[auto_1fr] items-baseline gap-x-4 gap-y-1">
                    {group.rows.map(([permission, row]) => (
                      <Fragment key={permission}>
                        <dt className="whitespace-nowrap text-body text-foreground">{row.permission}</dt>
                        <dd className="text-caption text-muted-foreground">{row.sources.join("、")}</dd>
                      </Fragment>
                    ))}
                  </dl>
                </div>
              ))}
            </div>
          ) : (
            <span>{t(($) => $.permissions.task_access_summary_none)}</span>
          )}
        </div>
      </section>
      <DialogFooter><Button variant="outline" onClick={() => setOpen(false)}>{t(($) => $.permissions.close)}</Button>{canManage ? <Button variant="brand" onClick={() => void save()} disabled={(!dirty && selectedCount === 0) || saving}>{saving ? t(($) => $.permissions.task_saving) : t(($) => $.permissions.task_save)}</Button> : null}</DialogFooter>
    </DialogContent></Dialog>
    <Dialog open={grantsOpen} onOpenChange={setGrantsOpen}><DialogContent className="max-h-[80vh] overflow-y-auto sm:max-w-4xl">
      <DialogHeader><DialogTitle>{t(($) => $.permissions.direct_access)}</DialogTitle><DialogDescription>{t(($) => $.permissions.existing_task_access_description)}</DialogDescription></DialogHeader>
      {/* 2026-09-20 coder(lq): Five data columns need a fixed layout. Auto layout
          let the permission list — seven labels for an Owner — claim the width it
          wanted, which pushed the other columns into wrapping their own headers
          ("权限级/别", "过期/间"). The permission column is now capped and wraps
          inside its cell instead, so every column reads on one line. */}
      <div className="overflow-x-auto rounded-lg border"><table className="w-full min-w-[680px] table-fixed text-body"><thead className="bg-muted/40 text-left text-caption text-muted-foreground"><tr><th className="w-[24%] px-3 py-2">{t(($) => $.permissions.authorization_subject)}</th><th className="px-3 py-2">{t(($) => $.permissions.task_role)}</th><th className="w-[28%] px-3 py-2">{t(($) => $.permissions.task_exact_permissions)}</th><th className="px-3 py-2">{t(($) => $.permissions.access_source_column)}</th><th className="w-[16%] px-3 py-2">{t(($) => $.permissions.task_expires)}</th><th className="w-12" /></tr></thead><tbody>
        {grants.map((grant, index) => {
          const definition = availableRoles.find((item) => item.key === grant.role);
          return <tr key={`${grant.subject_type}-${grant.subject_id}-${grant.role}-${index}`} className="border-t" data-testid="manual-access-row"><td className="px-3 py-2 align-top break-words">{subjectName(grant)}</td><td className="px-3 py-2 align-top">{taskRoleLabel(grant.role, definition?.name)}</td><td className="px-3 py-2 align-top text-caption text-muted-foreground break-words">{definition?.permissions.map(permissionLabel).join(", ") || "—"}</td><td className="px-3 py-2 align-top text-caption text-muted-foreground break-words">{t(($) => $.permissions.access_source_manual)}</td><td className="px-3 py-2 align-top whitespace-nowrap">{grant.expires_at ? new Date(grant.expires_at).toLocaleString() : t(($) => $.permissions.task_diagnostic_never)}</td><td className="align-top"><Button variant="ghost" size="icon-sm" aria-label={`${t(($) => $.permissions.remove_task_access_aria)} ${subjectName(grant)}`} onClick={() => void removeManualGrant(grant)} disabled={saving}><UserMinus className="size-3.5" /></Button></td></tr>;
        })}
        {derivedGrants.map((grant, index) => {
          const definition = availableRoles.find((item) => item.key === grant.role);
          return <tr key={`derived-${grant.source}-${grant.subject_type}-${grant.subject_id}-${grant.role}-${index}`} className="border-t bg-muted/20" data-testid="derived-access-row"><td className="px-3 py-2 align-top break-words">{derivedSubjectName(grant)}</td><td className="px-3 py-2 align-top">{taskRoleLabel(grant.role, definition?.name)}</td><td className="px-3 py-2 align-top text-caption text-muted-foreground break-words">{definition?.permissions.map(permissionLabel).join(", ") || "—"}</td><td className="px-3 py-2 align-top text-caption text-muted-foreground break-words">{derivedSourceLabel(grant)}</td><td className="px-3 py-2 align-top text-muted-foreground">—</td><td className="align-top">{grant.reason === "mention" && grant.subject_id ? <Button variant="ghost" size="icon-sm" disabled={saving} aria-label={`${t(($) => $.permissions.remove_task_access_aria)} ${derivedSubjectName(grant)}`} onClick={() => void revokeMentionGrant(grant)}><UserMinus className="size-3.5" /></Button> : null}</td></tr>;
        })}
        {!grants.length && !derivedGrants.length ? <tr><td colSpan={6} className="px-3 py-6 text-center text-muted-foreground">{t(($) => $.permissions.no_direct_access)}</td></tr> : null}
      </tbody></table></div>
      {derivedGrants.length ? <p className="text-caption text-muted-foreground">{t(($) => $.permissions.derived_access_note)}</p> : null}
      <DialogFooter><Button variant="outline" onClick={() => setGrantsOpen(false)}>{t(($) => $.permissions.close)}</Button></DialogFooter>
    </DialogContent></Dialog>
  </>;
}
