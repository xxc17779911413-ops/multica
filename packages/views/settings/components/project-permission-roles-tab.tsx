"use client";

import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Info, Plus, Trash2 } from "lucide-react";
import { api } from "@multica/core/api";
import { useWorkspaceId } from "@multica/core/hooks";
import { memberListOptions } from "@multica/core/workspace/queries";
import { useAuthStore } from "@multica/core/auth";
import type { ProjectPermissionReportPermission, ProjectPermissionRole } from "@multica/core/types";
import { Button } from "@multica/ui/components/ui/button";
import { Checkbox } from "@multica/ui/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@multica/ui/components/ui/dialog";
import { Input } from "@multica/ui/components/ui/input";
import { Textarea } from "@multica/ui/components/ui/textarea";
import { toast } from "sonner";
import { SettingsCard, SettingsSection, SettingsTab } from "./settings-layout";
import { useT } from "../../i18n";

const PERMISSIONS: ProjectPermissionReportPermission[] = [
  "project.view", "project.edit", "project.issue.create", "project.issue.comment", "project.issue.manage",
  "project.issue.archive", "project.agent.use", "project.member.manage", "project.settings.manage",
];

// 2026-08-28 coder(lq): Keep the built-in catalog visible while an older
// deployment is still migrating the role tables or while the catalog request
// is temporarily unavailable. Database rows always override these defaults,
// so saved system-role customizations remain authoritative.
const SYSTEM_ROLE_DEFAULTS: Array<{
  key: "owner" | "manager" | "member" | "viewer";
  name: string;
  permissions: ProjectPermissionReportPermission[];
}> = [
  {
    key: "owner",
    name: "Owner",
    permissions: [...PERMISSIONS],
  },
  {
    key: "manager",
    name: "Manager",
    permissions: ["project.view", "project.edit", "project.issue.create", "project.issue.comment", "project.issue.manage", "project.issue.archive", "project.agent.use"],
  },
  {
    key: "member",
    name: "Member",
    permissions: ["project.view", "project.issue.create", "project.issue.comment", "project.issue.archive", "project.agent.use"],
  },
  {
    key: "viewer",
    name: "Viewer",
    permissions: ["project.view"],
  },
];

// 2026-08-28 coder(lq): Keep role editing in its own settings surface so
// upstream project/member UI changes do not conflict with role policy work.
export function ProjectPermissionRolesTab() {
  const { t } = useT("settings");
  const workspaceId = useWorkspaceId();
  const currentUser = useAuthStore((state) => state.user);
  const queryClient = useQueryClient();
  const { data: workspaceMembers = [] } = useQuery({
    ...memberListOptions(workspaceId),
    enabled: !!workspaceId,
  });
  const rolesQuery = useQuery({
    queryKey: ["project-permission-roles", workspaceId],
    queryFn: () => api.listProjectPermissionRoles(),
    enabled: !!workspaceId,
  });
  const [editing, setEditing] = useState<ProjectPermissionRole | null>(null);
  const [creating, setCreating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [draft, setDraft] = useState({ key: "", name: "", description: "", permissions: [] as string[] });
  const roles = useMemo(() => {
    const persisted = rolesQuery.data?.roles ?? [];
    const persistedByKey = new Map(persisted.map((role) => [role.key, role]));
    const builtIns = SYSTEM_ROLE_DEFAULTS.map((fallback) => persistedByKey.get(fallback.key) ?? {
      id: `system-${workspaceId}-${fallback.key}`,
      workspace_id: workspaceId,
      key: fallback.key,
      name: fallback.name,
      description: "",
      is_system: true,
      permissions: fallback.permissions,
    });
    const customRoles = persisted.filter((role) => !SYSTEM_ROLE_DEFAULTS.some((fallback) => fallback.key === role.key));
    return [...builtIns, ...customRoles];
  }, [rolesQuery.data?.roles, workspaceId]);
  // 2026-08-28 coder(lq): Role definitions apply across the workspace. Keep
  // their management surface owner-only; project owners still consume this
  // catalog from the project-permission matrix.
  const canManage = workspaceMembers.some(
    (member) => member.user_id === currentUser?.id && member.role === "owner",
  );
  const permissionLabel = (permission: ProjectPermissionReportPermission) =>
    t(($) => $.permission_report.permissions[permission]);
  const roleLabel = (role: ProjectPermissionRole) => role.name || role.key;

  const openCreate = () => {
    setCreating(true);
    setEditing(null);
    setDraft({ key: "", name: "", description: "", permissions: ["project.view"] });
  };
  const openEdit = (role: ProjectPermissionRole) => {
    setCreating(false);
    setEditing(role);
    setDraft({ key: role.key, name: role.name, description: role.description, permissions: [...role.permissions] });
  };
  const closeEditor = () => {
    if (!saving) {
      setEditing(null);
      setCreating(false);
    }
  };
  const togglePermission = (permission: string, checked: boolean) => {
    setDraft((current) => ({
      ...current,
      permissions: checked ? [...new Set([...current.permissions, permission])] : current.permissions.filter((item) => item !== permission),
    }));
  };
  const save = async () => {
    if (!draft.name.trim() || (creating && !draft.key.trim())) return;
    setSaving(true);
    try {
      if (creating) {
        await api.createProjectPermissionRole({ ...draft, key: draft.key.trim(), name: draft.name.trim() });
      } else if (editing) {
        await api.updateProjectPermissionRole(editing.key, { name: draft.name.trim(), description: draft.description.trim(), permissions: draft.permissions });
      }
      await queryClient.invalidateQueries({ queryKey: ["project-permission-roles"] });
      toast.success(t(($) => $.permission_roles.saved));
      setEditing(null);
      setCreating(false);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t(($) => $.permission_roles.save_failed));
    } finally {
      setSaving(false);
    }
  };
  const remove = async (role: ProjectPermissionRole) => {
    if (role.is_system) return;
    try {
      await api.deleteProjectPermissionRole(role.key);
      await queryClient.invalidateQueries({ queryKey: ["project-permission-roles"] });
      toast.success(t(($) => $.permission_roles.deleted));
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t(($) => $.permission_roles.delete_failed));
    }
  };
  return (
    <SettingsTab
      title={t(($) => $.permission_roles.title)}
      description={t(($) => $.permission_roles.description)}
      action={canManage ? (
        <Button size="sm" onClick={openCreate}>
          <Plus className="size-4" />
          {t(($) => $.permission_roles.add)}
        </Button>
      ) : null}
    >
      <SettingsSection>
        <SettingsCard>
          <div className="flex items-start gap-2.5 bg-surface-hover/45 px-4 py-3 text-caption leading-5 text-muted-foreground">
            <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
            <p>{t(($) => $.permission_roles.system_hint)}</p>
          </div>
          {rolesQuery.isLoading ? <p className="px-4 py-6 text-caption text-muted-foreground">{t(($) => $.permission_roles.loading)}</p> : (
            <div className="divide-y divide-surface-border">
              {roles.map((role) => (
                <div
                  key={role.key}
                  className="grid min-w-0 grid-cols-[minmax(0,1fr)_auto] items-start gap-x-3 gap-y-3 px-4 py-4 md:grid-cols-[minmax(10rem,13rem)_minmax(0,1fr)_auto] md:items-center md:gap-x-5"
                >
                  <div className="col-start-1 row-start-1 min-w-0">
                    <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                      <span className="truncate font-medium">{roleLabel(role)}</span>
                      {role.is_system ? (
                        <span className="inline-flex h-5 shrink-0 items-center rounded-full border border-surface-border bg-surface-hover px-2 text-caption font-medium text-muted-foreground">
                          {t(($) => $.permission_roles.system)}
                        </span>
                      ) : null}
                    </div>
                    <div className="mt-0.5 truncate font-mono text-caption text-muted-foreground">{role.description || role.key}</div>
                  </div>
                  <div className="col-span-2 row-start-2 flex min-w-0 flex-wrap items-center gap-1.5 md:col-span-1 md:col-start-2 md:row-start-1">
                    {role.permissions.map((permission) => (
                      <span
                        key={permission}
                        className="inline-flex min-h-6 items-center rounded-md border border-surface-border bg-muted/60 px-2 py-0.5 text-caption leading-4 text-foreground"
                      >
                        {permissionLabel(permission)}
                      </span>
                    ))}
                  </div>
                  {canManage ? (
                    <div className="col-start-2 row-start-1 flex shrink-0 items-center gap-1.5 md:col-start-3">
                      <Button variant="outline" size="sm" onClick={() => openEdit(role)}>{t(($) => $.permission_roles.edit)}</Button>
                      <Button variant="ghost" size="icon-sm" disabled={role.is_system} aria-label={t(($) => $.permission_roles.delete)} onClick={() => void remove(role)}><Trash2 className="size-4" /></Button>
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          )}
        </SettingsCard>
      </SettingsSection>
      <Dialog open={creating || !!editing} onOpenChange={(open) => !open && closeEditor()}>
        <DialogContent>
          <DialogHeader><DialogTitle>{creating ? t(($) => $.permission_roles.create_title) : t(($) => $.permission_roles.edit_title)}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            {creating ? <div className="space-y-1"><label className="text-caption font-medium">{t(($) => $.permission_roles.key)}</label><Input value={draft.key} onChange={(event) => setDraft({ ...draft, key: event.target.value })} placeholder={t(($) => $.permission_roles.key_placeholder)} /></div> : null}
            <div className="space-y-1"><label className="text-caption font-medium">{t(($) => $.permission_roles.name)}</label><Input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} /></div>
            <div className="space-y-1"><label className="text-caption font-medium">{t(($) => $.permission_roles.description_field)}</label><Textarea value={draft.description} onChange={(event) => setDraft({ ...draft, description: event.target.value })} /></div>
            <div className="space-y-2"><div className="text-caption font-medium">{t(($) => $.permission_roles.permissions)}</div>{PERMISSIONS.map((permission) => <label key={permission} className="flex items-center gap-2 text-body"><Checkbox checked={draft.permissions.includes(permission)} onCheckedChange={(checked) => togglePermission(permission, checked === true)} />{permissionLabel(permission)}</label>)}</div>
          </div>
          <DialogFooter><Button variant="outline" onClick={closeEditor}>{t(($) => $.permission_roles.cancel)}</Button><Button onClick={() => void save()} disabled={saving || !draft.name.trim() || (creating && !draft.key.trim())}>{saving ? t(($) => $.permission_roles.saving) : t(($) => $.permission_roles.save)}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </SettingsTab>
  );
}
