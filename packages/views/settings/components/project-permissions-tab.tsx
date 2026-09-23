"use client";

import { useEffect, useMemo, useState } from "react";
import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Crown, Shield, UserRound } from "lucide-react";
import { api } from "@multica/core/api";
import { useWorkspaceId } from "@multica/core/hooks";
import { memberListOptions } from "@multica/core/workspace/queries";
import { projectListOptions } from "@multica/core/projects";
import { useAuthStore } from "@multica/core/auth";
import type { ProjectPermissionRole } from "@multica/core/types";
import { Badge } from "@multica/ui/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@multica/ui/components/ui/select";
import { toast } from "sonner";
import { SettingsCard, SettingsSection, SettingsTab } from "./settings-layout";
import { useT } from "../../i18n";

const NO_ACCESS = "__no_project_access__";
const ALL_FILTER = "__all__";
const BUILTIN_ROLES = ["owner", "manager", "member", "viewer"];
const PERSON_COLUMN_WIDTH = 280;
const WORKSPACE_ROLE_COLUMN_WIDTH = 112;
const PROJECT_COLUMN_WIDTH = 160;

// 2026-08-28 coder(lq): Project cells represent explicit project membership;
// workspace-level roles are shown separately and must not be copied here.
export function projectPermissionCellValue(explicitRole?: string | null): string {
  const role = explicitRole?.trim();
  return role || NO_ACCESS;
}

function projectMembersKey(projectId: string) {
  return ["project-members", projectId] as const;
}

// 2026-08-28 coder(lq): Compose this report from existing project/member
// endpoints so the private authorization overlay remains low-conflict with
// future upstream settings-page updates.
export function ProjectPermissionsTab() {
  const { t } = useT("settings");
  const workspaceId = useWorkspaceId();
  const queryClient = useQueryClient();
  const currentUser = useAuthStore((state) => state.user);
  const [savingCell, setSavingCell] = useState<string | null>(null);
  const [projectFilter, setProjectFilter] = useState(ALL_FILTER);
  const [roleFilter, setRoleFilter] = useState(ALL_FILTER);
  const [personFilter, setPersonFilter] = useState(ALL_FILTER);

  useEffect(() => {
    // 2026-08-28 coder(lq): Filters belong to a workspace; never carry an ID
    // from the previous workspace into the next report.
    setProjectFilter(ALL_FILTER);
    setRoleFilter(ALL_FILTER);
    setPersonFilter(ALL_FILTER);
  }, [workspaceId]);

  const { data: members = [], isLoading: membersLoading } = useQuery(memberListOptions(workspaceId));
  const { data: projects = [], isLoading: projectsLoading } = useQuery(projectListOptions(workspaceId));
  const { data: roleDefinitions } = useQuery({
    queryKey: ["project-permission-roles", workspaceId],
    queryFn: () => api.listProjectPermissionRoles(),
    enabled: !!workspaceId,
  });
  const projectMemberQueries = useQueries({
    queries: projects.map((project) => ({
      queryKey: projectMembersKey(project.id),
      queryFn: () => api.listProjectMembers(project.id),
      enabled: !!workspaceId && !!project.id,
    })),
  });

  const roles = useMemo<ProjectPermissionRole[]>(() => {
    const persisted = roleDefinitions?.roles ?? [];
    const keys = new Set(persisted.map((role) => role.key));
    const missing = BUILTIN_ROLES
      .filter((key) => !keys.has(key))
      .map((key) => ({
        id: `system-${workspaceId}-${key}`,
        workspace_id: workspaceId,
        key,
        name: key.charAt(0).toLocaleUpperCase() + key.slice(1),
        description: "",
        permissions: [],
        is_system: true,
      }));
    return [...persisted, ...missing];
  }, [roleDefinitions?.roles, workspaceId]);
  const roleByKey = useMemo(() => new Map(roles.map((role) => [role.key, role])), [roles]);
  const workspaceMemberByUser = useMemo(
    () => new Map(members.map((member) => [member.user_id, member])),
    [members],
  );
  const isWorkspaceOwner = workspaceMemberByUser.get(currentUser?.id ?? "")?.role === "owner";
  const projectMembersByProject = useMemo(
    () => new Map(projects.map((project, index) => [project.id, projectMemberQueries[index]?.data?.members ?? []])),
    [projectMemberQueries, projects],
  );
  // 2026-08-28 coder(lq): Keep report filtering local to the already loaded
  // matrix. This makes filter changes immediate and avoids a second report
  // endpoint whose write permissions could drift from the matrix controls.
  const filteredProjects = useMemo(
    () => projectFilter === ALL_FILTER ? projects : projects.filter((project) => project.id === projectFilter),
    [projectFilter, projects],
  );
  const filteredMembers = useMemo(
    () => members.filter((member) => {
      if (personFilter !== ALL_FILTER && member.user_id !== personFilter) return false;
      if (roleFilter === ALL_FILTER) return true;
      return filteredProjects.some((project) =>
        projectPermissionCellValue(
          (projectMembersByProject.get(project.id) ?? []).find(
            (projectMember) => projectMember.user_id === member.user_id,
          )?.role,
        ) === roleFilter,
      );
    }),
    [filteredProjects, members, personFilter, projectMembersByProject, roleFilter],
  );
  const canManageByProject = useMemo(
    () => new Map(projects.map((project, index) => [project.id, projectMemberQueries[index]?.data?.can_manage ?? false])),
    [projectMemberQueries, projects],
  );
  const loading = membersLoading || projectsLoading || projectMemberQueries.some((query) => query.isLoading);
  const hasError = projectMemberQueries.some((query) => query.isError);

  const roleLabel = (key: string) => {
    const persistedName = roleByKey.get(key)?.name;
    if (persistedName) return persistedName;
    if (["owner", "admin", ...BUILTIN_ROLES].includes(key)) {
      return t(($) => $.permission_report.roles[key as "owner" | "admin" | "manager" | "member" | "viewer"]);
    }
    return key;
  };
  const workspaceRoleLabel = (key: string) => {
    if (["owner", "admin", "member"].includes(key)) {
      return t(($) => $.permission_report.roles[key as "owner" | "admin" | "member"]);
    }
    return key;
  };
  const userLabel = (userId: string) => {
    const member = workspaceMemberByUser.get(userId);
    return member?.name || member?.email || userId;
  };

  const saveCell = async (projectId: string, userId: string, value: string) => {
    const cellKey = `${projectId}:${userId}`;
    setSavingCell(cellKey);
    try {
      if (value === NO_ACCESS) await api.removeProjectMember(projectId, userId);
      else await api.addProjectMember(projectId, { user_id: userId, role: value });
      await queryClient.invalidateQueries({ queryKey: projectMembersKey(projectId) });
      toast.success(t(($) => $.permission_report.saved));
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t(($) => $.permission_report.save_failed));
    } finally {
      setSavingCell(null);
    }
  };

  return (
    <SettingsTab title={t(($) => $.permission_report.title)} description={t(($) => $.permission_report.description)}>
      <SettingsSection>
        <SettingsCard>
          {loading ? (
            <p className="px-4 py-6 text-caption text-muted-foreground">{t(($) => $.permission_report.loading)}</p>
          ) : hasError ? (
            <p className="px-4 py-6 text-caption text-destructive">{t(($) => $.permission_report.load_failed)}</p>
          ) : members.length === 0 || projects.length === 0 ? (
            <p className="px-4 py-6 text-caption text-muted-foreground">{t(($) => $.permission_report.empty)}</p>
          ) : (
            <>
              <div className="flex flex-wrap items-end gap-3 px-4 py-4">
                <div className="flex min-w-44 flex-1 flex-col gap-1">
                  <span className="text-caption text-muted-foreground">{t(($) => $.permission_report.project_filter)}</span>
                  <Select
                    items={[{ value: ALL_FILTER, label: t(($) => $.permission_report.all_projects) }, ...projects.map((project) => ({ value: project.id, label: project.title }))]}
                    value={projectFilter}
                    onValueChange={(value) => value && setProjectFilter(value)}
                  >
                    <SelectTrigger className="w-full" aria-label={t(($) => $.permission_report.project_filter)}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={ALL_FILTER}>{t(($) => $.permission_report.all_projects)}</SelectItem>
                      {projects.map((project) => <SelectItem key={project.id} value={project.id}>{project.title}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex min-w-44 flex-1 flex-col gap-1">
                  <span className="text-caption text-muted-foreground">{t(($) => $.permission_report.role_filter)}</span>
                  <Select
                    items={[{ value: ALL_FILTER, label: t(($) => $.permission_report.all_roles) }, { value: NO_ACCESS, label: t(($) => $.permission_report.no_access) }, ...roles.map((role) => ({ value: role.key, label: roleLabel(role.key) }))]}
                    value={roleFilter}
                    onValueChange={(value) => value && setRoleFilter(value)}
                  >
                    <SelectTrigger className="w-full" aria-label={t(($) => $.permission_report.role_filter)}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={ALL_FILTER}>{t(($) => $.permission_report.all_roles)}</SelectItem>
                      <SelectItem value={NO_ACCESS}>{t(($) => $.permission_report.no_access)}</SelectItem>
                      {roles.map((role) => <SelectItem key={role.key} value={role.key}>{roleLabel(role.key)}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex min-w-44 flex-1 flex-col gap-1">
                  <span className="text-caption text-muted-foreground">{t(($) => $.permission_report.person_filter)}</span>
                  <Select
                    items={[{ value: ALL_FILTER, label: t(($) => $.permission_report.all_people) }, ...members.map((member) => ({ value: member.user_id, label: userLabel(member.user_id) }))]}
                    value={personFilter}
                    onValueChange={(value) => value && setPersonFilter(value)}
                  >
                    <SelectTrigger className="w-full" aria-label={t(($) => $.permission_report.person_filter)}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={ALL_FILTER}>{t(($) => $.permission_report.all_people)}</SelectItem>
                      {members.map((member) => <SelectItem key={member.user_id} value={member.user_id}>{userLabel(member.user_id)}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              {filteredProjects.length === 0 || filteredMembers.length === 0 ? (
                <p className="px-4 py-8 text-center text-caption text-muted-foreground">{t(($) => $.permission_report.empty)}</p>
              ) : (
                <div className="max-h-[60vh] overflow-auto">
                  {/* 2026-09-01 coder(lq): Keep filters and dialog chrome static while
                      the permission matrix scrolls independently. */}
                  <table
                    className="w-full table-fixed border-separate border-spacing-0 text-body"
                    style={{ minWidth: PERSON_COLUMN_WIDTH + WORKSPACE_ROLE_COLUMN_WIDTH + filteredProjects.length * PROJECT_COLUMN_WIDTH }}
                  >
                      <colgroup>
                        <col style={{ width: PERSON_COLUMN_WIDTH }} />
                        <col style={{ width: WORKSPACE_ROLE_COLUMN_WIDTH }} />
                        {filteredProjects.map((project) => <col key={project.id} />)}
                      </colgroup>
                      <thead>
                        <tr className="border-b border-surface-border text-left text-caption text-muted-foreground">
                          <th className="sticky left-0 top-0 z-30 border-r border-surface-border bg-surface px-3 py-2.5">{t(($) => $.permission_report.person_column)}</th>
                          <th className="sticky top-0 z-20 bg-surface px-3 py-2.5">{t(($) => $.permission_report.workspace_role_column)}</th>
                          {filteredProjects.map((project) => <th key={project.id} className="sticky top-0 z-20 truncate bg-surface px-3 py-2.5" title={project.title}>{project.title}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {filteredMembers.map((member) => {
                          const WorkspaceRoleIcon = member.role === "owner"
                            ? Crown
                            : member.role === "admin"
                              ? Shield
                              : UserRound;
                          return (
                            <tr key={member.user_id} className="border-b border-surface-border/60">
                              <td className="sticky left-0 z-10 overflow-hidden border-r border-surface-border bg-surface px-3 py-2.5">
                                <div className="truncate" title={userLabel(member.user_id)}>{userLabel(member.user_id)}</div>
                                {member.email && <div className="truncate text-caption text-muted-foreground" title={member.email}>{member.email}</div>}
                              </td>
                              <td className="px-3 py-2.5 align-middle">
                                <Badge variant="secondary" className="h-5 gap-1 px-2 text-micro font-medium text-muted-foreground">
                                  <WorkspaceRoleIcon aria-hidden="true" />
                                  {workspaceRoleLabel(member.role)}
                                </Badge>
                              </td>
                              {filteredProjects.map((project) => {
                                const projectMembers = projectMembersByProject.get(project.id) ?? [];
                                const explicit = projectMembers.find((projectMember) => projectMember.user_id === member.user_id);
                                const value = projectPermissionCellValue(explicit?.role);
                                const canManage = isWorkspaceOwner || canManageByProject.get(project.id) === true;
                                const cellKey = `${project.id}:${member.user_id}`;
                                const disabled = !canManage || savingCell === cellKey;
                                return (
                                  <td key={project.id} className="px-3 py-2.5 align-middle">
                                    <Select
                                      items={[{ value: NO_ACCESS, label: t(($) => $.permission_report.no_access) }, ...roles.map((role) => ({ value: role.key, label: roleLabel(role.key) }))]}
                                      value={value}
                                      onValueChange={(next) => next && void saveCell(project.id, member.user_id, next)}
                                      disabled={disabled}
                                    >
                                      <SelectTrigger className="w-32" aria-label={`${userLabel(member.user_id)} / ${project.title}`}>
                                        <SelectValue />
                                      </SelectTrigger>
                                      <SelectContent>
                                        <SelectItem value={NO_ACCESS}>{t(($) => $.permission_report.no_access)}</SelectItem>
                                        {roles.map((role) => <SelectItem key={role.key} value={role.key}>{roleLabel(role.key)}</SelectItem>)}
                                      </SelectContent>
                                    </Select>
                                  </td>
                                );
                              })}
                            </tr>
                          );
                        })}
                      </tbody>
                  </table>
                </div>
              )}
            </>
          )}
          <div className="flex items-center gap-2 px-4 py-3 text-caption text-muted-foreground">
            <span>{t(($) => $.permission_report.people_projects)}</span>
            <span>·</span>
            <span>{t(($) => $.permission_report.read_only_hint)}</span>
          </div>
        </SettingsCard>
      </SettingsSection>
    </SettingsTab>
  );
}
