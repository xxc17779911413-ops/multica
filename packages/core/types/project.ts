export type ProjectStatus = "planned" | "in_progress" | "paused" | "completed" | "cancelled";

export type ProjectPriority = "urgent" | "high" | "medium" | "low" | "none";

export interface Project {
  id: string;
  workspace_id: string;
  title: string;
  description: string | null;
  icon: string | null;
  status: ProjectStatus;
  priority: ProjectPriority;
  lead_type: "member" | "agent" | null;
  lead_id: string | null;
  // Calendar days ("YYYY-MM-DD"), no time-of-day or timezone — same contract as
  // issue.start_date / issue.due_date.
  start_date: string | null;
  due_date: string | null;
  created_at: string;
  updated_at: string;
  /** User who created the project; null for projects created before attribution was added. */
  created_by: string | null;
  issue_count: number;
  done_count: number;
  resource_count: number;
  /** Explicit role on this project for the signed-in user; omitted by legacy backends. */
  current_user_role?: string | null;
  /** Whether the signed-in user may delete this project. */
  can_delete?: boolean;
}

export interface CreateProjectRequest {
  title: string;
  description?: string;
  icon?: string;
  status?: ProjectStatus;
  priority?: ProjectPriority;
  lead_type?: "member" | "agent";
  lead_id?: string;
  start_date?: string;
  due_date?: string;
  // Resources to attach in the same transaction as the project. Server returns
  // 4xx (and rolls back) if any one is invalid or duplicate.
  resources?: CreateProjectResourceRequest[];
  /** Optional project-level grants persisted atomically with project creation. */
  access_grants?: CreateProjectAccessGrantRequest[];
}

export interface CreateProjectAccessGrantRequest {
  subject_type: ProjectAccessGrantSubjectType;
  subject_id?: string;
  role?: string;
  permission?: ProjectPermissionReportPermission | string;
}

export interface UpdateProjectRequest {
  title?: string;
  description?: string | null;
  icon?: string | null;
  status?: ProjectStatus;
  priority?: ProjectPriority;
  lead_type?: "member" | "agent" | null;
  lead_id?: string | null;
  // Omit the key to leave the date untouched; send null (or "") to clear it.
  start_date?: string | null;
  due_date?: string | null;
}

export interface ListProjectsResponse {
  projects: Project[];
  total: number;
}

// ProjectResource is a typed pointer from a project to an external resource.
// The resource_ref shape depends on resource_type. New types add a case in
// validateAndNormalizeResourceRef on the server and a renderer in the UI.
//
// Known types (UI must default-case unknown server-side additions):
//   - github_repo: cloud-side git checkout, ref = { url, ref?, default_branch_hint? }
//   - local_directory: agent execution on a specific daemon,
//     ref = { local_path, daemon_id, label?, execution_mode? }
export type ProjectResourceType = "github_repo" | "local_directory";

export interface GithubRepoResourceRef {
  url: string;
  ref?: string;
  default_branch_hint?: string;
}

/**
 * How tasks sharing one local directory are executed.
 *
 * - `in_place`: the agent works directly in the user's directory and tasks run
 *   one at a time — a second task waits in `waiting_local_directory`. Edits
 *   land in the user's working copy.
 * - `worktree`: each task gets its own git worktree of that repo inside the
 *   runtime's workspace, so tasks run concurrently and deliver their work as a
 *   branch instead of touching the working copy. Every task of one conversation
 *   shares that branch — `agent/<agent>/<issue>` — so a follow-up continues the
 *   previous turn's work; a task with no conversation behind it gets
 *   `agent/<agent>/<task>`. Continuation is decided by an ownership record in
 *   the repo, not by the branch name, so a same-named branch the user made is
 *   never adopted.
 *
 * Absent means `in_place`: resources created before the mode existed keep their
 * original behavior, so this is optional rather than defaulted on the server.
 */
export type LocalDirectoryExecutionMode = "in_place" | "worktree";

export interface LocalDirectoryResourceRef {
  local_path: string;
  daemon_id: string;
  label?: string;
  execution_mode?: LocalDirectoryExecutionMode;
}

export type ProjectResourceRef =
  | GithubRepoResourceRef
  | LocalDirectoryResourceRef
  | Record<string, unknown>;

export interface ProjectResource {
  id: string;
  project_id: string;
  workspace_id: string;
  resource_type: ProjectResourceType;
  resource_ref: ProjectResourceRef;
  label: string | null;
  position: number;
  created_at: string;
  created_by: string | null;
}

export interface CreateProjectResourceRequest {
  resource_type: ProjectResourceType;
  resource_ref: ProjectResourceRef;
  label?: string;
  position?: number;
}

// resource_type is immutable server-side; partial-update payload mirrors that.
// Sending only the field(s) you want to change is fine — the server merges
// the request body with the existing row, including resource_ref shortcuts.
export interface UpdateProjectResourceRequest {
  resource_ref?: ProjectResourceRef;
  label?: string | null;
  position?: number;
}

export interface ListProjectResourcesResponse {
  resources: ProjectResource[];
  total: number;
}

export interface ProjectAccessGrant {
  id: string;
  workspace_id: string;
  project_id: string;
  issue_id?: string;
  subject_type: ProjectAccessGrantSubjectType;
  subject_id?: string;
  role?: string;
  permission?: ProjectPermissionReportPermission | string;
  source: ProjectAccessGrantSource;
  granted_by?: string;
  /** Timestamp assigned by the canonical projectauth grant row. */
  created_at?: string;
}

export interface ProjectAccessGrantRequest {
  subject_type: ProjectAccessGrantSubjectType;
  subject_id?: string;
  role?: string;
  permission?: ProjectPermissionReportPermission | string;
  expires_at?: string;
}

export interface ProjectPermissionReportParams {
  project_id?: string;
  issue_id?: string;
  user_id?: string;
  role?: ProjectPermissionReportRole;
  permission?: ProjectPermissionReportPermission;
  subject_type?: ProjectAccessGrantSubjectType;
  subject_id?: string;
  scope?: "all" | "project" | "issue";
  limit?: number;
  offset?: number;
  /** Records an authorization audit event and returns the exact exported row set. */
  export?: boolean;
}

export interface ProjectPermissionReportResponse {
  rows: ProjectPermissionReportRow[];
  total: number;
  limit: number;
  offset: number;
}

export interface ProjectPermissionRole {
  id: string;
  workspace_id: string;
  key: string;
  name: string;
  description: string;
  is_system: boolean;
  permissions: string[];
}

export type ProjectPermissionReportRole = string;

export type ProjectPermissionReportPermission =
  | "project.view"
  | "project.edit"
  | "project.issue.create"
  | "project.issue.comment"
  | "project.issue.manage"
  | "project.issue.archive"
  | "project.agent.use"
  | "project.member.manage"
  | "project.settings.manage";

export const PROJECT_PERMISSION_KEYS: ProjectPermissionReportPermission[] = [
  "project.view",
  "project.edit",
  "project.issue.create",
  "project.issue.comment",
  "project.issue.manage",
  "project.issue.archive",
  "project.agent.use",
  "project.member.manage",
  "project.settings.manage",
];

export interface ProjectPermissionReportRow {
  scope: "project" | "issue";
  project_id: string;
  project_title: string;
  issue_id?: string;
  issue_title?: string;
  user_id: string;
  user_name: string;
  user_email: string;
  subject_type: ProjectAccessGrantSubjectType;
  subject_id?: string;
  workspace_role?: ProjectPermissionReportRole;
  project_role?: ProjectPermissionReportRole;
  role_scope?: "workspace" | "project" | "task";
  permission: ProjectPermissionReportPermission;
  source: string;
  grant_id?: string;
  granted_by?: string;
  created_at?: string;
  expires_at?: string;
  source_resource_scope?: "workspace" | "project" | "task";
  source_resource_id?: string;
  project_access_mode?: "inherit" | "restricted";
  policy_version?: number;
  inherited_from_project: boolean;
}

export type ProjectAccessGrantSubjectType = "user" | "role" | "organization" | "everyone";

export type ProjectAccessGrantSource = "manual" | "organization" | "everyone" | "migration" | "system" | string;

export type ProjectAuthorizationImportKind = "organizations" | "members";

export interface ProjectAuthorizationOrganization {
  id: string;
  workspace_id: string;
  provider: string;
  external_id: string;
  name: string;
  parent_id?: string;
  status: string;
}

export interface ProjectAuthorizationOrganizationMember {
  organization_id: string;
  user_id: string;
  name: string;
  email: string;
  avatar_url?: string;
  workspace_role: "owner" | "admin" | "member" | string;
  has_logged_in?: boolean;
}
