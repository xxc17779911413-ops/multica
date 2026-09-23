export type TaskAccessMode = "inherit" | "restricted";
export type TaskAccessSubjectType = "user" | "organization" | "everyone";

export interface TaskPermissionRole {
  id: string;
  workspace_id: string;
  key: string;
  name: string;
  description: string;
  is_system: boolean;
  scope: "task";
  permissions: string[];
}

export interface TaskPermissionRolesResponse {
  scope: "task";
  roles: TaskPermissionRole[];
}

export interface IssueAccessControlGrant {
  subject_type: TaskAccessSubjectType;
  subject_id?: string;
  role: string;
  scope: "task";
  expires_at?: string;
}

/**
 * Access the task carries from a source this API does not own — a mention, an
 * access request, a migration, an organization or Everyone. Read-only here: the
 * dialog may show it so a manager can see who really has access, but only the
 * owning source can change it.
 */
export interface IssueAccessControlDerivedGrant {
  subject_type: TaskAccessSubjectType;
  subject_id?: string;
  role: string;
  /** Stored grant source: system | organization | everyone | migration. */
  source: string;
  /** Why the row exists: creator | assignee | mention, else the stored source. */
  reason: string;
}

export interface IssueAccessControl {
  workspace_id: string;
  issue_id: string;
  project_id?: string;
  scope: "task";
  project_access_mode: TaskAccessMode;
  policy_version: number;
  grants: IssueAccessControlGrant[];
  derived_grants: IssueAccessControlDerivedGrant[];
}

export interface IssueAccessControlUpdate {
  expected_version: number;
  project_access_mode: TaskAccessMode;
  grants: IssueAccessControlGrant[];
}

export interface IssueAccessControlPreview {
  before: IssueAccessControl;
  after: IssueAccessControl;
  subjects_losing_access: string[];
  subjects_with_other_source: string[];
  affected_effects: string[];
}

export interface EffectiveAccessResourceRef {
  scope: "workspace" | "project" | "task";
  id: string;
}

export interface EffectiveTaskPermissionSource {
  permission: string;
  source: string;
  underlying_source?: string;
  subject_type?: string;
  subject_id?: string;
  role?: string;
  scope?: "workspace" | "project" | "task";
  grant_id?: string;
  grant_source?: string;
  granted_by?: string;
  origin_kind?: string;
  origin_id?: string;
  expires_at?: string;
  source_resource: EffectiveAccessResourceRef;
  underlying_resource?: EffectiveAccessResourceRef;
  target_resource: EffectiveAccessResourceRef;
  policy_version: number;
}

export interface EffectiveIssueAccess {
  workspace_id: string;
  issue_id: string;
  project_id?: string;
  project_access_mode: TaskAccessMode;
  policy_version: number;
  permissions: string[];
  sources: EffectiveTaskPermissionSource[];
}

export interface IssueAccessRequest {
  id: string;
  workspace_id: string;
  issue_id: string;
  requester_user_id: string;
  requested_role: string;
  reason?: string;
  status: "pending" | "approved" | "rejected" | "cancelled" | "expired";
  reviewer_user_id?: string;
  review_comment?: string;
  expires_at?: string;
  reviewed_at?: string;
  created_at: string;
  updated_at: string;
}

export interface IssueAccessRequestTarget {
  id: string;
  identifier: string;
}
