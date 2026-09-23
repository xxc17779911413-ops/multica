package projectauth

import "time"

// 2026-08-24 coder(lq): Keep workspace roles sourced from Multica's native member table.
type WorkspaceRole string

const (
	WorkspaceOwner  WorkspaceRole = "owner"
	WorkspaceAdmin  WorkspaceRole = "admin"
	WorkspaceMember WorkspaceRole = "member"
)

// 2026-08-24 coder(lq): Keep project roles independent from the native workspace role.
type ProjectRole string

const (
	ProjectOwner   ProjectRole = "owner"
	ProjectManager ProjectRole = "manager"
	ProjectMember  ProjectRole = "member"
	ProjectViewer  ProjectRole = "viewer"
)

// TaskRole is intentionally distinct from ProjectRole. The two catalogs use
// the same built-in keys, but their permission matrices and persistence are
// independent.
// 2026-09-14 coder(lq): Prevent same-named project roles from defining task ACLs.
type TaskRole string

const (
	TaskOwner   TaskRole = "owner"
	TaskManager TaskRole = "manager"
	TaskMember  TaskRole = "member"
	TaskViewer  TaskRole = "viewer"
)

type RoleScope string

const (
	RoleScopeWorkspace RoleScope = "workspace"
	RoleScopeProject   RoleScope = "project"
	RoleScopeTask      RoleScope = "task"
)

// RoleKey is the persistence-neutral role identifier carried by a grant. The
// accompanying Scope is mandatory at domain boundaries: identical keys such
// as "member" intentionally resolve against different project/task catalogs.
// Keep this as a string-backed type so existing API payloads remain compatible
// while compile-time conversions make catalog crossings visible in code review.
// 2026-09-14 coder(lq): Remove the false ProjectRole typing from task grants.
type RoleKey string

// 2026-08-24 coder(lq): Carry the already-authenticated identity and native workspace
// membership. The HTTP adapter can construct it from Multica's request context.
type Subject struct {
	UserID        string
	WorkspaceID   string
	WorkspaceRole WorkspaceRole
}

// Organization is the provider-neutral directory snapshot used by project
// authorization. External providers (DingTalk, WeCom, Feishu, etc.) sync
// into this model; request-time authorization never calls those providers.
// 2026-09-01 coder(lq): Expose stable local organization IDs to authorization
// pickers while keeping provider-specific identifiers out of grant payloads.
type Organization struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Provider    string `json:"provider"`
	ExternalID  string `json:"external_id"`
	Name        string `json:"name"`
	ParentID    string `json:"parent_id,omitempty"`
	Status      string `json:"status"`
}

// OrganizationMember is a provider-neutral directory membership used by the
// organization browser. Authorization still evaluates the normalized
// projectauth_organization_members relation and never copies department grants
// into per-user grants.
// 2026-09-03 coder(lq): Expose synchronized employees without leaking OA IDs.
type OrganizationMember struct {
	OrganizationID string        `json:"organization_id"`
	UserID         string        `json:"user_id"`
	Name           string        `json:"name"`
	Email          string        `json:"email"`
	AvatarURL      string        `json:"avatar_url,omitempty"`
	WorkspaceRole  WorkspaceRole `json:"workspace_role"`
	// 2026-09-06 coder(lq): True only after a real login, not after directory import.
	HasLoggedIn bool `json:"has_logged_in"`
}

// 2026-08-31 coder(lq): Grant subjects are independent from external login
// providers. Adapters resolve external identities to the native user ID first.
type SubjectType string

const (
	SubjectUser         SubjectType = "user"
	SubjectRole         SubjectType = "role"
	SubjectOrganization SubjectType = "organization"
	SubjectEveryone     SubjectType = "everyone"
)

type GrantSource string

const (
	GrantSourceManual       GrantSource = "manual"
	GrantSourceOrganization GrantSource = "organization"
	GrantSourceEveryone     GrantSource = "everyone"
	GrantSourceMigration    GrantSource = "migration"
	GrantSourceSystem       GrantSource = "system"
)

// AccessGrant is the storage-neutral representation of one allow grant. A
// nil-equivalent empty IssueID means project scope; a value means task scope.
type AccessGrant struct {
	ID          string      `json:"id"`
	WorkspaceID string      `json:"workspace_id"`
	ProjectID   string      `json:"project_id"`
	IssueID     string      `json:"issue_id,omitempty"`
	SubjectType SubjectType `json:"subject_type"`
	SubjectID   string      `json:"subject_id,omitempty"`
	Role        RoleKey     `json:"role,omitempty"`
	Scope       RoleScope   `json:"scope,omitempty"`
	Permission  Permission  `json:"permission,omitempty"`
	Source      GrantSource `json:"source"`
	GrantedBy   string      `json:"granted_by,omitempty"`
	CreatedAt   string      `json:"created_at,omitempty"`
	ExpiresAt   *time.Time  `json:"expires_at,omitempty"`
	OriginKind  string      `json:"origin_kind,omitempty"`
	OriginID    string      `json:"origin_id,omitempty"`
}

// ValidateRoleScope rejects a grant whose declared catalog/resource scope does
// not match the resource carrying it. Exact-permission grants carry the same
// scope so role subjects and API consumers never have to infer a catalog.
func (g AccessGrant) ValidateRoleScope() error {
	return (&g).NormalizeRoleScope()
}

// NormalizeRoleScope provides a compatibility boundary for existing API rows
// whose unified string role predates the scope field. After this method every
// grant is explicit; a conflicting supplied scope is rejected.
func (g *AccessGrant) NormalizeRoleScope() error {
	want := RoleScopeProject
	if g.IssueID != "" {
		want = RoleScopeTask
	}
	if g.Scope == "" {
		g.Scope = want
		return nil
	}
	if g.Scope != want {
		return ErrInvalidRoleScope
	}
	return nil
}

// 2026-08-24 coder(lq): Use strings so new permissions can be added
// without changing the storage schema or the native Multica models.
type Permission string

const (
	View        Permission = "project.view"
	Edit        Permission = "project.edit"
	IssueCreate Permission = "project.issue.create"
	// 2026-09-02 coder(lq): Keep task conversation writes separate from
	// project metadata editing so members can comment without broad edit access.
	IssueComment Permission = "project.issue.comment"
	IssueManage  Permission = "project.issue.manage"
	// 2026-09-02 coder(lq): Archive is isolated from issue management so
	// deployments can grant retention control without granting task edits.
	IssueArchive Permission = "project.issue.archive"
	AgentUse     Permission = "project.agent.use"
	// 2026-09-14 coder(lq): Creating or linking a child is a task permission;
	// creating the child in an explicit project is checked separately.
	IssueChildCreate Permission = "project.issue.child.create"
	MemberManage     Permission = "project.member.manage"
	SettingsManage   Permission = "project.settings.manage"
)
