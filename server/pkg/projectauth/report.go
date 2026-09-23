package projectauth

import (
	"context"
	"errors"
	"fmt"
)

// 2026-08-31 coder(lq): Permission reports expose authorization facts for
// projects and tasks, including inherited project grants and their original
// subject/source. Keeping this shape in the independent package lets callers
// render a matrix or an audit table without coupling to PostgreSQL.
type PermissionReportFilter struct {
	WorkspaceID string
	ProjectID   string
	IssueID     string
	UserID      string
	Role        string
	Permission  Permission
	SubjectType SubjectType
	SubjectID   string
	Scope       string // all, project, or issue
	Limit       int
	Offset      int
}
type PermissionReportRow struct {
	Scope                string            `json:"scope"`
	ProjectID            string            `json:"project_id"`
	ProjectTitle         string            `json:"project_title"`
	IssueID              string            `json:"issue_id,omitempty"`
	IssueTitle           string            `json:"issue_title,omitempty"`
	UserID               string            `json:"user_id"`
	UserName             string            `json:"user_name"`
	UserEmail            string            `json:"user_email"`
	SubjectType          SubjectType       `json:"subject_type"`
	SubjectID            string            `json:"subject_id,omitempty"`
	WorkspaceRole        WorkspaceRole     `json:"workspace_role"`
	ProjectRole          ProjectRole       `json:"project_role,omitempty"`
	RoleScope            RoleScope         `json:"role_scope,omitempty"`
	Permission           Permission        `json:"permission"`
	Source               string            `json:"source"`
	GrantID              string            `json:"grant_id,omitempty"`
	GrantedBy            string            `json:"granted_by,omitempty"`
	CreatedAt            string            `json:"created_at,omitempty"`
	ExpiresAt            string            `json:"expires_at,omitempty"`
	SourceResourceScope  RoleScope         `json:"source_resource_scope,omitempty"`
	SourceResourceID     string            `json:"source_resource_id,omitempty"`
	ProjectAccessMode    ProjectAccessMode `json:"project_access_mode,omitempty"`
	PolicyVersion        int64             `json:"policy_version,omitempty"`
	InheritedFromProject bool              `json:"inherited_from_project"`
}

type PermissionReportResult struct {
	Rows  []PermissionReportRow
	Total int64
}

type PermissionReportRepository interface {
	Repository
	ListPermissionReport(ctx context.Context, filter PermissionReportFilter) (PermissionReportResult, error)
}

// 2026-08-27 coder(lq): Reports are administrative reads. Only workspace
// owners may report across the workspace; other users need project settings
// permission and must scope the report to one project.
func (s *Service) ListPermissionReport(ctx context.Context, subject Subject, filter PermissionReportFilter) (PermissionReportResult, error) {
	if s == nil || !s.Enabled() {
		return PermissionReportResult{}, nil
	}
	if s.repo == nil {
		return PermissionReportResult{}, ErrDisabled
	}
	rr, ok := s.repo.(PermissionReportRepository)
	if !ok {
		return PermissionReportResult{}, ErrDisabled
	}
	if filter.WorkspaceID == "" {
		filter.WorkspaceID = subject.WorkspaceID
	}
	if filter.WorkspaceID == "" || filter.WorkspaceID != subject.WorkspaceID {
		return PermissionReportResult{}, ErrCrossWorkspace
	}
	if filter.Scope == "" {
		filter.Scope = "all"
	}
	if filter.Scope != "all" && filter.Scope != "project" && filter.Scope != "issue" {
		return PermissionReportResult{}, fmt.Errorf("%w: scope=%s", ErrInvalidReportFilter, filter.Scope)
	}
	if filter.SubjectType != "" && filter.SubjectType != SubjectUser && filter.SubjectType != SubjectRole && filter.SubjectType != SubjectOrganization && filter.SubjectType != SubjectEveryone {
		return PermissionReportResult{}, fmt.Errorf("%w: subject_type=%s", ErrInvalidReportFilter, filter.SubjectType)
	}
	if filter.Role != "" && !validReportRole(ctx, s.repo, filter.WorkspaceID, filter.Role) {
		return PermissionReportResult{}, fmt.Errorf("%w: role=%s", ErrInvalidReportFilter, filter.Role)
	}
	if filter.Permission != "" && !validReportPermission(filter.Permission) {
		return PermissionReportResult{}, fmt.Errorf("%w: permission=%s", ErrInvalidReportFilter, filter.Permission)
	}
	if filter.Limit <= 0 || filter.Limit > 1000 {
		filter.Limit = 1000
	}
	if filter.Offset < 0 {
		return PermissionReportResult{}, fmt.Errorf("%w: offset=%d", ErrInvalidReportFilter, filter.Offset)
	}
	role, err := s.repo.WorkspaceRole(ctx, subject.WorkspaceID, subject.UserID)
	if err != nil {
		return PermissionReportResult{}, ErrNotWorkspaceMember
	}
	if filter.IssueID != "" {
		resourceRepo, ok := s.repo.(ResourceRepository)
		if !ok {
			return PermissionReportResult{}, ErrMigrationRequired
		}
		workspaceID, projectID, issueErr := resourceRepo.IssueProject(ctx, filter.IssueID)
		if issueErr != nil {
			if errors.Is(issueErr, ErrMigrationRequired) {
				return PermissionReportResult{}, issueErr
			}
			return PermissionReportResult{}, ErrNoProjectAccess
		}
		if workspaceID != subject.WorkspaceID {
			return PermissionReportResult{}, ErrNoProjectAccess
		}
		if filter.ProjectID == "" {
			filter.ProjectID = projectID
		} else if filter.ProjectID != projectID {
			return PermissionReportResult{}, ErrCrossWorkspace
		}
	}
	fullWorkspaceReport := role == WorkspaceOwner
	if role == WorkspaceOwner {
		if bypassRepo, ok := s.repo.(WorkspaceOwnerBypassReader); ok {
			fullWorkspaceReport, err = bypassRepo.WorkspaceOwnerBypassEnabled(ctx, subject.WorkspaceID)
			if err != nil {
				return PermissionReportResult{}, ErrStorageUnavailable
			}
		}
	}
	canManageProject := false
	if filter.ProjectID != "" {
		canManageProject = s.Check(ctx, subject, filter.ProjectID, SettingsManage) == nil
	}
	canManageIssue := false
	if filter.IssueID != "" {
		if effectiveRepo, ok := s.repo.(EffectiveAccessRepository); ok {
			canManageIssue = NewEffectiveAccessResolver(effectiveRepo).CanIssue(ctx, subject, filter.IssueID, IssueManage) == nil
		}
	}
	if !fullWorkspaceReport && !canManageProject && !canManageIssue {
		// Ordinary users can inspect only their own effective access. This keeps
		// the dashboard useful without disclosing restricted-resource membership.
		if filter.UserID != "" && filter.UserID != subject.UserID {
			return PermissionReportResult{}, ErrForbidden
		}
		filter.UserID = subject.UserID
	}
	return rr.ListPermissionReport(ctx, filter)
}

func validReportRole(ctx context.Context, repo Repository, workspaceID, role string) bool {
	switch role {
	// 2026-08-27 coder(lq): Workspace and project roles intentionally share
	// owner/member values, so validate their distinct wire values only once.
	case "owner", "admin", "member", "manager", "viewer":
		return true
	}
	roleRepo, ok := repo.(RoleRepository)
	if ok {
		definition, err := roleRepo.GetRoleDefinition(ctx, workspaceID, role)
		if err == nil && definition.Key != "" {
			return true
		}
	}
	taskRepo, ok := repo.(TaskRolePermissionRepository)
	if !ok {
		return false
	}
	_, found, err := taskRepo.TaskRolePermissions(ctx, workspaceID, TaskRole(role))
	return err == nil && found
}

func validReportPermission(permission Permission) bool {
	switch permission {
	case View, Edit, IssueCreate, IssueComment, IssueManage, IssueArchive, AgentUse, IssueChildCreate, MemberManage, SettingsManage:
		return true
	default:
		return false
	}
}
