package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/util"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// projectAuthRepository is the only Handler-side adapter for projectauth.
// Keeping SQL here means the permission package remains independent of sqlc
// generated code and upstream handler structure.
type projectAuthRepository struct{ db dbExecutor }

var _ projectauth.EffectiveAccessRepository = (*projectAuthRepository)(nil)

var projectPermissionValues = []string{"project.view", "project.edit", "project.issue.create", "project.issue.comment", "project.issue.manage", "project.issue.archive", "project.agent.use", "project.issue.child.create", "project.member.manage", "project.settings.manage"}

func (r *projectAuthRepository) RecordAuthorizationAudit(ctx context.Context, event projectauth.AuthorizationAuditEvent) error {
	details, err := json.Marshal(event.Details)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(ctx, `
		INSERT INTO activity_log (workspace_id, issue_id, actor_type, actor_id, action, details)
		VALUES ($1, NULLIF($2, '')::uuid, 'member', NULLIF($3, '')::uuid, $4, $5::jsonb)`,
		event.WorkspaceID, event.IssueID, event.ActorUserID, event.Action, details)
	if err != nil {
		// 2026-09-05 coder(lq): Surface the underlying audit insert failure;
		// the service deliberately maps storage errors to a stable 503 response.
		slog.Error("project permission revoke audit failed",
			"workspace_id", event.WorkspaceID,
			"project_id", event.ProjectID,
			"issue_id", event.IssueID,
			"action", event.Action,
			"sqlstate", projectPermissionSQLState(err),
			"error", err,
		)
	}
	return err
}

func newProjectAuthRepository(db dbExecutor) projectauth.Repository {
	if db == nil {
		return nil
	}
	return &projectAuthRepository{db: db}
}

func (r *projectAuthRepository) WorkspaceRole(ctx context.Context, workspaceID, userID string) (projectauth.WorkspaceRole, error) {
	var role string
	err := r.db.QueryRow(ctx, `SELECT role FROM member WHERE workspace_id = $1 AND user_id = $2`, workspaceID, userID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", projectauth.ErrNotWorkspaceMember
	}
	return projectauth.WorkspaceRole(role), wrapProjectPermissionRepositoryError(err)
}

func (r *projectAuthRepository) ProjectCreator(ctx context.Context, projectID string) (string, error) {
	var creator string
	err := r.db.QueryRow(ctx, `
		SELECT COALESCE(created_by::text, '')
		FROM project
		WHERE id = $1`, projectID).Scan(&creator)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", projectauth.ErrNoProjectAccess
	}
	return creator, wrapProjectPermissionRepositoryError(err)
}

// UserInWorkspace and ActiveOrganizationInWorkspace are deliberately narrow
// directory queries. They let the provider-neutral authorization service
// reject stale/cross-workspace subjects without coupling it to an OA API.
// 2026-09-01 coder(lq): Add subject existence checks at the persistence seam.
func (r *projectAuthRepository) UserInWorkspace(ctx context.Context, workspaceID, userID string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM member WHERE workspace_id=$1 AND user_id=$2)`, workspaceID, userID).Scan(&exists)
	return exists, wrapProjectPermissionRepositoryError(err)
}

func (r *projectAuthRepository) ActiveOrganizationInWorkspace(ctx context.Context, workspaceID, organizationID string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projectauth_organizations WHERE workspace_id=$1 AND id=$2::uuid AND status='active')`, workspaceID, organizationID).Scan(&exists)
	if err != nil && projectPermissionSchemaMissing(err) {
		return false, wrapProjectPermissionRepositoryError(err)
	}
	return exists, err
}

// WorkspaceOwnerBypassEnabled reads the deployment-level project permission
// switch from the process environment. Workspace settings no longer own this
// decision, which keeps the toggle out of the editable page state.
func (r *projectAuthRepository) WorkspaceOwnerBypassEnabled(ctx context.Context, workspaceID string) (bool, error) {
	_ = ctx
	_ = workspaceID
	return projectauth.WorkspaceOwnerBypassEnabledFromEnvironment(), nil
}

// IssueAccessResource loads every resource binding needed by the effective
// access algorithm in one snapshot. Related workspace IDs are returned to the
// domain layer so inconsistent cross-workspace rows fail closed there.
func (r *projectAuthRepository) IssueAccessResource(ctx context.Context, workspaceID, issueID string) (projectauth.IssueAccessResource, error) {
	if r == nil || r.db == nil {
		return projectauth.IssueAccessResource{}, projectauth.ErrStorageUnavailable
	}
	var resource projectauth.IssueAccessResource
	var creatorType string
	var originType pgtype.Text
	var originID pgtype.UUID
	err := r.db.QueryRow(ctx, `
		SELECT i.workspace_id::text, i.id::text,
		       COALESCE(i.project_id::text, ''), COALESCE(p.workspace_id::text, ''),
		       COALESCE(i.parent_issue_id::text, ''), COALESCE(parent.workspace_id::text, ''),
		       CASE
		         WHEN i.creator_type='member' THEN COALESCE(i.creator_id::text, '')
		         WHEN i.creator_type='agent' AND creator_agent.kind='user' THEN COALESCE(creator_agent.owner_id::text, '')
		         ELSE ''
		       END,
		       CASE
		         WHEN i.assignee_type='member' THEN COALESCE(i.assignee_id::text, '')
		         WHEN i.assignee_type='agent' AND assignee_agent.kind='user' THEN COALESCE(assignee_agent.owner_id::text, '')
		         ELSE ''
		       END,
		       i.creator_type, i.origin_type, i.origin_id,
		       COALESCE(policy.project_access_mode, 'inherit'), COALESCE(policy.policy_version, 1)
		FROM issue i
		LEFT JOIN project p ON p.id=i.project_id
		LEFT JOIN issue parent ON parent.id=i.parent_issue_id
		LEFT JOIN agent creator_agent
		  ON creator_agent.id=i.creator_id AND creator_agent.workspace_id=i.workspace_id AND creator_agent.kind='user'
		LEFT JOIN agent assignee_agent
		  ON assignee_agent.id=i.assignee_id AND assignee_agent.workspace_id=i.workspace_id AND assignee_agent.kind='user'
		LEFT JOIN projectauth_issue_policies policy
		  ON policy.workspace_id=i.workspace_id AND policy.issue_id=i.id
		WHERE i.workspace_id=$1::uuid AND i.id=$2::uuid`, workspaceID, issueID).
		Scan(&resource.WorkspaceID, &resource.IssueID, &resource.ProjectID, &resource.ProjectWorkspaceID,
			&resource.ParentIssueID, &resource.ParentWorkspaceID, &resource.CreatorUserID, &resource.AssigneeUserID,
			&creatorType, &originType, &originID, &resource.ProjectAccessMode, &resource.PolicyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return projectauth.IssueAccessResource{}, projectauth.ErrNoProjectAccess
	}
	if err != nil {
		return projectauth.IssueAccessResource{}, wrapProjectPermissionRepositoryError(err)
	}
	workspaceUUID, err := util.ParseUUID(resource.WorkspaceID)
	if err != nil {
		return projectauth.IssueAccessResource{}, projectauth.ErrCrossWorkspace
	}
	resource.OriginatorUserID, err = resolveDelegatedIssueMemberWithExecutor(ctx, r.db, workspaceUUID, creatorType, originType, originID)
	if err != nil {
		return projectauth.IssueAccessResource{}, wrapProjectPermissionRepositoryError(err)
	}
	return resource, nil
}

// ListIssueAccessGrants returns only task-scoped rows for one task. Project
// rows are loaded independently and projected by the domain resolver.
func (r *projectAuthRepository) ListIssueAccessGrants(ctx context.Context, workspaceID, issueID string) ([]projectauth.AccessGrant, error) {
	var projectID string
	err := r.db.QueryRow(ctx, `
		SELECT COALESCE(project_id::text, '') FROM issue
		WHERE workspace_id=$1::uuid AND id=$2::uuid`, workspaceID, issueID).Scan(&projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, projectauth.ErrNoProjectAccess
	}
	if err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}

	table := "projectauth_access_grants"
	projectColumn := "g.project_id::text"
	permissionColumn := "COALESCE(g.permission, '')"
	projectPredicate := "AND g.project_id=$3::uuid"
	args := []any{workspaceID, issueID, projectID}
	if projectID == "" {
		table = "projectauth_issue_access_grants"
		projectColumn = "''"
		permissionColumn = "''"
		projectPredicate = ""
		args = args[:2]
	}
	query := fmt.Sprintf(`
		SELECT g.id::text, g.workspace_id::text, %s, g.issue_id::text,
		       g.subject_type, COALESCE(g.subject_id, ''), COALESCE(g.role_key, ''),
		       %s, g.source, COALESCE(g.granted_by::text, ''), g.created_at::text,
		       c.expires_at,
		       COALESCE(c.origin_kind, CASE WHEN g.source='system' THEN 'system' ELSE 'manual' END),
		       COALESCE(c.origin_id::text, '')
		FROM %s g
		LEFT JOIN projectauth_grant_constraints c
		  ON c.workspace_id=g.workspace_id AND c.grant_id=g.id
		WHERE g.workspace_id=$1::uuid AND g.issue_id=$2::uuid %s
		ORDER BY g.created_at, g.id`, projectColumn, permissionColumn, table, projectPredicate)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	defer rows.Close()
	return scanScopedAccessGrants(rows, projectauth.RoleScopeTask)
}

func (r *projectAuthRepository) ListProjectAccessGrants(ctx context.Context, workspaceID, projectID string) ([]projectauth.AccessGrant, error) {
	grants, err := r.ListAccessGrants(ctx, workspaceID, projectID, "")
	if err != nil {
		return nil, err
	}
	for _, grant := range grants {
		if grant.Scope != projectauth.RoleScopeProject || grant.IssueID != "" {
			return nil, projectauth.ErrInvalidRoleScope
		}
	}
	return grants, nil
}

func scanScopedAccessGrants(rows pgx.Rows, scope projectauth.RoleScope) ([]projectauth.AccessGrant, error) {
	grants := make([]projectauth.AccessGrant, 0)
	for rows.Next() {
		var grant projectauth.AccessGrant
		var roleKey, permission, grantedBy, originKind, originID string
		var expiresAt pgtype.Timestamptz
		if err := rows.Scan(&grant.ID, &grant.WorkspaceID, &grant.ProjectID, &grant.IssueID,
			&grant.SubjectType, &grant.SubjectID, &roleKey, &permission, &grant.Source, &grantedBy, &grant.CreatedAt,
			&expiresAt, &originKind, &originID); err != nil {
			return nil, wrapProjectPermissionRepositoryError(err)
		}
		grant.Role, grant.Scope, grant.Permission, grant.GrantedBy = projectauth.RoleKey(roleKey), scope, projectauth.Permission(permission), grantedBy
		grant.OriginKind, grant.OriginID = originKind, originID
		if expiresAt.Valid {
			expires := expiresAt.Time
			grant.ExpiresAt = &expires
		}
		if err := grant.ValidateRoleScope(); err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	return grants, nil
}

func (r *projectAuthRepository) ProjectRole(ctx context.Context, projectID, userID string) (projectauth.ProjectRole, error) {
	var role string
	err := r.db.QueryRow(ctx, `
		SELECT CASE WHEN EXISTS (
			SELECT 1
			FROM project p
			WHERE p.id=$1
			  AND p.created_by=$2::uuid
			  AND EXISTS (
				SELECT 1
				FROM member m
				WHERE m.workspace_id = p.workspace_id
				  AND m.user_id = p.created_by
			  )
		) THEN 'owner'
		ELSE COALESCE((
			SELECT role_key
			FROM projectauth_access_grants g
			JOIN project p ON p.id = g.project_id
			WHERE g.project_id=$1
			  AND g.workspace_id = p.workspace_id
			  AND g.issue_id IS NULL AND g.role_key IS NOT NULL
			  AND ((g.subject_type='user' AND g.subject_id=$2::text)
			    OR (g.subject_type='everyone' AND (g.subject_id='' OR g.subject_id=p.workspace_id::text))
			    OR (g.subject_type='organization' AND g.subject_id IN (
			        WITH RECURSIVE user_orgs(organization_id, parent_id) AS (
			            SELECT org.id, org.parent_id
			            FROM projectauth_organization_members om
			            JOIN projectauth_organizations org ON org.id = om.organization_id
			            WHERE om.user_id=$2::uuid
			              AND om.workspace_id=p.workspace_id
			              AND org.workspace_id=p.workspace_id
			              AND org.status = 'active'
			            UNION
			            SELECT parent.id, parent.parent_id
			            FROM user_orgs child
			            JOIN projectauth_organizations parent ON parent.id = child.parent_id
			              WHERE parent.workspace_id=p.workspace_id
			              AND parent.status = 'active'
			        )
			        SELECT organization_id::text FROM user_orgs
			    )))
			ORDER BY CASE role_key WHEN 'owner' THEN 4 WHEN 'manager' THEN 3 WHEN 'member' THEN 2 WHEN 'viewer' THEN 1 ELSE 0 END DESC
			LIMIT 1
		), '') END`, projectID, userID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", projectauth.ErrNoProjectAccess
	}
	if err == nil && role == "" {
		return "", projectauth.ErrNoProjectAccess
	}
	return projectauth.ProjectRole(role), wrapProjectPermissionRepositoryError(err)
}

func (r *projectAuthRepository) IssuePermission(ctx context.Context, issueID, userID string, permission projectauth.Permission) (bool, error) {
	// 2026-09-05 coder(lq): Resolve the nullable project binding first. The
	// historical IssueProject helper intentionally rejects projectless tasks,
	// but this compatibility reader must still see a task-level @ grant stored
	// in projectauth_issue_access_grants.
	if r == nil || r.db == nil {
		return false, projectauth.ErrStorageUnavailable
	}
	var workspaceID, projectID string
	err := r.db.QueryRow(ctx, `
		SELECT workspace_id::text, COALESCE(project_id::text, '')
		FROM issue
		WHERE id = $1`, issueID).Scan(&workspaceID, &projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, wrapProjectPermissionRepositoryError(err)
	}
	if projectID == "" {
		return r.projectlessIssuePermission(ctx, issueID, workspaceID, userID, permission)
	}
	return r.projectBoundIssuePermission(ctx, issueID, workspaceID, projectID, userID, permission)
}

func (r *projectAuthRepository) projectBoundIssuePermission(ctx context.Context, issueID, workspaceID, projectID, userID string, permission projectauth.Permission) (bool, error) {
	// 2026-09-05 coder(lq): Keep project-bound tasks on the canonical service
	// path so project inheritance and task-only grants remain identical to HTTP
	// authorization checks.
	workspaceRole, err := r.WorkspaceRole(ctx, workspaceID, userID)
	if err != nil {
		if errors.Is(err, projectauth.ErrNotWorkspaceMember) || errors.Is(err, projectauth.ErrNoProjectAccess) {
			return false, nil
		}
		return false, err
	}
	service := projectauth.New(r, true)
	if err := service.CheckIssue(ctx, projectauth.Subject{
		UserID:        userID,
		WorkspaceID:   workspaceID,
		WorkspaceRole: workspaceRole,
	}, issueID, projectID, permission); err != nil {
		if errors.Is(err, projectauth.ErrForbidden) ||
			errors.Is(err, projectauth.ErrNoProjectAccess) ||
			errors.Is(err, projectauth.ErrNotWorkspaceMember) ||
			errors.Is(err, projectauth.ErrCrossWorkspace) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// 2026-09-05 coder(lq): Projectless tasks have no project row from which the
// authorization service can inherit permissions. Evaluate their immutable
// creator/assignee access and the dedicated task-grant table here instead of
// treating a missing project as a missing task.
func (r *projectAuthRepository) projectlessIssuePermission(ctx context.Context, issueID, workspaceID, userID string, permission projectauth.Permission) (bool, error) {
	if !taskPermissionAllowedForCompatibility(permission) {
		return false, nil
	}
	if _, err := r.WorkspaceRole(ctx, workspaceID, userID); err != nil {
		if errors.Is(err, projectauth.ErrNotWorkspaceMember) || errors.Is(err, projectauth.ErrNoProjectAccess) {
			return false, nil
		}
		return false, err
	}

	var creatorID, assigneeID string
	err := r.db.QueryRow(ctx, `
		SELECT
			CASE
				WHEN i.creator_type = 'member' THEN i.creator_id::text
				WHEN i.creator_type = 'agent' AND creator_agent.kind = 'user' AND creator_agent.owner_id IS NOT NULL THEN creator_agent.owner_id::text
				ELSE ''
			END,
			CASE
				WHEN i.assignee_type = 'member' THEN i.assignee_id::text
				WHEN i.assignee_type = 'agent' AND assignee_agent.kind = 'user' AND assignee_agent.owner_id IS NOT NULL THEN assignee_agent.owner_id::text
				ELSE ''
			END
		FROM issue i
		LEFT JOIN agent creator_agent
		  ON creator_agent.id = i.creator_id
		 AND creator_agent.workspace_id = i.workspace_id
		 AND creator_agent.kind = 'user'
		LEFT JOIN agent assignee_agent
		  ON assignee_agent.id = i.assignee_id
		 AND assignee_agent.workspace_id = i.workspace_id
		 AND assignee_agent.kind = 'user'
		WHERE i.id = $1 AND i.workspace_id = $2 AND i.project_id IS NULL`, issueID, workspaceID).Scan(&creatorID, &assigneeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, wrapProjectPermissionRepositoryError(err)
	}
	if userID == creatorID || userID == assigneeID {
		return true, nil
	}

	ownerBypass, err := r.WorkspaceOwnerBypassEnabled(ctx, workspaceID)
	if err != nil {
		return false, err
	}
	if ownerBypass {
		var isOwner bool
		if err := r.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM member WHERE workspace_id=$1 AND user_id=$2 AND role='owner')`, workspaceID, userID).Scan(&isOwner); err != nil {
			return false, wrapProjectPermissionRepositoryError(err)
		}
		if isOwner {
			return true, nil
		}
	}

	var allowed bool
	err = r.db.QueryRow(ctx, `
		WITH RECURSIVE user_orgs(organization_id, parent_id) AS (
			SELECT org.id, org.parent_id
			FROM projectauth_organization_members om
			JOIN projectauth_organizations org
			  ON org.id = om.organization_id
			 AND org.workspace_id = $1
			 AND org.status = 'active'
			WHERE om.workspace_id = $1 AND om.user_id = $3::uuid
			UNION
			SELECT parent.id, parent.parent_id
			FROM user_orgs child
			JOIN projectauth_organizations parent
			  ON parent.id = child.parent_id
			 AND parent.workspace_id = $1
			 AND parent.status = 'active'
		)
		SELECT EXISTS (
			SELECT 1
			FROM projectauth_issue_access_grants g
			WHERE g.workspace_id = $1
			  AND g.issue_id = $2::uuid
			  AND (
				(g.subject_type = 'user' AND g.subject_id = $3::text)
				OR (g.subject_type = 'everyone' AND (g.subject_id = '' OR g.subject_id = $1::text))
				OR (g.subject_type = 'organization' AND g.subject_id IN (SELECT organization_id::text FROM user_orgs))
			  )
			  AND (
				EXISTS (
					SELECT 1
					FROM projectauth_task_roles rr
					JOIN projectauth_task_role_permissions rp ON rp.role_id = rr.id
					WHERE rr.workspace_id = g.workspace_id
					  AND rr.role_key = g.role_key
					  AND rp.permission = $4
				)
				OR (
					g.role_key IN ('owner', 'manager', 'member', 'viewer')
					AND NOT EXISTS (
						SELECT 1 FROM projectauth_task_roles rr
						WHERE rr.workspace_id = g.workspace_id AND rr.role_key = g.role_key
					)
					AND (
						$4 = 'project.view'
						OR ($4 IN ('project.edit', 'project.issue.comment', 'project.issue.child.create') AND g.role_key IN ('owner', 'manager', 'member'))
						OR ($4 IN ('project.issue.archive', 'project.agent.use') AND g.role_key IN ('owner', 'manager'))
						OR ($4 = 'project.issue.manage' AND g.role_key IN ('owner', 'manager'))
					)
				)
			  )
		)`, workspaceID, issueID, userID, string(permission)).Scan(&allowed)
	if err != nil {
		return false, wrapProjectPermissionRepositoryError(err)
	}
	return allowed, nil
}

func taskPermissionAllowedForCompatibility(permission projectauth.Permission) bool {
	switch permission {
	case projectauth.View, projectauth.Edit, projectauth.IssueComment, projectauth.IssueManage, projectauth.IssueArchive, projectauth.AgentUse, projectauth.IssueChildCreate:
		return true
	default:
		return false
	}
}

// 2026-08-31 coder(lq): Unified grant reads are kept in this adapter so the
// projectauth package remains independent of PostgreSQL and generated models.
func (r *projectAuthRepository) ListAccessGrants(ctx context.Context, workspaceID, projectID, issueID string) ([]projectauth.AccessGrant, error) {
	query := `
		SELECT g.id::text, g.workspace_id::text, g.project_id::text, COALESCE(g.issue_id::text, ''),
		       subject_type, COALESCE(subject_id, ''), COALESCE(role_key, ''),
		       COALESCE(permission, ''), source, COALESCE(granted_by::text, ''), g.created_at::text,
		       c.expires_at, COALESCE(c.origin_kind, ''), COALESCE(c.origin_id::text, '')
		FROM projectauth_access_grants g
		LEFT JOIN projectauth_grant_constraints c
		  ON c.workspace_id = g.workspace_id AND c.grant_id = g.id
		WHERE g.workspace_id = $1 AND g.project_id = $2 AND (($3 = '' AND g.issue_id IS NULL) OR ($3 <> '' AND (g.issue_id IS NULL OR g.issue_id = $3::uuid)))
		ORDER BY g.created_at, g.id`
	rows, err := r.db.Query(ctx, query, workspaceID, projectID, issueID)
	if err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	grants := make([]projectauth.AccessGrant, 0)
	for rows.Next() {
		var grant projectauth.AccessGrant
		var issueID, roleKey, permission, grantedBy, originKind, originID string
		var expiresAt pgtype.Timestamptz
		if err := rows.Scan(&grant.ID, &grant.WorkspaceID, &grant.ProjectID, &issueID,
			&grant.SubjectType, &grant.SubjectID, &roleKey, &permission, &grant.Source, &grantedBy, &grant.CreatedAt,
			&expiresAt, &originKind, &originID); err != nil {
			return nil, wrapProjectPermissionRepositoryError(err)
		}
		grant.IssueID, grant.Role, grant.Permission, grant.GrantedBy = issueID, projectauth.RoleKey(roleKey), projectauth.Permission(permission), grantedBy
		if expiresAt.Valid {
			expires := expiresAt.Time
			grant.ExpiresAt = &expires
		}
		grant.OriginKind, grant.OriginID = originKind, originID
		if err := grant.NormalizeRoleScope(); err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	rows.Close()
	// 2026-09-05 coder(lq): Project and task creators have immutable Owner
	// access even when the deployment has not run either creator backfill
	// migration. Return read-only virtual rows for both scopes so the dialogs
	// accurately describe effective access without mutating data during GET.
	var projectCreatorID, projectCreatedAt string
	err = r.db.QueryRow(ctx, `
		SELECT CASE WHEN EXISTS (
			SELECT 1
			FROM member m
			WHERE m.workspace_id = p.workspace_id
			  AND m.user_id = p.created_by
		) THEN COALESCE(p.created_by::text, '') ELSE '' END,
			COALESCE(p.created_at::text, '')
		FROM project p
		WHERE p.id = $1 AND p.workspace_id = $2`, projectID, workspaceID).Scan(&projectCreatorID, &projectCreatedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	if projectCreatorID != "" {
		projectCreatorOwnerExists := false
		for _, grant := range grants {
			if grant.Scope == projectauth.RoleScopeProject && grant.IssueID == "" && grant.SubjectType == projectauth.SubjectUser && grant.SubjectID == projectCreatorID && projectauth.ProjectRole(grant.Role) == projectauth.ProjectOwner {
				projectCreatorOwnerExists = true
				break
			}
		}
		if !projectCreatorOwnerExists {
			grants = append(grants, projectauth.AccessGrant{
				ID:          "creator-owner-" + projectID + "-" + projectCreatorID,
				WorkspaceID: workspaceID,
				ProjectID:   projectID,
				SubjectType: projectauth.SubjectUser,
				SubjectID:   projectCreatorID,
				Role:        projectauth.RoleKey(projectauth.ProjectOwner),
				Scope:       projectauth.RoleScopeProject,
				Source:      projectauth.GrantSourceSystem,
				CreatedAt:   projectCreatedAt,
			})
		}
	}
	if issueID != "" {
		var issueCreatorID, issueCreatedAt string
		err = r.db.QueryRow(ctx, `
			SELECT CASE
				WHEN EXISTS (
					SELECT 1
					FROM member m
					WHERE m.workspace_id = i.workspace_id
					  AND m.user_id = CASE
						WHEN i.creator_type = 'member' THEN i.creator_id
						WHEN i.creator_type = 'agent' AND a.kind = 'user' THEN a.owner_id
						ELSE NULL
					  END
				) THEN CASE
					WHEN i.creator_type = 'member' THEN COALESCE(i.creator_id::text, '')
					WHEN i.creator_type = 'agent' AND a.kind = 'user' THEN COALESCE(a.owner_id::text, '')
					ELSE ''
				END
				ELSE ''
			END, COALESCE(i.created_at::text, '')
			FROM issue i
			LEFT JOIN agent a
			  ON a.id = i.creator_id
			 AND a.workspace_id = i.workspace_id
			 AND a.kind = 'user'
			WHERE i.id = $1::uuid
			  AND i.workspace_id = $2
			  AND i.project_id = $3`, issueID, workspaceID, projectID).Scan(&issueCreatorID, &issueCreatedAt)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, wrapProjectPermissionRepositoryError(err)
		}
		// Project ownership and task creator ownership are separate sources even
		// when the same user holds both same-named roles.
		if issueCreatorID != "" {
			issueCreatorOwnerExists := false
			for _, grant := range grants {
				if grant.Scope == projectauth.RoleScopeTask && grant.IssueID == issueID && grant.SubjectType == projectauth.SubjectUser && grant.SubjectID == issueCreatorID && projectauth.TaskRole(grant.Role) == projectauth.TaskOwner {
					issueCreatorOwnerExists = true
					break
				}
			}
			if !issueCreatorOwnerExists {
				grants = append(grants, projectauth.AccessGrant{
					ID:          "creator-owner-" + issueID + "-" + issueCreatorID,
					WorkspaceID: workspaceID,
					ProjectID:   projectID,
					IssueID:     issueID,
					SubjectType: projectauth.SubjectUser,
					SubjectID:   issueCreatorID,
					Role:        projectauth.RoleKey(projectauth.TaskOwner),
					Scope:       projectauth.RoleScopeTask,
					Source:      projectauth.GrantSourceSystem,
					CreatedAt:   issueCreatedAt,
				})
			}
		}
	}
	return grants, nil
}

// GetAccessGrant reads the canonical row after an upsert so callers receive
// generated IDs and normalized source/actor fields in the POST response.
// 2026-08-31 coder(lq): Keep read-after-write in the PostgreSQL adapter; the
// projectauth package remains storage-neutral.
func (r *projectAuthRepository) GetAccessGrant(ctx context.Context, workspaceID, projectID, issueID string,
	subjectType projectauth.SubjectType, subjectID string, role projectauth.RoleKey, permission projectauth.Permission) (projectauth.AccessGrant, error) {
	var grant projectauth.AccessGrant
	var issue, roleKey, permissionKey, source, grantedBy string
	err := r.db.QueryRow(ctx, `
		SELECT g.id::text, g.workspace_id::text, g.project_id::text, COALESCE(g.issue_id::text, ''),
		       g.subject_type, COALESCE(g.subject_id, ''), COALESCE(g.role_key, ''),
		       COALESCE(g.permission, ''), g.source, COALESCE(g.granted_by::text, ''), g.created_at::text,
		       constraint_row.expires_at, COALESCE(constraint_row.origin_kind, ''), COALESCE(constraint_row.origin_id::text, '')
		FROM projectauth_access_grants g
		LEFT JOIN projectauth_grant_constraints constraint_row
		  ON constraint_row.workspace_id=g.workspace_id AND constraint_row.grant_id=g.id
		WHERE g.workspace_id=$1 AND g.project_id=$2
		  AND g.issue_id IS NOT DISTINCT FROM NULLIF($3,'')::uuid
		  AND g.subject_type=$4 AND COALESCE(g.subject_id, '') = COALESCE($5, '')
		  AND g.role_key IS NOT DISTINCT FROM NULLIF($6,'')
		  AND g.permission IS NOT DISTINCT FROM NULLIF($7,'')
		LIMIT 1`, workspaceID, projectID, issueID, string(subjectType), subjectID, string(role), string(permission)).
		Scan(&grant.ID, &grant.WorkspaceID, &grant.ProjectID, &issue, &grant.SubjectType, &grant.SubjectID,
			&roleKey, &permissionKey, &source, &grantedBy, &grant.CreatedAt,
			&grant.ExpiresAt, &grant.OriginKind, &grant.OriginID)
	if err != nil {
		return projectauth.AccessGrant{}, wrapProjectPermissionRepositoryError(err)
	}
	grant.IssueID = issue
	grant.Role = projectauth.RoleKey(roleKey)
	grant.Permission = projectauth.Permission(permissionKey)
	grant.Source = projectauth.GrantSource(source)
	grant.GrantedBy = grantedBy
	if err := grant.NormalizeRoleScope(); err != nil {
		return projectauth.AccessGrant{}, err
	}
	return grant, nil
}

func (r *projectAuthRepository) ListUserOrganizations(ctx context.Context, workspaceID, userID string) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		-- 2026-09-03 coder(lq): A user's effective organization set includes
		-- every active ancestor, so a grant on a parent department is inherited
		-- by members of all descendant departments. UNION (rather than UNION ALL)
		-- also makes malformed parent cycles terminate safely.
		WITH RECURSIVE user_orgs(organization_id, parent_id) AS (
			SELECT org.id, org.parent_id
			FROM projectauth_organization_members om
			JOIN projectauth_organizations org ON org.id = om.organization_id
			WHERE om.workspace_id = $1 AND om.user_id = $2
			  AND org.workspace_id = $1 AND org.status = 'active'
			UNION
			SELECT parent.id, parent.parent_id
			FROM user_orgs child
			JOIN projectauth_organizations parent ON parent.id = child.parent_id
			WHERE parent.workspace_id = $1 AND parent.status = 'active'
		)
		SELECT organization_id::text FROM user_orgs`, workspaceID, userID)
	if err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	defer rows.Close()
	organizations := make([]string, 0)
	for rows.Next() {
		var organizationID string
		if err := rows.Scan(&organizationID); err != nil {
			return nil, wrapProjectPermissionRepositoryError(err)
		}
		organizations = append(organizations, organizationID)
	}
	return organizations, wrapProjectPermissionRepositoryError(rows.Err())
}

// ListOrganizations reads only the provider-neutral directory snapshot. The
// sync workers own provider API calls; HTTP authorization requests stay local
// and deterministic. 2026-09-01 coder(lq): Add organization picker query.
func (r *projectAuthRepository) ListOrganizations(ctx context.Context, workspaceID string) ([]projectauth.Organization, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id::text, workspace_id::text, provider, external_id,
		       name, COALESCE(parent_id::text, ''), status
		FROM projectauth_organizations
		WHERE workspace_id = $1 AND status = 'active'
		ORDER BY name, provider, external_id`, workspaceID)
	if err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	defer rows.Close()
	organizations := make([]projectauth.Organization, 0)
	for rows.Next() {
		var organization projectauth.Organization
		if err := rows.Scan(&organization.ID, &organization.WorkspaceID, &organization.Provider,
			&organization.ExternalID, &organization.Name, &organization.ParentID, &organization.Status); err != nil {
			return nil, wrapProjectPermissionRepositoryError(err)
		}
		organizations = append(organizations, organization)
	}
	return organizations, wrapProjectPermissionRepositoryError(rows.Err())
}

// ListOrganizationMembers joins synchronized directory memberships to native
// workspace users. Only active departments and current workspace members are
// returned, keeping the browser consistent with authorization evaluation.
// 2026-09-03 coder(lq): Serve the department-tree employee list locally.
func (r *projectAuthRepository) ListOrganizationMembers(ctx context.Context, workspaceID string) ([]projectauth.OrganizationMember, error) {
	rows, err := r.db.Query(ctx, `
		SELECT om.organization_id::text, om.user_id::text,
		       COALESCE(u.name, ''), COALESCE(u.email, ''),
		       COALESCE(u.avatar_url, ''), m.role,
		       -- 2026-09-06 coder(lq): Preserve the legacy authenticated-user
		       -- signal carried by workspace owner/admin roles.
		       (l.user_id IS NOT NULL OR u.onboarded_at IS NOT NULL OR m.role IN ('owner', 'admin')) AS has_logged_in
		FROM projectauth_organization_members om
		JOIN projectauth_organizations o
		  ON o.id = om.organization_id
		 AND o.workspace_id = om.workspace_id
		 AND o.status = 'active'
		JOIN member m
		  ON m.workspace_id = om.workspace_id
		 AND m.user_id = om.user_id
		JOIN "user" u ON u.id = om.user_id
		LEFT JOIN projectauth_user_logins l ON l.user_id = om.user_id
		WHERE om.workspace_id = $1
		ORDER BY u.name, u.email, om.organization_id`, workspaceID)
	if err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	defer rows.Close()
	members := make([]projectauth.OrganizationMember, 0)
	for rows.Next() {
		var member projectauth.OrganizationMember
		if err := rows.Scan(&member.OrganizationID, &member.UserID, &member.Name,
			&member.Email, &member.AvatarURL, &member.WorkspaceRole, &member.HasLoggedIn); err != nil {
			return nil, wrapProjectPermissionRepositoryError(err)
		}
		members = append(members, member)
	}
	return members, wrapProjectPermissionRepositoryError(rows.Err())
}

// 2026-09-06 coder(lq): Record only successful interactive logins. The
// unique user row is updated in place so repeated sign-ins remain cheap and
// the directory can expose a stable boolean without exposing timestamps.
func (r *projectAuthRepository) RecordUserLogin(ctx context.Context, userID string) error {
	if r == nil || r.db == nil {
		return errors.New("projectauth login repository is unavailable")
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO projectauth_user_logins (user_id, last_logged_in_at)
		VALUES ($1::uuid, now())
		ON CONFLICT (user_id) DO UPDATE SET last_logged_in_at = EXCLUDED.last_logged_in_at`, userID)
	return wrapProjectPermissionRepositoryError(err)
}

func (r *projectAuthRepository) UpsertAccessGrant(ctx context.Context, grant projectauth.AccessGrant) error {
	if err := grant.NormalizeRoleScope(); err != nil {
		return err
	}
	if grant.WorkspaceID == "" && grant.ProjectID != "" {
		workspaceID, err := r.ProjectWorkspace(ctx, grant.ProjectID)
		if err != nil {
			return err
		}
		grant.WorkspaceID = workspaceID
	}
	// 2026-09-05 coder(lq): Keep creator Owner immutable at the final
	// persistence seam. Service methods and compatibility adapters already
	// normalize this role, but direct repository callers must not be able to
	// downgrade a project/task creator to Member or Viewer.
	isOwnerRole := (grant.Scope == projectauth.RoleScopeProject && projectauth.ProjectRole(grant.Role) == projectauth.ProjectOwner) ||
		(grant.Scope == projectauth.RoleScopeTask && projectauth.TaskRole(grant.Role) == projectauth.TaskOwner)
	if grant.SubjectType == projectauth.SubjectUser && grant.Permission == "" && !isOwnerRole {
		creatorID := ""
		var err error
		if grant.IssueID != "" {
			creatorID, err = r.IssueCreator(ctx, grant.IssueID)
		} else if grant.ProjectID != "" {
			creatorID, err = r.ProjectCreator(ctx, grant.ProjectID)
		}
		if err != nil {
			return err
		}
		if creatorID != "" && creatorID == grant.SubjectID {
			if grant.Scope == projectauth.RoleScopeTask {
				grant.Role = projectauth.RoleKey(projectauth.TaskOwner)
			} else {
				grant.Role = projectauth.RoleKey(projectauth.ProjectOwner)
			}
		}
	}
	// 2026-09-05 coder(lq): The project/task uniqueness indexes are partial
	// expression indexes, so PostgreSQL cannot infer them for a bare
	// "ON CONFLICT DO UPDATE". Keep the write idempotent with a conflict-safe
	// insert followed by a key-based metadata update; both statements run in
	// the caller's transaction.
	_, err := r.db.Exec(ctx, `
		INSERT INTO projectauth_access_grants
			(workspace_id, project_id, issue_id, subject_type, subject_id, role_key, permission, source, granted_by)
		VALUES ($1,$2,NULLIF($3,'')::uuid,$4,COALESCE($5,''),NULLIF($6,''),NULLIF($7,''),$8,NULLIF($9,'')::uuid)
		ON CONFLICT DO NOTHING`,
		grant.WorkspaceID, grant.ProjectID, grant.IssueID, string(grant.SubjectType), grant.SubjectID,
		string(grant.Role), string(grant.Permission), string(grant.Source), grant.GrantedBy)
	if err != nil {
		return wrapProjectPermissionRepositoryError(err)
	}
	_, err = r.db.Exec(ctx, `
		UPDATE projectauth_access_grants
		SET source=$8, granted_by=NULLIF($9,'')::uuid, updated_at=now()
		WHERE workspace_id=$1 AND project_id=$2
		  AND issue_id IS NOT DISTINCT FROM NULLIF($3,'')::uuid
		  AND subject_type=$4 AND COALESCE(subject_id,'')=COALESCE($5,'')
		  AND role_key IS NOT DISTINCT FROM NULLIF($6,'')
		  AND permission IS NOT DISTINCT FROM NULLIF($7,'')`,
		grant.WorkspaceID, grant.ProjectID, grant.IssueID, string(grant.SubjectType), grant.SubjectID,
		string(grant.Role), string(grant.Permission), string(grant.Source), grant.GrantedBy)
	if err != nil {
		return wrapProjectPermissionRepositoryError(err)
	}
	persisted, err := r.GetAccessGrant(ctx, grant.WorkspaceID, grant.ProjectID, grant.IssueID,
		grant.SubjectType, grant.SubjectID, grant.Role, grant.Permission)
	if err != nil {
		return err
	}
	return persistGrantConstraint(ctx, r.db, grant.WorkspaceID, persisted.ID, grant.ExpiresAt, grant.OriginKind, grant.OriginID)
}

func persistGrantConstraint(ctx context.Context, executor dbExecutor, workspaceID, grantID string, expiresAt *time.Time, originKind, originID string) error {
	if expiresAt == nil && originKind == "" && originID == "" {
		_, err := executor.Exec(ctx, `DELETE FROM projectauth_grant_constraints WHERE workspace_id=$1 AND grant_id=$2`, workspaceID, grantID)
		return wrapProjectPermissionRepositoryError(err)
	}
	if originKind == "" {
		originKind = "manual"
	}
	_, err := executor.Exec(ctx, `
		INSERT INTO projectauth_grant_constraints (workspace_id, grant_id, expires_at, origin_kind, origin_id)
		VALUES ($1,$2,$3,$4,NULLIF($5,'')::uuid)
		ON CONFLICT (workspace_id, grant_id) DO UPDATE
		SET expires_at=EXCLUDED.expires_at, origin_kind=EXCLUDED.origin_kind,
		    origin_id=EXCLUDED.origin_id, updated_at=now()`, workspaceID, grantID, expiresAt, originKind, originID)
	return wrapProjectPermissionRepositoryError(err)
}

func (r *projectAuthRepository) DeleteAccessGrant(ctx context.Context, workspaceID, projectID, issueID string, subjectType projectauth.SubjectType, subjectID string, role projectauth.RoleKey, permission projectauth.Permission) error {
	_, err := r.db.Exec(ctx, `
		WITH project_lock AS (
			SELECT pg_advisory_xact_lock(hashtextextended(($2::uuid)::text, 0))
		)
		DELETE FROM projectauth_access_grants g
		USING project p
		WHERE EXISTS (SELECT 1 FROM project_lock)
		  AND p.id = g.project_id
		  -- 2026-09-05 coder(lq): Parameter $2 is also used by the advisory
		  -- lock. Keep that parameter UUID-typed, then cast only the lock key
		  -- to text, so PostgreSQL never resolves a comparison as uuid = text.
		  AND p.workspace_id = $1::uuid
		  AND g.workspace_id=$1::uuid AND g.project_id=$2::uuid AND g.issue_id IS NOT DISTINCT FROM NULLIF($3,'')::uuid
		  AND g.subject_type=$4 AND COALESCE(g.subject_id, '') = COALESCE($5, '')
		  AND g.role_key IS NOT DISTINCT FROM NULLIF($6,'')
		  AND g.permission IS NOT DISTINCT FROM NULLIF($7,'')
		  AND (
			-- 2026-09-05 coder(lq): Task-scope creator Owner is immutable,
			-- while every other task grant is removable independently of the
			-- number of project Owners.
			(
				g.issue_id IS NOT NULL
				AND NOT (
					g.role_key = 'owner'
					AND g.subject_type = 'user'
					AND EXISTS (
						SELECT 1
						FROM issue i
						LEFT JOIN agent a
						  ON a.id = i.creator_id
						 AND a.workspace_id = i.workspace_id
						 AND a.kind = 'user'
						WHERE i.id = g.issue_id
						  AND i.project_id = g.project_id
						  AND (
							(i.creator_type = 'member' AND i.creator_id::text = g.subject_id)
							OR (i.creator_type = 'agent' AND a.owner_id IS NOT NULL AND a.owner_id::text = g.subject_id)
						  )
					)
				)
			)
			OR
			-- Project-scope non-Owner grants are always removable.
			(
				g.issue_id IS NULL
				AND g.role_key IS DISTINCT FROM 'owner'
			)
			OR
			-- A project Owner can be removed only when it is not the immutable
			-- project creator and another physical project Owner remains.
			(
				g.issue_id IS NULL
				AND g.role_key = 'owner'
				AND NOT (
					g.subject_type = 'user'
					AND p.created_by IS NOT NULL
					AND g.subject_id = p.created_by::text
				)
				AND (
					SELECT count(*)
					FROM projectauth_access_grants owners
					WHERE owners.workspace_id = g.workspace_id
					  AND owners.project_id = g.project_id
					  AND owners.issue_id IS NULL
					  AND owners.role_key = 'owner'
				) > 1
			)
		  )`, workspaceID, projectID, issueID,
		string(subjectType), subjectID, string(role), string(permission))
	if err != nil {
		// 2026-09-05 coder(lq): Preserve the database error in local logs so a
		// generic 503 can be traced to the exact revoke statement and grant key.
		slog.Error("project permission revoke delete failed",
			"workspace_id", workspaceID,
			"project_id", projectID,
			"issue_id", issueID,
			"subject_type", string(subjectType),
			"has_subject_id", strings.TrimSpace(subjectID) != "",
			"role", string(role),
			"permission", string(permission),
			"sqlstate", projectPermissionSQLState(err),
			"error", err,
		)
	}
	return wrapProjectPermissionRepositoryError(err)
}

// CurrentProjectRoles resolves project grants and the immutable creator owner
// role in one query for the project list response. Workspace-owner inheritance
// remains an access-control rule, but it is intentionally not reported as a
// project role: the table's "my role" column describes project-specific access.
// 2026-08-31 coder(lq): Keep effective workspace access separate from project
// membership metadata so workspace owners are shown as owners only when they
// are also the immutable creator or have an explicit project owner grant.
func (r *projectAuthRepository) CurrentProjectRoles(ctx context.Context, workspaceID, userID string) (map[string]projectauth.ProjectRole, error) {
	rows, err := r.db.Query(ctx, `
		SELECT p.id::text, 'owner'::text
		FROM project p
		WHERE p.workspace_id=$1
		  AND p.created_by=$2::uuid
		  AND EXISTS (
			SELECT 1
			FROM member m
			WHERE m.workspace_id = p.workspace_id
			  AND m.user_id = p.created_by
		  )

		UNION ALL

		SELECT g.project_id::text, g.role_key
		FROM projectauth_access_grants g
		JOIN project p ON p.id = g.project_id AND p.workspace_id = g.workspace_id
		WHERE g.workspace_id=$1 AND g.issue_id IS NULL AND g.role_key IS NOT NULL
		  AND (
			-- 2026-09-05 coder(lq): subject_id is stored as text while the
			-- workspace/user parameters are inferred as UUID by the first
			-- SELECT; cast them explicitly so the role metadata query cannot
			-- fail with PostgreSQL's "text = uuid" operator error.
			(g.subject_type='user' AND g.subject_id=$2::text)
			OR (g.subject_type='everyone' AND (g.subject_id='' OR g.subject_id=$1::text))
			OR (g.subject_type='organization' AND g.subject_id IN (
				WITH RECURSIVE user_orgs(organization_id, parent_id) AS (
					SELECT org.id, org.parent_id
					FROM projectauth_organization_members om
					JOIN projectauth_organizations org ON org.id = om.organization_id
					WHERE om.workspace_id=$1 AND om.user_id=$2
					  AND org.workspace_id=$1 AND org.status='active'
					UNION
					SELECT parent.id, parent.parent_id
					FROM user_orgs child
					JOIN projectauth_organizations parent ON parent.id = child.parent_id
					WHERE parent.workspace_id=$1 AND parent.status='active'
				)
				SELECT organization_id::text FROM user_orgs
			))
		  )
		ORDER BY 1`, workspaceID, userID)
	if err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	defer rows.Close()
	roles := make(map[string]projectauth.ProjectRole)
	for rows.Next() {
		var projectID string
		var role string
		if err := rows.Scan(&projectID, &role); err != nil {
			return nil, wrapProjectPermissionRepositoryError(err)
		}
		if role != "" {
			candidate := projectauth.ProjectRole(role)
			if current, exists := roles[projectID]; !exists || projectRoleRank(candidate) > projectRoleRank(current) {
				roles[projectID] = candidate
			}
		}
	}
	return roles, wrapProjectPermissionRepositoryError(rows.Err())
}

// 2026-08-31 coder(lq): A user can receive different project roles through a
// direct, organization, everyone, or legacy grant. The list column reports the
// strongest explicit role deterministically; permission-only grants remain
// role-less instead of being presented as a misleading Owner role.
func projectRoleRank(role projectauth.ProjectRole) int {
	switch role {
	case projectauth.ProjectOwner:
		return 4
	case projectauth.ProjectManager:
		return 3
	case projectauth.ProjectMember:
		return 2
	case projectauth.ProjectViewer:
		return 1
	default:
		return 0
	}
}

func (r *projectAuthRepository) RolePermissions(ctx context.Context, workspaceID string, role projectauth.ProjectRole) ([]projectauth.Permission, bool, error) {
	permissions, found, err := r.queryRolePermissions(ctx, workspaceID, role)
	if err != nil {
		return nil, false, wrapProjectPermissionRepositoryError(err)
	}
	if found || !projectauth.IsSystemRole(role) {
		return permissions, found, nil
	}
	// 2026-08-28 coder(lq): System roles are persisted workspace records. Seed
	// a role set for workspaces created after migration 439 before resolving
	// their permissions, while preserving an explicitly empty permission set.
	if err := r.ensureSystemRoleDefinitions(ctx, workspaceID); err != nil {
		return nil, false, wrapProjectPermissionRepositoryError(err)
	}
	permissions, found, err = r.queryRolePermissions(ctx, workspaceID, role)
	return permissions, found, wrapProjectPermissionRepositoryError(err)
}

// TaskRolePermissions resolves the task-specific role catalog. Keeping this
// query separate from RolePermissions prevents a project role override from
// silently changing task access for the same role key.
// 2026-09-14 coder(lq): Wire the independent LC-797 task role persistence.
func (r *projectAuthRepository) TaskRolePermissions(ctx context.Context, workspaceID string, role projectauth.TaskRole) ([]projectauth.Permission, bool, error) {
	permissions, found, err := r.queryTaskRolePermissions(ctx, workspaceID, role)
	if err != nil {
		return nil, false, wrapProjectPermissionRepositoryError(err)
	}
	if found || !projectauth.IsSystemTaskRole(role) {
		return permissions, found, nil
	}
	if err := r.ensureTaskSystemRoleDefinitions(ctx, workspaceID); err != nil {
		return nil, false, wrapProjectPermissionRepositoryError(err)
	}
	permissions, found, err = r.queryTaskRolePermissions(ctx, workspaceID, role)
	return permissions, found, wrapProjectPermissionRepositoryError(err)
}

func (r *projectAuthRepository) queryTaskRolePermissions(ctx context.Context, workspaceID string, role projectauth.TaskRole) ([]projectauth.Permission, bool, error) {
	rows, err := r.db.Query(ctx, `
		SELECT permission.permission
		FROM projectauth_task_roles role
		LEFT JOIN projectauth_task_role_permissions permission ON permission.role_id = role.id
		WHERE role.workspace_id = $1 AND role.role_key = $2
		ORDER BY permission.permission`, workspaceID, string(role))
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	permissions := make([]projectauth.Permission, 0)
	found := false
	for rows.Next() {
		var permission *string
		if err := rows.Scan(&permission); err != nil {
			return nil, false, err
		}
		found = true
		if permission != nil {
			permissions = append(permissions, projectauth.Permission(*permission))
		}
	}
	return permissions, found, wrapProjectPermissionRepositoryError(rows.Err())
}

func (r *projectAuthRepository) ensureTaskSystemRoleDefinitions(ctx context.Context, workspaceID string) error {
	_, err := r.db.Exec(ctx, `
		WITH system_roles(role_key, name) AS (
			VALUES ('owner', 'Owner'), ('manager', 'Manager'), ('member', 'Member'), ('viewer', 'Viewer')
		), upserted_roles AS (
			INSERT INTO projectauth_task_roles (workspace_id, role_key, name, is_system)
			SELECT $1, role_key, name, true FROM system_roles
			ON CONFLICT (workspace_id, role_key) DO UPDATE
			SET name = EXCLUDED.name, is_system = true, updated_at = now()
			RETURNING id, role_key
		)
		INSERT INTO projectauth_task_role_permissions (role_id, permission)
		SELECT role.id, defaults.permission
		FROM upserted_roles role
		JOIN (VALUES
			('owner','project.view'), ('owner','project.edit'), ('owner','project.issue.comment'),
			('owner','project.issue.manage'), ('owner','project.issue.archive'), ('owner','project.agent.use'),
			('owner','project.issue.child.create'), ('manager','project.view'), ('manager','project.edit'),
			('manager','project.issue.comment'), ('manager','project.issue.manage'), ('manager','project.issue.archive'),
			('manager','project.agent.use'), ('manager','project.issue.child.create'), ('member','project.view'),
			('member','project.edit'), ('member','project.issue.comment'), ('member','project.issue.child.create'),
			('viewer','project.view')
		) AS defaults(role_key, permission) ON defaults.role_key = role.role_key
		ON CONFLICT DO NOTHING`, workspaceID)
	return wrapProjectPermissionRepositoryError(err)
}

func (r *projectAuthRepository) queryRolePermissions(ctx context.Context, workspaceID string, role projectauth.ProjectRole) ([]projectauth.Permission, bool, error) {
	rows, err := r.db.Query(ctx, `
		SELECT p.permission
		FROM project_permission_roles role
		LEFT JOIN project_permission_role_permissions p ON p.role_id = role.id
		WHERE role.workspace_id = $1 AND role.role_key = $2
		ORDER BY p.permission`, workspaceID, string(role))
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	permissions := make([]projectauth.Permission, 0)
	found := false
	for rows.Next() {
		var permission *string
		if err := rows.Scan(&permission); err != nil {
			return nil, false, err
		}
		found = true
		if permission != nil {
			permissions = append(permissions, projectauth.Permission(*permission))
		}
	}
	return permissions, found, wrapProjectPermissionRepositoryError(rows.Err())
}

func projectPermissionSchemaMissing(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	// 2026-08-28 coder(lq): Treat missing tables and columns as the same
	// migration-state problem. A partially applied 439 can create one overlay
	// table while leaving a required column absent, which otherwise surfaces as
	// the generic report error and gives self-hosted operators no next step.
	// 42P10 covers an overlay table that exists but is missing the unique index
	// required by the grant upsert, another symptom of a partial migration.
	switch pgErr.Code {
	case "42P01", // undefined_table
		"42703", // undefined_column
		"42P10": // invalid ON CONFLICT target
		return true
	default:
		return false
	}
}

// 2026-09-01 coder(lq): Once the project-permission feature is enabled, the
// unified ACL schema is authoritative. Missing overlay tables/columns must be
// surfaced as a migration failure instead of silently falling back to legacy
// project_members or issue_permissions data.
func wrapProjectPermissionRepositoryError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, projectauth.ErrMigrationRequired) || projectPermissionSchemaMissing(err) {
		return fmt.Errorf("%w: %v", projectauth.ErrMigrationRequired, err)
	}
	return err
}

func (r *projectAuthRepository) ListRoleDefinitions(ctx context.Context, workspaceID string) ([]projectauth.RoleDefinition, error) {
	if err := r.ensureSystemRoleDefinitions(ctx, workspaceID); err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	rows, err := r.db.Query(ctx, `
		SELECT role.id::text, role.workspace_id::text, role.role_key, role.name,
		       role.description, role.is_system, COALESCE(array_agg(p.permission ORDER BY p.permission) FILTER (WHERE p.permission IS NOT NULL), '{}')
		FROM project_permission_roles role
		LEFT JOIN project_permission_role_permissions p ON p.role_id = role.id
		WHERE role.workspace_id = $1
		GROUP BY role.id ORDER BY role.is_system DESC, role.name`, workspaceID)
	if err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	defer rows.Close()
	result := make([]projectauth.RoleDefinition, 0)
	for rows.Next() {
		var role projectauth.RoleDefinition
		var permissions []string
		if err := rows.Scan(&role.ID, &role.WorkspaceID, &role.Key, &role.Name, &role.Description, &role.IsSystem, &permissions); err != nil {
			return nil, wrapProjectPermissionRepositoryError(err)
		}
		for _, permission := range permissions {
			role.Permissions = append(role.Permissions, projectauth.Permission(permission))
		}
		role.Scope = projectauth.RoleScopeProject
		result = append(result, role)
	}
	return result, wrapProjectPermissionRepositoryError(rows.Err())
}

func (r *projectAuthRepository) GetRoleDefinition(ctx context.Context, workspaceID, key string) (projectauth.RoleDefinition, error) {
	roles, err := r.ListRoleDefinitions(ctx, workspaceID)
	if err != nil {
		return projectauth.RoleDefinition{}, err
	}
	for _, role := range roles {
		if string(role.Key) == key {
			return role, nil
		}
	}
	return projectauth.RoleDefinition{}, fmt.Errorf("role %q not found", key)
}

func (r *projectAuthRepository) CreateRoleDefinition(ctx context.Context, workspaceID, createdBy string, role projectauth.RoleDefinition) (projectauth.RoleDefinition, error) {
	if _, err := r.db.Exec(ctx, `INSERT INTO project_permission_roles (workspace_id, role_key, name, description, is_system, created_by) VALUES ($1,$2,$3,$4,false,$5)`, workspaceID, string(role.Key), role.Name, role.Description, createdBy); err != nil {
		return projectauth.RoleDefinition{}, wrapProjectPermissionRepositoryError(err)
	}
	if err := r.replaceRolePermissions(ctx, workspaceID, role.Key, role.Permissions); err != nil {
		return projectauth.RoleDefinition{}, err
	}
	return r.GetRoleDefinition(ctx, workspaceID, string(role.Key))
}

func (r *projectAuthRepository) UpdateRoleDefinition(ctx context.Context, workspaceID, key string, role projectauth.RoleDefinition) (projectauth.RoleDefinition, error) {
	if _, err := r.db.Exec(ctx, `UPDATE project_permission_roles SET name=$3, description=$4, updated_at=now() WHERE workspace_id=$1 AND role_key=$2`, workspaceID, key, role.Name, role.Description); err != nil {
		return projectauth.RoleDefinition{}, wrapProjectPermissionRepositoryError(err)
	}
	if err := r.replaceRolePermissions(ctx, workspaceID, projectauth.ProjectRole(key), role.Permissions); err != nil {
		return projectauth.RoleDefinition{}, err
	}
	return r.GetRoleDefinition(ctx, workspaceID, key)
}

func (r *projectAuthRepository) DeleteRoleDefinition(ctx context.Context, workspaceID, key string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM project_permission_roles WHERE workspace_id=$1 AND role_key=$2 AND is_system=false
		AND NOT EXISTS (
			SELECT 1 FROM projectauth_access_grants g
			WHERE g.workspace_id=$1 AND g.role_key = project_permission_roles.role_key
		)`, workspaceID, key)
	if err != nil {
		return wrapProjectPermissionRepositoryError(err)
	}
	if tag.RowsAffected() == 0 {
		return projectauth.ErrRoleInUse
	}
	return nil
}

func (r *projectAuthRepository) ensureSystemRoleDefinitions(ctx context.Context, workspaceID string) error {
	// 2026-09-01 coder(lq): Seed defaults only for roles created by this call.
	// Existing rows are administrator-owned configuration; filling their
	// missing permissions would silently undo intentional permission removals.
	_, err := r.db.Exec(ctx, `
		WITH system_roles(role_key, name) AS (
			VALUES ('owner', 'Owner'), ('manager', 'Manager'), ('member', 'Member'), ('viewer', 'Viewer')
		), inserted_roles AS (
			INSERT INTO project_permission_roles (workspace_id, role_key, name, is_system)
			SELECT $1, role_key, name, true FROM system_roles
			ON CONFLICT (workspace_id, role_key) DO NOTHING
			RETURNING id, role_key
		)
		INSERT INTO project_permission_role_permissions (role_id, permission)
		SELECT inserted.id, defaults.permission
		FROM inserted_roles inserted
		JOIN (VALUES
			('owner','project.view'), ('owner','project.edit'), ('owner','project.issue.create'),
			('owner','project.issue.comment'), ('owner','project.issue.manage'), ('owner','project.issue.archive'), ('owner','project.agent.use'), ('owner','project.member.manage'),
			('owner','project.settings.manage'), ('manager','project.view'), ('manager','project.edit'),
			('manager','project.issue.create'), ('manager','project.issue.comment'), ('manager','project.issue.manage'), ('manager','project.issue.archive'), ('manager','project.agent.use'), ('manager','project.member.manage'),
			('member','project.view'), ('member','project.issue.create'), ('member','project.issue.comment'), ('member','project.issue.archive'), ('member','project.agent.use'),
			('viewer','project.view')
		) AS defaults(role_key, permission) ON defaults.role_key = inserted.role_key
		ON CONFLICT DO NOTHING`, workspaceID)
	return wrapProjectPermissionRepositoryError(err)
}

func (r *projectAuthRepository) replaceRolePermissions(ctx context.Context, workspaceID string, key projectauth.ProjectRole, permissions []projectauth.Permission) error {
	if _, err := r.db.Exec(ctx, `DELETE FROM project_permission_role_permissions WHERE role_id = (SELECT id FROM project_permission_roles WHERE workspace_id=$1 AND role_key=$2)`, workspaceID, string(key)); err != nil {
		return wrapProjectPermissionRepositoryError(err)
	}
	for _, permission := range permissions {
		if !containsProjectPermission(projectPermissionValues, string(permission)) {
			return fmt.Errorf("invalid project permission %q", permission)
		}
		if _, err := r.db.Exec(ctx, `INSERT INTO project_permission_role_permissions (role_id, permission) SELECT id, $3 FROM project_permission_roles WHERE workspace_id=$1 AND role_key=$2`, workspaceID, string(key), string(permission)); err != nil {
			return wrapProjectPermissionRepositoryError(err)
		}
	}
	return nil
}

func containsProjectPermission(values []string, value string) bool {
	return strings.TrimSpace(value) != "" && func() bool {
		for _, candidate := range values {
			if candidate == value {
				return true
			}
		}
		return false
	}()
}

func (r *projectAuthRepository) ProjectWorkspace(ctx context.Context, projectID string) (string, error) {
	var workspaceID string
	err := r.db.QueryRow(ctx, `SELECT workspace_id::text FROM project WHERE id = $1`, projectID).Scan(&workspaceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", projectauth.ErrNoProjectAccess
	}
	return workspaceID, wrapProjectPermissionRepositoryError(err)
}

// IssueProject resolves the canonical workspace/project binding for a task.
// 2026-08-31 coder(lq): Keep task grant writes and reads tied to the actual
// issue row so a caller cannot pair an issue UUID with another project.
func (r *projectAuthRepository) IssueProject(ctx context.Context, issueID string) (string, string, error) {
	var workspaceID, projectID string
	err := r.db.QueryRow(ctx, `
		SELECT workspace_id::text, project_id::text
		FROM issue
		WHERE id = $1 AND project_id IS NOT NULL`, issueID).Scan(&workspaceID, &projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", projectauth.ErrNoProjectAccess
	}
	return workspaceID, projectID, wrapProjectPermissionRepositoryError(err)
}

// IssueCreator resolves a task creator to a native user ID. Agent-authored
// tasks use the owning human as their effective creator for authorization.
// 2026-09-05 coder(lq): Keep the immutable task-owner invariant in the SQL
// adapter so service and direct repository paths use the same identity.
func (r *projectAuthRepository) IssueCreator(ctx context.Context, issueID string) (string, error) {
	var creatorID string
	err := r.db.QueryRow(ctx, `
		SELECT CASE
			WHEN i.creator_type = 'member' THEN i.creator_id::text
			WHEN i.creator_type = 'agent' AND a.kind = 'user' AND a.owner_id IS NOT NULL THEN a.owner_id::text
			ELSE ''
		END
		FROM issue i
		LEFT JOIN agent a
		  ON a.id = i.creator_id
		 AND a.workspace_id = i.workspace_id
		 AND a.kind = 'user'
		WHERE i.id = $1`, issueID).Scan(&creatorID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", projectauth.ErrNoProjectAccess
	}
	return creatorID, wrapProjectPermissionRepositoryError(err)
}

func (r *projectAuthRepository) VisibleProjectIDs(ctx context.Context, workspaceID, userID string) ([]string, error) {
	return r.VisibleProjectIDsWithWorkspaceScope(ctx, workspaceID, userID, true)
}

func (r *projectAuthRepository) VisibleProjectIDsWithWorkspaceScope(ctx context.Context, workspaceID, userID string, includeWorkspaceOwned bool) ([]string, error) {
	ownerClause := "FALSE"
	if includeWorkspaceOwned {
		ownerClause = fmt.Sprintf(`(%s) AND EXISTS (
				SELECT 1 FROM member m
				WHERE m.workspace_id = p.workspace_id AND m.user_id = $2
				AND m.role = 'owner'
			)`, workspaceOwnerBypassPredicate("p.workspace_id"))
	}
	visibilityClause := projectAccessPredicate("p.id", "$1", "$2")
	query := fmt.Sprintf(`
		SELECT p.id::text
		FROM project p
		WHERE p.workspace_id = $1
		  AND (%s OR %s)
		ORDER BY p.created_at DESC`, ownerClause, visibilityClause)
	rows, err := r.db.Query(ctx, query, workspaceID, userID)
	if err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, wrapProjectPermissionRepositoryError(err)
		}
		ids = append(ids, id)
	}
	return ids, wrapProjectPermissionRepositoryError(rows.Err())
}

func (r *projectAuthRepository) AddProjectMember(ctx context.Context, projectID, userID string, role projectauth.ProjectRole) error {
	// 2026-09-05 coder(lq): The creator Owner invariant must hold even when a
	// legacy caller reaches this adapter without going through Service.AddMember.
	// Normalize the requested role before writing both compatibility and
	// canonical rows so a direct update cannot downgrade the project creator.
	creator, err := r.ProjectCreator(ctx, projectID)
	if err != nil {
		return err
	}
	if creator == userID {
		role = projectauth.ProjectOwner
	}
	_, err = r.db.Exec(ctx, `
		INSERT INTO project_members (project_id, user_id, role, custom_role_id)
		SELECT $1, $2, $3
			, (SELECT id FROM project_permission_roles WHERE workspace_id = (SELECT workspace_id FROM project WHERE id=$1) AND role_key=$3 AND is_system=false)
		WHERE EXISTS (
			SELECT 1 FROM project p
			JOIN member m ON m.workspace_id = p.workspace_id
			WHERE p.id = $1 AND m.user_id = $2
		)
		ON CONFLICT (project_id, user_id)
		DO UPDATE SET role = EXCLUDED.role, custom_role_id = EXCLUDED.custom_role_id, updated_at = now()`, projectID, userID, role)
	if err != nil {
		// 2026-09-04 coder(lq): Preserve migration-state errors at the
		// authorization boundary so project/member APIs can tell operators to
		// run the permission migrations instead of returning a generic 500.
		return wrapProjectPermissionRepositoryError(err)
	}
	return r.UpsertAccessGrant(ctx, projectauth.AccessGrant{ProjectID: projectID, SubjectType: projectauth.SubjectUser, SubjectID: userID, Role: projectauth.RoleKey(role), Scope: projectauth.RoleScopeProject, Source: projectauth.GrantSourceManual})
}

// 2026-08-27 coder(lq): Keep automatic role upgrades atomic in PostgreSQL so
// concurrent assignment and mention events cannot downgrade an existing role.
func (r *projectAuthRepository) PromoteProjectMember(ctx context.Context, projectID, userID string, minimumRole projectauth.ProjectRole) error {
	// 2026-09-05 coder(lq): Automatic promotions (assignee, lead, mention,
	// onboarding) are monotonic, but the creator rule is stronger: a creator
	// must remain Owner even when this compatibility API is called directly.
	creator, err := r.ProjectCreator(ctx, projectID)
	if err != nil {
		return err
	}
	if creator == userID {
		minimumRole = projectauth.ProjectOwner
	}
	_, err = r.db.Exec(ctx, `
		INSERT INTO project_members (project_id, user_id, role)
		SELECT $1, $2, CASE WHEN EXISTS (SELECT 1 FROM project p WHERE p.id=$1 AND p.created_by=$2::uuid) THEN 'owner' ELSE $3 END
		WHERE EXISTS (
			SELECT 1 FROM project p
			JOIN member m ON m.workspace_id = p.workspace_id
			WHERE p.id = $1 AND m.user_id = $2
		)
		ON CONFLICT (project_id, user_id)
		DO UPDATE SET role = CASE
			WHEN project_members.custom_role_id IS NOT NULL THEN project_members.role
			WHEN CASE project_members.role
				WHEN 'owner' THEN 4 WHEN 'manager' THEN 3 WHEN 'member' THEN 2 ELSE 1 END
				>= CASE EXCLUDED.role
				WHEN 'owner' THEN 4 WHEN 'manager' THEN 3 WHEN 'member' THEN 2 ELSE 1 END
			THEN project_members.role
			ELSE EXCLUDED.role
		END, updated_at = now()`, projectID, userID, minimumRole)
	if err != nil {
		// 2026-09-04 coder(lq): The owner seed runs inside project creation;
		// normalize missing permission columns/tables before the handler maps
		// the error to a client-visible migration response.
		return wrapProjectPermissionRepositoryError(err)
	}
	return r.UpsertAccessGrant(ctx, projectauth.AccessGrant{ProjectID: projectID, SubjectType: projectauth.SubjectUser, SubjectID: userID, Role: projectauth.RoleKey(minimumRole), Scope: projectauth.RoleScopeProject, Source: projectauth.GrantSourceSystem})
}

func (r *projectAuthRepository) RemoveProjectMember(ctx context.Context, projectID, userID string) error {
	// 2026-09-05 coder(lq): Keep the immutable creator Owner and the final
	// project Owner protected at the storage seam as well as in Service. This
	// covers old jobs or adapters that call the compatibility method directly.
	creator, err := r.ProjectCreator(ctx, projectID)
	if err != nil {
		return err
	}
	if creator == userID {
		return projectauth.ErrLastOwner
	}
	var targetRole string
	if err := r.db.QueryRow(ctx, `
		SELECT COALESCE((
			SELECT role_key
			FROM projectauth_access_grants
			WHERE project_id=$1 AND issue_id IS NULL AND subject_type='user' AND subject_id=$2
			ORDER BY CASE role_key WHEN 'owner' THEN 4 WHEN 'manager' THEN 3 WHEN 'member' THEN 2 WHEN 'viewer' THEN 1 ELSE 0 END DESC
			LIMIT 1
		), '')`, projectID, userID).Scan(&targetRole); err != nil {
		return wrapProjectPermissionRepositoryError(err)
	}
	if targetRole == string(projectauth.ProjectOwner) {
		var ownerCount int
		if err := r.db.QueryRow(ctx, `
			SELECT count(*)
			FROM projectauth_access_grants
			WHERE project_id=$1 AND issue_id IS NULL AND role_key='owner'`, projectID).Scan(&ownerCount); err != nil {
			return wrapProjectPermissionRepositoryError(err)
		}
		if ownerCount <= 1 {
			return projectauth.ErrLastOwner
		}
	}
	if _, err := r.db.Exec(ctx, `DELETE FROM project_members WHERE project_id = $1 AND user_id = $2`, projectID, userID); err != nil {
		return wrapProjectPermissionRepositoryError(err)
	}
	_, err = r.db.Exec(ctx, `DELETE FROM projectauth_access_grants WHERE project_id=$1 AND issue_id IS NULL AND subject_type='user' AND subject_id=$2`, projectID, userID)
	return wrapProjectPermissionRepositoryError(err)
}

func (r *projectAuthRepository) ListProjectMembers(ctx context.Context, projectID string) ([]projectauth.ProjectMemberRecord, error) {
	rows, err := r.db.Query(ctx, `
		-- 2026-09-01 coder(lq): The unified grant table is the sole source for
		-- project membership reads when the overlay is enabled. Keep this API's
		-- response shape for existing callers; organization/everyone grants are
		-- exposed through the access-grant API rather than fabricated as users.
		SELECT project_id::text, subject_id, role_key
		FROM projectauth_access_grants
		WHERE project_id = $1 AND issue_id IS NULL
		  AND subject_type = 'user' AND role_key IS NOT NULL
		ORDER BY created_at, id`, projectID)
	if err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	defer rows.Close()
	var result []projectauth.ProjectMemberRecord
	for rows.Next() {
		var member projectauth.ProjectMemberRecord
		var role string
		if err := rows.Scan(&member.ProjectID, &member.UserID, &role); err != nil {
			return nil, wrapProjectPermissionRepositoryError(err)
		}
		member.Role = projectauth.ProjectRole(role)
		result = append(result, member)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	rows.Close()

	// 2026-09-05 coder(lq): The project creator is an immutable Owner even
	// when the historical creator backfill was not run. Include a virtual
	// member row for this legacy endpoint so owner-count protection and the
	// project member dialog use the same runtime rule as ProjectRole/Check.
	var creatorID string
	err = r.db.QueryRow(ctx, `
		SELECT CASE WHEN EXISTS (
			SELECT 1
			FROM member m
			WHERE m.workspace_id = p.workspace_id
			  AND m.user_id = p.created_by
		) THEN COALESCE(p.created_by::text, '') ELSE '' END
		FROM project p
		WHERE p.id = $1`, projectID).Scan(&creatorID)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	if creatorID == "" {
		return result, nil
	}
	for _, member := range result {
		if member.UserID == creatorID && member.Role == projectauth.ProjectOwner {
			return result, nil
		}
	}
	result = append(result, projectauth.ProjectMemberRecord{
		ProjectID: projectID,
		UserID:    creatorID,
		Role:      projectauth.ProjectOwner,
	})
	return result, nil
}

// 2026-08-31 coder(lq): Keep report SQL in the Handler adapter so the
// projectauth package does not depend on sqlc or the upstream schema layer.
// The query starts from the unified grant fact table, expands organization and
// everyone subjects to effective users, and materializes project grants as
// inherited task rows. Legacy ACL tables are intentionally not read once the
// overlay is enabled; migration 453 is responsible for backfilling them.
func (r *projectAuthRepository) ListPermissionReport(ctx context.Context, filter projectauth.PermissionReportFilter) (projectauth.PermissionReportResult, error) {
	// 2026-09-04 coder(lq): Seed system roles before reporting so a workspace
	// created before its first role read has the same role permissions in the
	// report as it does during live authorization checks.
	if err := r.ensureSystemRoleDefinitions(ctx, filter.WorkspaceID); err != nil {
		return projectauth.PermissionReportResult{}, wrapProjectPermissionRepositoryError(err)
	}
	if err := r.ensureTaskSystemRoleDefinitions(ctx, filter.WorkspaceID); err != nil {
		return projectauth.PermissionReportResult{}, wrapProjectPermissionRepositoryError(err)
	}
	// 2026-09-04 coder(lq): Keep synthetic workspace-owner rows aligned with
	// every other visibility query. When the deployment disables the owner
	// bypass, the report must not claim access that list/detail endpoints deny.
	ownerBypass := workspaceOwnerBypassPredicate("p.workspace_id")
	query := fmt.Sprintf(`
		WITH RECURSIVE canonical AS (
			SELECT g.id::text AS grant_id, g.workspace_id::text AS workspace_id,
				g.project_id::text AS project_id, COALESCE(g.issue_id::text, '') AS issue_id,
				g.subject_type, COALESCE(g.subject_id, '') AS subject_id,
				g.role_key, g.permission, g.source, COALESCE(g.granted_by::text, '') AS granted_by,
				g.created_at, constraint_row.expires_at
			FROM projectauth_access_grants g
			JOIN project p ON p.id = g.project_id AND p.workspace_id = g.workspace_id
			LEFT JOIN projectauth_grant_constraints constraint_row
			  ON constraint_row.workspace_id = g.workspace_id AND constraint_row.grant_id = g.id
			WHERE g.workspace_id = $1
			  AND ($2 = '' OR g.project_id::text = $2)
			  -- Project grants remain in scope when the report is filtered to one
			  -- issue because they materialize inherited permissions below.
			  AND ($3 = '' OR g.issue_id IS NULL OR g.issue_id::text = $3)
			  AND (constraint_row.expires_at IS NULL OR constraint_row.expires_at > now())

			UNION ALL

			-- 2026-09-05 coder(lq): Creator Owner is an immutable runtime rule,
			-- not dependent on the optional backfill migration. Keep it in the
			-- report's canonical facts so legacy projects still show their real
			-- effective Owner role. A physical Owner grant wins this de-dup check.
			SELECT 'creator-owner-project-' || p.id::text, p.workspace_id::text,
				p.id::text, ''::text, 'user'::text, p.created_by::text,
				'owner'::text, NULL::text, 'system'::text, ''::text, p.created_at, NULL::timestamptz
			FROM project p
			JOIN member creator_member
			  ON creator_member.workspace_id = p.workspace_id
			 AND creator_member.user_id = p.created_by
			WHERE p.workspace_id = $1
			  AND p.created_by IS NOT NULL
			  AND ($2 = '' OR p.id::text = $2)
			  AND NOT EXISTS (
				SELECT 1
				FROM projectauth_access_grants owner_grant
				WHERE owner_grant.workspace_id = p.workspace_id
				  AND owner_grant.project_id = p.id
				  AND owner_grant.issue_id IS NULL
				  AND owner_grant.subject_type = 'user'
				  AND owner_grant.subject_id = p.created_by::text
				  AND owner_grant.role_key = 'owner'
			  )

			UNION ALL

			-- 2026-09-05 coder(lq): Tasks have the same immutable Owner rule.
			-- Agent-authored tasks resolve to the owning human; the task scope is
			-- deliberately kept on issue_id so it cannot become project access.
			SELECT 'creator-owner-issue-' || i.id::text, i.workspace_id::text,
				i.project_id::text, i.id::text, 'user'::text,
				CASE
					WHEN i.creator_type = 'member' THEN i.creator_id::text
					WHEN i.creator_type = 'agent' AND a.kind = 'user' THEN a.owner_id::text
					ELSE ''
				END,
				'owner'::text, NULL::text, 'system'::text, ''::text, i.created_at, NULL::timestamptz
			FROM issue i
			JOIN project p ON p.id = i.project_id AND p.workspace_id = i.workspace_id
			LEFT JOIN agent a
			  ON a.id = i.creator_id
			 AND a.workspace_id = i.workspace_id
			 AND a.kind = 'user'
			JOIN member creator_member
			  ON creator_member.workspace_id = i.workspace_id
			 AND creator_member.user_id = CASE
				WHEN i.creator_type = 'member' THEN i.creator_id
				WHEN i.creator_type = 'agent' AND a.kind = 'user' THEN a.owner_id
				ELSE NULL
			 END
			WHERE i.workspace_id = $1
			  AND i.project_id IS NOT NULL
			  AND ($2 = '' OR i.project_id::text = $2)
			  AND ($3 = '' OR i.id::text = $3)
			  AND NOT EXISTS (
				SELECT 1
				FROM projectauth_access_grants owner_grant
				WHERE owner_grant.workspace_id = i.workspace_id
				  AND owner_grant.project_id = i.project_id
				  AND owner_grant.issue_id = i.id
				  AND owner_grant.subject_type = 'user'
				  AND owner_grant.subject_id = CASE
					WHEN i.creator_type = 'member' THEN i.creator_id::text
					WHEN i.creator_type = 'agent' AND a.kind = 'user' THEN a.owner_id::text
					ELSE ''
				  END
				  AND owner_grant.role_key = 'owner'
			  )
		), permission_rows AS (
			SELECT c.*, c.permission AS permission_key
			FROM canonical c WHERE c.permission IS NOT NULL
			UNION ALL
			SELECT c.*, rp.permission AS permission_key
			FROM canonical c
			JOIN project_permission_roles rd
			  ON rd.workspace_id = c.workspace_id::uuid AND rd.role_key = c.role_key
			JOIN project_permission_role_permissions rp ON rp.role_id = rd.id
			WHERE c.role_key IS NOT NULL AND c.issue_id = ''
			UNION ALL
			SELECT c.*, rp.permission AS permission_key
			FROM canonical c
			JOIN projectauth_task_roles rd
			  ON rd.workspace_id = c.workspace_id::uuid AND rd.role_key = c.role_key
			JOIN projectauth_task_role_permissions rp ON rp.role_id = rd.id
			WHERE c.role_key IS NOT NULL AND c.issue_id <> ''
		), effective_org_members(workspace_id, organization_id, parent_id, user_id) AS (
			-- 2026-09-03 coder(lq): Materialize each user's active department and
			-- all active ancestors so reports reflect inherited parent grants too.
			SELECT org.workspace_id, org.id, org.parent_id, om.user_id
			FROM projectauth_organization_members om
			JOIN projectauth_organizations org ON org.id = om.organization_id
			JOIN member active_member
			  ON active_member.workspace_id = om.workspace_id
			 AND active_member.user_id = om.user_id
			WHERE om.workspace_id = $1 AND org.workspace_id = $1 AND org.status = 'active'
			UNION
			SELECT parent.workspace_id, parent.id, parent.parent_id, eom.user_id
			FROM effective_org_members eom
			JOIN projectauth_organizations parent ON parent.id = eom.parent_id
			WHERE parent.workspace_id = $1 AND parent.status = 'active'
		), role_members AS (
			-- A role subject targets users who hold that role. Expand every
			-- project-level role grant source, including organization and everyone,
			-- and keep task-level role assignments tied to their issue. A task role
			-- must never make a project grant match or leak to a sibling issue.
			SELECT DISTINCT c.project_id, c.issue_id, c.subject_id AS user_id, c.role_key
			FROM canonical c
			WHERE c.issue_id = '' AND c.subject_type = 'user' AND c.role_key IS NOT NULL
			UNION
			SELECT DISTINCT c.project_id, c.issue_id, om.user_id::text, c.role_key
			FROM canonical c
			JOIN effective_org_members om
			  ON om.organization_id::text = c.subject_id
			 AND om.workspace_id::text = c.workspace_id
			WHERE c.issue_id = '' AND c.subject_type = 'organization' AND c.role_key IS NOT NULL
			UNION
			SELECT DISTINCT c.project_id, c.issue_id, m.user_id::text, c.role_key
			FROM canonical c
			JOIN member m ON m.workspace_id::text = c.workspace_id
			WHERE c.issue_id = '' AND c.subject_type = 'everyone' AND c.role_key IS NOT NULL
			UNION
			SELECT DISTINCT c.project_id, c.issue_id, c.subject_id AS user_id, c.role_key
			FROM canonical c
			WHERE c.issue_id <> '' AND c.subject_type = 'user' AND c.role_key IS NOT NULL
			UNION
			SELECT DISTINCT c.project_id, c.issue_id, om.user_id::text, c.role_key
			FROM canonical c
			JOIN effective_org_members om
			  ON om.organization_id::text = c.subject_id
			 AND om.workspace_id::text = c.workspace_id
			WHERE c.issue_id <> '' AND c.subject_type = 'organization' AND c.role_key IS NOT NULL
			UNION
			SELECT DISTINCT c.project_id, c.issue_id, m.user_id::text, c.role_key
			FROM canonical c
			JOIN member m ON m.workspace_id::text = c.workspace_id
			WHERE c.issue_id <> '' AND c.subject_type = 'everyone' AND c.role_key IS NOT NULL
		), subjects AS (
			SELECT pr.*, pr.subject_id AS effective_user_id
			FROM permission_rows pr WHERE pr.subject_type = 'user'
			UNION ALL
			SELECT pr.*, om.user_id::text
			FROM permission_rows pr
			JOIN effective_org_members om
			  ON om.workspace_id::text = pr.workspace_id AND om.organization_id::text = pr.subject_id
			WHERE pr.subject_type = 'organization'
			UNION ALL
			SELECT pr.*, m.user_id::text
			FROM permission_rows pr
			JOIN member m ON m.workspace_id::text = pr.workspace_id
			WHERE pr.subject_type = 'everyone'
			UNION ALL
			SELECT pr.*, rm.user_id
			FROM permission_rows pr
			JOIN role_members rm ON rm.project_id = pr.project_id AND rm.role_key = pr.subject_id
			  AND (rm.issue_id = pr.issue_id OR (pr.issue_id <> '' AND rm.issue_id = ''))
			WHERE pr.subject_type = 'role'
		), report_rows AS (
			SELECT 'project'::text AS scope, s.project_id, p.title AS project_title,
				''::text AS issue_id, ''::text AS issue_title, s.effective_user_id AS user_id,
				COALESCE(u.name, '') AS user_name, COALESCE(u.email, '') AS user_email, COALESCE(m.role, '') AS workspace_role,
				COALESCE(s.role_key, '') AS project_role, s.permission_key AS permission,
				s.source, s.granted_by, s.subject_type, s.subject_id, FALSE AS inherited_from_project,
				s.grant_id, s.created_at, s.expires_at, 'project'::text AS source_resource_scope,
				s.project_id AS source_resource_id, ''::text AS project_access_mode, 0::bigint AS policy_version
			FROM subjects s
			JOIN project p ON p.id::text = s.project_id AND p.workspace_id::text = s.workspace_id
			LEFT JOIN "user" u ON u.id::text = NULLIF(s.effective_user_id, '')
			LEFT JOIN member m ON m.workspace_id = p.workspace_id AND m.user_id::text = NULLIF(s.effective_user_id, '')
			WHERE s.issue_id = ''

			UNION ALL

			SELECT 'issue', s.project_id, p.title, i.id::text, i.title, s.effective_user_id,
				COALESCE(u.name, ''), COALESCE(u.email, ''), COALESCE(m.role, ''), COALESCE(s.role_key, ''), s.permission_key,
				s.source, s.granted_by, s.subject_type, s.subject_id, FALSE,
				s.grant_id, s.created_at, s.expires_at, 'task'::text, i.id::text,
				COALESCE(policy.project_access_mode, 'inherit'), COALESCE(policy.policy_version, 1)
			FROM subjects s
			JOIN project p ON p.id::text = s.project_id AND p.workspace_id::text = s.workspace_id
			JOIN issue i ON i.id::text = s.issue_id AND i.project_id = p.id AND i.workspace_id = p.workspace_id
			LEFT JOIN projectauth_issue_policies policy
			  ON policy.workspace_id = i.workspace_id AND policy.issue_id = i.id
			LEFT JOIN "user" u ON u.id::text = NULLIF(s.effective_user_id, '')
			LEFT JOIN member m ON m.workspace_id = p.workspace_id AND m.user_id::text = NULLIF(s.effective_user_id, '')
			WHERE s.issue_id <> ''

			UNION ALL

			SELECT 'issue', s.project_id, p.title, i.id::text, i.title, s.effective_user_id,
				COALESCE(u.name, ''), COALESCE(u.email, ''), COALESCE(m.role, ''), COALESCE(s.role_key, ''), s.permission_key,
				s.source, s.granted_by, s.subject_type, s.subject_id, TRUE,
				s.grant_id, s.created_at, s.expires_at, 'project'::text, s.project_id,
				COALESCE(policy.project_access_mode, 'inherit'), COALESCE(policy.policy_version, 1)
			FROM subjects s
			JOIN project p ON p.id::text = s.project_id AND p.workspace_id::text = s.workspace_id
			JOIN issue i ON i.project_id = p.id AND i.workspace_id = p.workspace_id
			LEFT JOIN projectauth_issue_policies policy
			  ON policy.workspace_id = i.workspace_id AND policy.issue_id = i.id
			LEFT JOIN "user" u ON u.id::text = NULLIF(s.effective_user_id, '')
			LEFT JOIN member m ON m.workspace_id = p.workspace_id AND m.user_id::text = NULLIF(s.effective_user_id, '')
			WHERE s.issue_id = ''
			  AND COALESCE(policy.project_access_mode, 'inherit') = 'inherit'
			  AND s.permission_key IN ('project.view', 'project.edit', 'project.issue.comment',
				'project.issue.manage', 'project.issue.archive', 'project.agent.use',
				'project.issue.child.create')
		), owner_users AS (
			SELECT m.workspace_id::text AS workspace_id, m.user_id::text AS user_id
			FROM member m
			WHERE m.workspace_id = $1 AND m.role = 'owner'
		), owner_rows AS (
			SELECT 'project'::text AS scope, p.id::text AS project_id, p.title AS project_title,
				''::text AS issue_id, ''::text AS issue_title, ou.user_id,
				COALESCE(u.name, '') AS user_name, COALESCE(u.email, '') AS user_email, m.role AS workspace_role,
				''::text AS project_role, pm.permission, 'workspace_role'::text AS source,
				''::text AS granted_by, 'user'::text AS subject_type, m.user_id::text AS subject_id,
				FALSE AS inherited_from_project, ''::text AS grant_id, p.created_at,
				NULL::timestamptz AS expires_at, 'workspace'::text AS source_resource_scope,
				p.workspace_id::text AS source_resource_id, ''::text AS project_access_mode,
				0::bigint AS policy_version
			FROM project p
			JOIN owner_users ou ON ou.workspace_id = p.workspace_id::text
			JOIN member m ON m.workspace_id = p.workspace_id AND m.user_id::text = ou.user_id
			JOIN "user" u ON u.id::text = ou.user_id
			CROSS JOIN (VALUES ('project.view'), ('project.edit'), ('project.issue.create'),
				('project.issue.comment'), ('project.issue.manage'), ('project.issue.archive'),
				('project.agent.use'), ('project.issue.child.create'), ('project.member.manage'),
				('project.settings.manage')) AS pm(permission)
			WHERE p.workspace_id = $1 AND (%s)

			UNION ALL

			SELECT 'issue'::text AS scope, p.id::text AS project_id, p.title AS project_title,
				i.id::text AS issue_id, i.title AS issue_title, ou.user_id,
				COALESCE(u.name, '') AS user_name, COALESCE(u.email, '') AS user_email, 'owner'::text AS workspace_role,
				''::text AS project_role, pm.permission, 'workspace_role'::text AS source,
				''::text AS granted_by, 'user'::text AS subject_type, ou.user_id AS subject_id,
				TRUE AS inherited_from_project, ''::text AS grant_id, i.created_at,
				NULL::timestamptz AS expires_at, 'workspace'::text AS source_resource_scope,
				p.workspace_id::text AS source_resource_id,
				COALESCE(policy.project_access_mode, 'inherit') AS project_access_mode,
				COALESCE(policy.policy_version, 1) AS policy_version
			FROM issue i
			JOIN project p ON p.id = i.project_id AND p.workspace_id = i.workspace_id
			JOIN owner_users ou ON ou.workspace_id = p.workspace_id::text
			JOIN "user" u ON u.id::text = ou.user_id
			CROSS JOIN (VALUES ('project.view'), ('project.edit'),
				('project.issue.comment'), ('project.issue.manage'), ('project.issue.archive'),
				('project.agent.use'), ('project.issue.child.create')) AS pm(permission)
			LEFT JOIN projectauth_issue_policies policy
			  ON policy.workspace_id = i.workspace_id AND policy.issue_id = i.id
			WHERE p.workspace_id = $1 AND (%s)
			  AND COALESCE(policy.project_access_mode, 'inherit') = 'inherit'
		), all_rows AS (
			SELECT scope, project_id, project_title, issue_id, issue_title, user_id,
				user_name, user_email, workspace_role, project_role, permission, source,
				granted_by, subject_type, subject_id, inherited_from_project, grant_id,
				created_at, expires_at, source_resource_scope, source_resource_id,
				project_access_mode, policy_version
			FROM report_rows
			UNION ALL
			SELECT scope, project_id, project_title, issue_id, issue_title, user_id,
				user_name, user_email, workspace_role, project_role, permission, source,
				granted_by, subject_type, subject_id, inherited_from_project, grant_id,
				created_at, expires_at, source_resource_scope, source_resource_id,
				project_access_mode, policy_version
			FROM owner_rows
		), filtered_rows AS (
			SELECT DISTINCT * FROM all_rows
			WHERE ($2 = '' OR project_id = $2)
			  AND ($3 = '' OR issue_id = $3)
			  AND ($4 = '' OR user_id = $4)
			  AND ($5 = '' OR workspace_role = $5 OR project_role = $5)
			  AND ($6 = '' OR permission = $6)
			  AND ($7 = '' OR subject_type = $7)
			  AND ($8 = '' OR subject_id = $8)
			  AND ($9 = 'all' OR scope = $9)
		)
		SELECT scope, project_id, project_title, issue_id, issue_title,
			user_id, user_name, user_email, workspace_role, project_role,
			permission, source, granted_by, subject_type, subject_id,
			inherited_from_project, grant_id, created_at, expires_at,
			source_resource_scope, source_resource_id, project_access_mode,
			policy_version, COUNT(*) OVER() AS total_count
		FROM filtered_rows
		ORDER BY project_title, project_id, issue_title, issue_id, user_name, permission, source
		LIMIT $10 OFFSET $11`, ownerBypass, ownerBypass)
	rows, err := r.db.Query(ctx, query,
		filter.WorkspaceID, filter.ProjectID, filter.IssueID, filter.UserID,
		filter.Role, string(filter.Permission), string(filter.SubjectType), filter.SubjectID,
		filter.Scope, filter.Limit, filter.Offset)
	if err != nil {
		return projectauth.PermissionReportResult{}, wrapProjectPermissionRepositoryError(err)
	}
	defer rows.Close()

	result := projectauth.PermissionReportResult{Rows: make([]projectauth.PermissionReportRow, 0)}
	for rows.Next() {
		var row projectauth.PermissionReportRow
		var issueID, issueTitle, projectRole, grantedBy, subjectID, grantID pgtype.Text
		var workspaceRole, permission, source, subjectType, sourceResourceScope, sourceResourceID, projectAccessMode pgtype.Text
		var createdAt, expiresAt pgtype.Timestamptz
		var inherited bool
		var policyVersion, total int64
		if err := rows.Scan(&row.Scope, &row.ProjectID, &row.ProjectTitle, &issueID, &issueTitle,
			&row.UserID, &row.UserName, &row.UserEmail, &workspaceRole, &projectRole,
			&permission, &source, &grantedBy, &subjectType, &subjectID, &inherited,
			&grantID, &createdAt, &expiresAt, &sourceResourceScope, &sourceResourceID,
			&projectAccessMode, &policyVersion, &total); err != nil {
			return projectauth.PermissionReportResult{}, wrapProjectPermissionRepositoryError(err)
		}
		if issueID.Valid {
			row.IssueID = issueID.String
		}
		if issueTitle.Valid {
			row.IssueTitle = issueTitle.String
		}
		if subjectType.Valid {
			row.SubjectType = projectauth.SubjectType(subjectType.String)
		}
		if subjectID.Valid {
			row.SubjectID = subjectID.String
		}
		if workspaceRole.Valid {
			row.WorkspaceRole = projectauth.WorkspaceRole(workspaceRole.String)
		}
		if permission.Valid {
			row.Permission = projectauth.Permission(permission.String)
		}
		if source.Valid {
			row.Source = source.String
		}
		if projectRole.Valid {
			row.ProjectRole = projectauth.ProjectRole(projectRole.String)
		}
		if row.ProjectRole != "" {
			if inherited || row.Scope == "project" {
				row.RoleScope = projectauth.RoleScopeProject
			} else {
				row.RoleScope = projectauth.RoleScopeTask
			}
		}
		if grantID.Valid {
			row.GrantID = grantID.String
		}
		if grantedBy.Valid {
			row.GrantedBy = grantedBy.String
		}
		if createdAt.Valid {
			row.CreatedAt = createdAt.Time.UTC().Format(time.RFC3339Nano)
		}
		if expiresAt.Valid {
			row.ExpiresAt = expiresAt.Time.UTC().Format(time.RFC3339Nano)
		}
		if sourceResourceScope.Valid {
			row.SourceResourceScope = projectauth.RoleScope(sourceResourceScope.String)
		}
		if sourceResourceID.Valid {
			row.SourceResourceID = sourceResourceID.String
		}
		if projectAccessMode.Valid {
			row.ProjectAccessMode = projectauth.ProjectAccessMode(projectAccessMode.String)
		}
		row.PolicyVersion = policyVersion
		row.InheritedFromProject = inherited
		result.Rows = append(result.Rows, row)
		result.Total = total
	}
	return result, wrapProjectPermissionRepositoryError(rows.Err())
}
