package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// projectAccessGrantRequest is deliberately provider-neutral. The caller
// supplies a MissionOS user, role, organization, or everyone subject; the
// authorization service validates the subject and resource boundaries.
type projectAccessGrantRequest struct {
	SubjectType projectauth.SubjectType `json:"subject_type"`
	SubjectID   string                  `json:"subject_id"`
	Role        projectauth.RoleKey     `json:"role"`
	Scope       projectauth.RoleScope   `json:"scope,omitempty"`
	Permission  projectauth.Permission  `json:"permission"`
	ExpiresAt   *time.Time              `json:"expires_at,omitempty"`
}

func (h *Handler) issueAccessSubject(w http.ResponseWriter, r *http.Request, issueID string) (projectauth.Subject, string, bool) {
	issueUUID, ok := parseUUIDOrBadRequest(w, issueID, "task id")
	if !ok {
		return projectauth.Subject{}, "", false
	}
	issueID = util.UUIDToString(issueUUID)
	userID, ok := requireUserID(w, r)
	if !ok {
		return projectauth.Subject{}, "", false
	}
	workspaceID := h.resolveWorkspaceID(r)
	if workspaceID == "" {
		writeError(w, http.StatusBadRequest, "workspace_id is required")
		return projectauth.Subject{}, "", false
	}
	var issueWorkspaceID, projectID string
	// 2026-09-05 coder(lq): A task-level grant is valid even before a task is
	// attached to a project. Keep the project binding empty in that case and
	// let the narrow issue-grant adapter handle storage and authorization.
	if err := h.DB.QueryRow(r.Context(), `
		SELECT workspace_id::text, COALESCE(project_id::text, '')
		FROM issue WHERE id = $1`, issueID).Scan(&issueWorkspaceID, &projectID); err != nil {
		writeError(w, http.StatusNotFound, "task not found")
		return projectauth.Subject{}, "", false
	}
	if issueWorkspaceID != workspaceID {
		writeError(w, http.StatusNotFound, "task not found")
		return projectauth.Subject{}, "", false
	}
	member, err := h.getWorkspaceMember(r.Context(), userID, workspaceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return projectauth.Subject{}, "", false
	}
	return projectauth.Subject{UserID: userID, WorkspaceID: workspaceID, WorkspaceRole: projectauth.WorkspaceRole(member.Role)}, projectID, true
}

// 2026-09-01 coder(lq): Normalize UUID subjects at the HTTP boundary so
// malformed user or organization IDs return 400 instead of reaching a
// PostgreSQL UUID cast and becoming an opaque 500.
func normalizeAccessGrantIDs(w http.ResponseWriter, grant *projectauth.AccessGrant) bool {
	// 2026-09-05 coder(lq): Projectless task grants intentionally omit a
	// project ID. Validate it only for project-bound grants so the HTTP adapter
	// can keep the canonical projectauth_access_grants.project_id constraint.
	if grant.ProjectID != "" {
		projectUUID, ok := parseUUIDOrBadRequest(w, grant.ProjectID, "project id")
		if !ok {
			return false
		}
		grant.ProjectID = util.UUIDToString(projectUUID)
	}
	if grant.IssueID != "" {
		issueUUID, valid := parseUUIDOrBadRequest(w, grant.IssueID, "task id")
		if !valid {
			return false
		}
		grant.IssueID = util.UUIDToString(issueUUID)
	}
	if grant.SubjectType == projectauth.SubjectUser || grant.SubjectType == projectauth.SubjectOrganization {
		subjectUUID, valid := parseUUIDOrBadRequest(w, grant.SubjectID, "subject id")
		if !valid {
			return false
		}
		grant.SubjectID = util.UUIDToString(subjectUUID)
	}
	return true
}

func (h *Handler) listProjectAccessGrants(w http.ResponseWriter, r *http.Request) {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeErrorCode(w, http.StatusNotFound, "project_permission_disabled", "project permissions are disabled")
		return
	}
	projectID := chi.URLParam(r, "id")
	projectUUID, ok := parseUUIDOrBadRequest(w, projectID, "project id")
	if !ok {
		return
	}
	projectID = util.UUIDToString(projectUUID)
	subject, ok := h.projectSubject(w, r, projectID)
	if !ok {
		return
	}
	grants, err := h.ProjectAuth.ListAccessGrants(r.Context(), subject, projectID, "")
	if err != nil {
		writeProjectAccessGrantError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": grants, "total": len(grants)})
}

// ListProjectAccessGrants is the router-facing export for the project grant
// endpoint. Keep the implementation unexported so the handler file's helper
// surface stays small while the server package can register it.
func (h *Handler) ListProjectAccessGrants(w http.ResponseWriter, r *http.Request) {
	h.listProjectAccessGrants(w, r)
}

func (h *Handler) listIssueAccessGrants(w http.ResponseWriter, r *http.Request) {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeErrorCode(w, http.StatusNotFound, "project_permission_disabled", "project permissions are disabled")
		return
	}
	issueID := chi.URLParam(r, "id")
	subject, projectID, ok := h.issueAccessSubject(w, r, issueID)
	if !ok {
		return
	}
	issueUUID, ok := parseUUIDOrBadRequest(w, issueID, "task id")
	if !ok {
		return
	}
	issueID = util.UUIDToString(issueUUID)
	allowed, reason := h.effectiveIssueAccessAllowed(r.Context(), subject, issueID, projectauth.IssueManage, true)
	if !allowed {
		if reason == "internal" || reason == "unavailable" || reason == "migration" {
			writeProjectAccessGrantError(w, projectauth.ErrStorageUnavailable)
		} else {
			writeProjectAccessGrantError(w, projectauth.ErrForbidden)
		}
		return
	}
	if projectID == "" {
		grants, err := h.listProjectlessIssueAccessGrants(r.Context(), subject, issueID)
		if err != nil {
			writeProjectAccessGrantError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"grants": grants, "total": len(grants), "project_id": nil})
		return
	}
	// Authorization is performed by EffectiveAccessResolver above. Read the
	// rows directly so a caller whose access comes only from the direct parent
	// is not re-checked against the legacy project-only matrix.
	grants, err := (&projectAuthRepository{db: h.DB}).ListAccessGrants(r.Context(), subject.WorkspaceID, projectID, issueID)
	if err != nil {
		writeProjectAccessGrantError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": grants, "total": len(grants), "project_id": projectID})
}

// 2026-09-05 coder(lq): Projectless tasks use a dedicated grant table because
// the canonical project grant table intentionally requires project_id. Keep
// this adapter read-only and synthesize the creator Owner row when an older
// deployment has not run the backfill migration yet.
func (h *Handler) listProjectlessIssueAccessGrants(ctx context.Context, subject projectauth.Subject, issueID string) ([]projectauth.AccessGrant, error) {
	issueUUID, err := util.ParseUUID(issueID)
	if err != nil {
		return nil, projectauth.ErrNoProjectAccess
	}
	workspaceUUID, err := util.ParseUUID(subject.WorkspaceID)
	if err != nil {
		return nil, projectauth.ErrNoProjectAccess
	}
	issue, err := h.Queries.GetIssueInWorkspace(ctx, db.GetIssueInWorkspaceParams{ID: issueUUID, WorkspaceID: workspaceUUID})
	if err != nil || issue.ProjectID.Valid {
		return nil, projectauth.ErrNoProjectAccess
	}
	allowed, reason := h.effectiveIssueAccessAllowed(ctx, subject, issueID, projectauth.View, true)
	if !allowed {
		if reason == "internal" {
			return nil, projectauth.ErrStorageUnavailable
		}
		return nil, projectauth.ErrNoProjectAccess
	}
	rows, err := h.DB.Query(ctx, `
		SELECT id::text, workspace_id::text, issue_id::text,
		       subject_type, COALESCE(subject_id, ''), role_key, source,
		       COALESCE(granted_by::text, ''), created_at::text
		FROM projectauth_issue_access_grants
		WHERE workspace_id=$1 AND issue_id=$2
		ORDER BY created_at, id`, subject.WorkspaceID, issueID)
	if err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	defer rows.Close()
	grants := make([]projectauth.AccessGrant, 0)
	for rows.Next() {
		var grant projectauth.AccessGrant
		if err := rows.Scan(&grant.ID, &grant.WorkspaceID, &grant.IssueID,
			&grant.SubjectType, &grant.SubjectID, &grant.Role, &grant.Source,
			&grant.GrantedBy, &grant.CreatedAt); err != nil {
			return nil, wrapProjectPermissionRepositoryError(err)
		}
		grant.ProjectID = ""
		grant.Scope = projectauth.RoleScopeTask
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapProjectPermissionRepositoryError(err)
	}

	// Keep the immutable creator access visible without creating a row as a
	// side effect of a GET request. Agent-authored tasks resolve to the owning
	// human, matching IssueCreator in the repository adapter.
	var creatorID, createdAt string
	err = h.DB.QueryRow(ctx, `
		SELECT CASE
			WHEN i.creator_type = 'member' THEN i.creator_id::text
			WHEN i.creator_type = 'agent' AND a.kind = 'user' AND a.owner_id IS NOT NULL THEN a.owner_id::text
			ELSE ''
		END, COALESCE(i.created_at::text, '')
		FROM issue i
		LEFT JOIN agent a
		  ON a.id=i.creator_id AND a.workspace_id=i.workspace_id AND a.kind='user'
		WHERE i.id=$1 AND i.workspace_id=$2 AND i.project_id IS NULL`, issueID, subject.WorkspaceID).Scan(&creatorID, &createdAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, wrapProjectPermissionRepositoryError(err)
	}
	if creatorID != "" {
		var active bool
		if err := h.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM member WHERE workspace_id=$1 AND user_id=$2::uuid)`, subject.WorkspaceID, creatorID).Scan(&active); err != nil {
			return nil, wrapProjectPermissionRepositoryError(err)
		}
		if active {
			creatorOwnerExists := false
			for _, grant := range grants {
				if grant.SubjectType == projectauth.SubjectUser && grant.SubjectID == creatorID && projectauth.TaskRole(grant.Role) == projectauth.TaskOwner {
					creatorOwnerExists = true
					break
				}
			}
			if !creatorOwnerExists {
				grants = append(grants, projectauth.AccessGrant{
					ID: "creator-owner-" + issueID + "-" + creatorID, WorkspaceID: subject.WorkspaceID,
					IssueID: issueID, SubjectType: projectauth.SubjectUser, SubjectID: creatorID,
					Role: projectauth.RoleKey(projectauth.TaskOwner), Scope: projectauth.RoleScopeTask,
					Source: projectauth.GrantSourceSystem, CreatedAt: createdAt,
				})
			}
		}
	}
	return grants, nil
}

func (h *Handler) ListIssueAccessGrants(w http.ResponseWriter, r *http.Request) {
	h.listIssueAccessGrants(w, r)
}

func decodeProjectAccessGrant(r *http.Request) (projectauth.AccessGrant, error) {
	var req projectAccessGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return projectauth.AccessGrant{}, err
	}
	return projectauth.AccessGrant{
		SubjectType: req.SubjectType,
		SubjectID:   strings.TrimSpace(req.SubjectID),
		Role:        req.Role,
		Scope:       req.Scope,
		Permission:  req.Permission,
		ExpiresAt:   req.ExpiresAt,
	}, nil
}

func (h *Handler) mutateProjectAccessGrant(w http.ResponseWriter, r *http.Request, grant projectauth.AccessGrant, issueID string) {
	if h.TxStarter == nil {
		logProjectAccessGrantFailure("begin", grant, issueID, errors.New("transaction starter is nil"))
		writeErrorCode(w, http.StatusServiceUnavailable, "project_permission_unavailable", "project permission storage is unavailable")
		return
	}
	tx, err := h.TxStarter.Begin(r.Context())
	if err != nil {
		logProjectAccessGrantFailure("begin", grant, issueID, err)
		writeProjectAccessGrantError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	// 2026-08-31 coder(lq): Lock the canonical resource during a grant change
	// so concurrent project deletion or task moves cannot create an orphaned
	// authorization row.
	if issueID == "" {
		var workspaceID string
		if err := tx.QueryRow(r.Context(), `SELECT workspace_id::text FROM project WHERE id=$1 FOR UPDATE`, grant.ProjectID).Scan(&workspaceID); err != nil {
			logProjectAccessGrantFailure("lock_project", grant, issueID, err)
			writeProjectAccessGrantError(w, projectauth.ErrNoProjectAccess)
			return
		}
		grant.WorkspaceID = workspaceID
	} else if grant.ProjectID == "" {
		// 2026-09-05 coder(lq): Projectless tasks are locked by their issue
		// row and use the dedicated issue grant table. Never fabricate a project
		// ID just to reuse the project grant schema.
		if err := tx.QueryRow(r.Context(), `
			SELECT workspace_id::text, COALESCE(project_id::text, '')
			FROM issue WHERE id=$1 FOR UPDATE`, issueID).Scan(&grant.WorkspaceID, &grant.ProjectID); err != nil {
			logProjectAccessGrantFailure("lock_issue", grant, issueID, err)
			writeProjectAccessGrantError(w, projectauth.ErrNoProjectAccess)
			return
		}
		if grant.ProjectID != "" {
			// The project-bound path below owns this case. Keeping the branch
			// explicit prevents a projectless request from writing the wrong table.
			writeProjectAccessGrantError(w, projectauth.ErrCrossWorkspace)
			return
		}
		if err := h.mutateProjectlessIssueAccessGrantTx(r.Context(), tx, grant, issueID, r); err != nil {
			logProjectAccessGrantFailure("grant_projectless_issue", grant, issueID, err)
			writeProjectAccessGrantError(w, err)
			return
		}
		// 2026-09-05 coder(lq): Read back the canonical row so projectless
		// task grants have the same generated ID/timestamp response contract as
		// project-bound grants. The insert is idempotent, so this also returns
		// the existing manual row when the caller repeats the request.
		created, err := readProjectlessIssueAccessGrant(r.Context(), tx, grant)
		if err != nil {
			logProjectAccessGrantFailure("readback_projectless_issue", grant, issueID, err)
			writeProjectAccessGrantError(w, err)
			return
		}
		if err := persistGrantConstraint(r.Context(), tx, created.WorkspaceID, created.ID, grant.ExpiresAt, "manual", ""); err != nil {
			writeProjectAccessGrantError(w, err)
			return
		}
		created.ExpiresAt = grant.ExpiresAt
		if err := tx.Commit(r.Context()); err != nil {
			logProjectAccessGrantFailure("commit_projectless_issue", grant, issueID, err)
			writeProjectAccessGrantError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, created)
		return
	} else {
		var workspaceID, projectID string
		if err := tx.QueryRow(r.Context(), `SELECT workspace_id::text, project_id::text FROM issue WHERE id=$1 AND project_id IS NOT NULL FOR UPDATE`, issueID).Scan(&workspaceID, &projectID); err != nil || projectID != grant.ProjectID {
			if err == nil {
				err = errors.New("task belongs to a different project")
			}
			logProjectAccessGrantFailure("lock_issue", grant, issueID, err)
			writeProjectAccessGrantError(w, projectauth.ErrCrossWorkspace)
			return
		}
		grant.WorkspaceID = workspaceID
	}
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	member, err := h.getWorkspaceMember(r.Context(), userID, grant.WorkspaceID)
	if err != nil {
		logProjectAccessGrantFailure("member", grant, issueID, err)
		writeProjectAccessGrantError(w, projectauth.ErrNotWorkspaceMember)
		return
	}
	actor := projectauth.Subject{UserID: userID, WorkspaceID: grant.WorkspaceID, WorkspaceRole: projectauth.WorkspaceRole(member.Role)}
	service := projectauth.New(newProjectAuthRepository(tx), true)
	if err := service.GrantAccess(r.Context(), actor, grant); err != nil {
		logProjectAccessGrantFailure("grant", grant, issueID, err)
		writeProjectAccessGrantError(w, err)
		return
	}
	// Return the canonical row rather than an empty 204. The web client uses
	// this response to update its grant cache without guessing generated IDs or
	// server-normalized fields. Older adapters may not implement the optional
	// reader, so retain a source-compatible fallback during migration.
	created := grant
	created.WorkspaceID = actor.WorkspaceID
	created.Source = projectauth.GrantSourceManual
	created.GrantedBy = actor.UserID
	if reader, ok := any(newProjectAuthRepository(tx)).(projectauth.AccessGrantReader); ok {
		persisted, readErr := reader.GetAccessGrant(r.Context(), grant.WorkspaceID, grant.ProjectID, grant.IssueID,
			grant.SubjectType, grant.SubjectID, grant.Role, grant.Permission)
		if readErr != nil {
			logProjectAccessGrantFailure("readback", grant, issueID, readErr)
			writeProjectAccessGrantError(w, readErr)
			return
		}
		created = persisted
	}
	if err := tx.Commit(r.Context()); err != nil {
		logProjectAccessGrantFailure("commit", grant, issueID, err)
		writeProjectAccessGrantError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// 2026-09-05 coder(lq): Keep the public error intentionally generic while
// exposing the failing transaction stage and PostgreSQL state in local logs.
// Subject IDs are deliberately reduced to a presence bit to avoid placing
// directory identifiers in request logs.
func logProjectAccessGrantFailure(stage string, grant projectauth.AccessGrant, issueID string, err error) {
	attrs := []any{
		"stage", stage,
		"project_id", grant.ProjectID,
		"issue_id", issueID,
		"subject_type", string(grant.SubjectType),
		"has_subject_id", strings.TrimSpace(grant.SubjectID) != "",
		"role", string(grant.Role),
		"permission", string(grant.Permission),
		"sqlstate", projectPermissionSQLState(err),
		"error", err,
	}
	slog.Error("project permission grant failed", attrs...)
}

func projectPermissionSQLState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func (h *Handler) createProjectAccessGrant(w http.ResponseWriter, r *http.Request) {
	if !h.requireProjectAuthorizationEnabled(w) {
		return
	}
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeErrorCode(w, http.StatusNotFound, "project_permission_disabled", "project permissions are disabled")
		return
	}
	grant, err := decodeProjectAccessGrant(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid access grant payload")
		return
	}
	grant.ProjectID = chi.URLParam(r, "id")
	if !normalizeAccessGrantIDs(w, &grant) {
		return
	}
	h.mutateProjectAccessGrant(w, r, grant, "")
}

func (h *Handler) CreateProjectAccessGrant(w http.ResponseWriter, r *http.Request) {
	h.createProjectAccessGrant(w, r)
}

func (h *Handler) createIssueAccessGrant(w http.ResponseWriter, r *http.Request) {
	if !h.requireProjectAuthorizationEnabled(w) {
		return
	}
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeErrorCode(w, http.StatusNotFound, "project_permission_disabled", "project permissions are disabled")
		return
	}
	grant, err := decodeProjectAccessGrant(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid access grant payload")
		return
	}
	grant.IssueID = chi.URLParam(r, "id")
	_, projectID, ok := h.issueAccessSubject(w, r, grant.IssueID)
	if !ok {
		return
	}
	grant.ProjectID = projectID
	if !normalizeAccessGrantIDs(w, &grant) {
		return
	}
	h.mutateProjectAccessGrant(w, r, grant, grant.IssueID)
}

func (h *Handler) CreateIssueAccessGrant(w http.ResponseWriter, r *http.Request) {
	h.createIssueAccessGrant(w, r)
}

// 2026-09-05 coder(lq): Projectless task grants intentionally support role
// assignments only. Reuse the same built-in role names as project grants and
// validate custom roles against the task-safe permission subset.
func validateProjectlessIssueRole(ctx context.Context, executor dbExecutor, workspaceID string, role projectauth.RoleKey) error {
	if role == "" {
		return projectauth.ErrInvalidRole
	}
	if projectauth.IsSystemTaskRole(projectauth.TaskRole(role)) {
		return nil
	}
	var exists bool
	if err := executor.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM projectauth_task_roles WHERE workspace_id=$1 AND role_key=$2)`, workspaceID, string(role)).Scan(&exists); err != nil {
		return wrapProjectPermissionRepositoryError(err)
	}
	if !exists {
		return projectauth.ErrInvalidRole
	}
	var invalid int
	if err := executor.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM projectauth_task_role_permissions rp
		JOIN projectauth_task_roles rr ON rr.id=rp.role_id
		WHERE rr.workspace_id=$1 AND rr.role_key=$2
		  AND rp.permission NOT IN ('project.view', 'project.edit', 'project.issue.comment', 'project.issue.manage', 'project.issue.archive', 'project.agent.use', 'project.issue.child.create')`, workspaceID, string(role)).Scan(&invalid); err != nil {
		return wrapProjectPermissionRepositoryError(err)
	}
	if invalid > 0 {
		return projectauth.ErrInvalidIssuePermission
	}
	return nil
}

// 2026-09-05 coder(lq): Write projectless grants in one transaction so the
// task boundary, subject membership, ACL row, and audit event are consistent.
func (h *Handler) mutateProjectlessIssueAccessGrantTx(ctx context.Context, tx dbExecutor, grant projectauth.AccessGrant, issueID string, r *http.Request) error {
	grant.IssueID = issueID
	if err := grant.NormalizeRoleScope(); err != nil {
		return err
	}
	if grant.Permission != "" || grant.Role == "" {
		return projectauth.ErrInvalidRole
	}
	issueUUID, err := util.ParseUUID(issueID)
	if err != nil {
		return projectauth.ErrNoProjectAccess
	}
	workspaceUUID, err := util.ParseUUID(grant.WorkspaceID)
	if err != nil {
		return projectauth.ErrCrossWorkspace
	}
	issue, err := h.Queries.GetIssueInWorkspace(ctx, db.GetIssueInWorkspaceParams{ID: issueUUID, WorkspaceID: workspaceUUID})
	if err != nil || issue.ProjectID.Valid {
		return projectauth.ErrCrossWorkspace
	}
	userID, ok := requireUserIDValue(r)
	if !ok {
		return projectauth.ErrNotWorkspaceMember
	}
	member, err := h.getWorkspaceMember(ctx, userID, grant.WorkspaceID)
	if err != nil {
		return projectauth.ErrNotWorkspaceMember
	}
	subject := projectauth.Subject{UserID: userID, WorkspaceID: grant.WorkspaceID, WorkspaceRole: projectauth.WorkspaceRole(member.Role)}
	allowed, reason := h.effectiveIssueAccessAllowed(ctx, subject, issueID, projectauth.IssueManage, true)
	if !allowed {
		if reason == "internal" {
			return projectauth.ErrStorageUnavailable
		}
		return projectauth.ErrForbidden
	}
	if err := validateProjectlessIssueRole(ctx, tx, grant.WorkspaceID, grant.Role); err != nil {
		return err
	}
	subjectID := strings.TrimSpace(grant.SubjectID)
	switch grant.SubjectType {
	case projectauth.SubjectUser:
		if _, err := util.ParseUUID(subjectID); err != nil {
			return projectauth.ErrInvalidSubject
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM member WHERE workspace_id=$1 AND user_id=$2::uuid)`, grant.WorkspaceID, subjectID).Scan(&exists); err != nil {
			return wrapProjectPermissionRepositoryError(err)
		}
		if !exists {
			return projectauth.ErrInvalidSubject
		}
	case projectauth.SubjectOrganization:
		if _, err := util.ParseUUID(subjectID); err != nil {
			return projectauth.ErrInvalidSubject
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projectauth_organizations WHERE workspace_id=$1 AND id=$2::uuid AND status='active')`, grant.WorkspaceID, subjectID).Scan(&exists); err != nil {
			return wrapProjectPermissionRepositoryError(err)
		}
		if !exists {
			return projectauth.ErrInvalidSubject
		}
	case projectauth.SubjectEveryone:
		if subjectID != "" {
			return projectauth.ErrInvalidSubject
		}
		subjectID = ""
	default:
		return projectauth.ErrInvalidSubject
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO projectauth_issue_access_grants
			(workspace_id, issue_id, subject_type, subject_id, role_key, source, granted_by)
		VALUES ($1,$2,$3,$4,$5,'manual',$6)
		ON CONFLICT DO NOTHING`, grant.WorkspaceID, issueID, string(grant.SubjectType), subjectID, string(grant.Role), userID)
	if err != nil {
		return wrapProjectPermissionRepositoryError(err)
	}
	grant.SubjectID = subjectID
	grant.IssueID, grant.ProjectID = issueID, ""
	grant.Source, grant.GrantedBy = projectauth.GrantSourceManual, userID
	return (&projectAuthRepository{db: tx}).RecordAuthorizationAudit(ctx, projectauth.AuthorizationAuditEvent{
		WorkspaceID: grant.WorkspaceID,
		IssueID:     issueID,
		ActorUserID: userID,
		Action:      "project_permission_granted",
		Details: map[string]any{
			"issue_id": issueID, "subject_type": string(grant.SubjectType), "subject_id": subjectID,
			"role": string(grant.Role), "permission": "", "source": string(projectauth.GrantSourceManual),
		},
	})
}

// 2026-09-05 coder(lq): Keep the projectless POST response aligned with the
// project grant response by reading the row generated inside the same
// transaction. This avoids exposing a partial in-memory grant to clients.
func readProjectlessIssueAccessGrant(ctx context.Context, tx dbExecutor, grant projectauth.AccessGrant) (projectauth.AccessGrant, error) {
	var created projectauth.AccessGrant
	err := tx.QueryRow(ctx, `
		SELECT id::text, workspace_id::text, issue_id::text,
		       subject_type, subject_id, role_key, source,
		       COALESCE(granted_by::text, ''), created_at::text
		FROM projectauth_issue_access_grants
		WHERE workspace_id=$1 AND issue_id=$2
		  AND subject_type=$3 AND subject_id=$4
		  AND role_key=$5 AND source='manual'
		LIMIT 1`, grant.WorkspaceID, grant.IssueID, string(grant.SubjectType), grant.SubjectID, string(grant.Role)).
		Scan(&created.ID, &created.WorkspaceID, &created.IssueID,
			&created.SubjectType, &created.SubjectID, &created.Role, &created.Source,
			&created.GrantedBy, &created.CreatedAt)
	if err != nil {
		return projectauth.AccessGrant{}, wrapProjectPermissionRepositoryError(err)
	}
	created.ProjectID = ""
	created.Scope = projectauth.RoleScopeTask
	return created, nil
}

func requireUserIDValue(r *http.Request) (string, bool) {
	userID := requestUserID(r)
	if userID == "" {
		return "", false
	}
	return userID, true
}

func (h *Handler) revokeProjectAccessGrant(w http.ResponseWriter, r *http.Request) {
	if !h.requireProjectAuthorizationEnabled(w) {
		return
	}
	h.revokeAccessGrant(w, r, chi.URLParam(r, "id"), "")
}

func (h *Handler) RevokeProjectAccessGrant(w http.ResponseWriter, r *http.Request) {
	h.revokeProjectAccessGrant(w, r)
}

func (h *Handler) revokeIssueAccessGrant(w http.ResponseWriter, r *http.Request) {
	if !h.requireProjectAuthorizationEnabled(w) {
		return
	}
	issueID := chi.URLParam(r, "id")
	subject, projectID, ok := h.issueAccessSubject(w, r, issueID)
	if !ok {
		return
	}
	if projectID == "" {
		h.revokeProjectlessIssueAccessGrant(w, r, issueID, subject)
		return
	}
	h.revokeAccessGrant(w, r, projectID, issueID)
}

// 2026-09-05 coder(lq): Projectless tasks have their own ACL table, so they
// cannot use projectauth.Service.RevokeAccess (which deliberately requires a
// project_id). Keep this adapter narrow: only manual rows are removable and
// the immutable task-creator Owner can never be deleted or downgraded.
func (h *Handler) revokeProjectlessIssueAccessGrant(w http.ResponseWriter, r *http.Request, issueID string, subject projectauth.Subject) {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeErrorCode(w, http.StatusNotFound, "project_permission_disabled", "project permissions are disabled")
		return
	}
	grant, err := decodeProjectAccessGrant(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid access grant payload")
		return
	}
	grant.ProjectID = ""
	grant.IssueID = issueID
	grant.WorkspaceID = subject.WorkspaceID
	if !normalizeAccessGrantIDs(w, &grant) {
		return
	}
	if grant.SubjectType == projectauth.SubjectEveryone {
		grant.SubjectID = ""
	}
	if grant.Permission != "" || grant.Role == "" {
		writeProjectAccessGrantError(w, projectauth.ErrInvalidRole)
		return
	}
	if err := validateProjectlessIssueRole(r.Context(), h.DB, subject.WorkspaceID, grant.Role); err != nil {
		writeProjectAccessGrantError(w, err)
		return
	}
	if h.TxStarter == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, "project_permission_unavailable", "project permission storage is unavailable")
		return
	}
	tx, err := h.TxStarter.Begin(r.Context())
	if err != nil {
		writeProjectAccessGrantError(w, err)
		return
	}
	defer tx.Rollback(r.Context())

	var workspaceID, projectID string
	if err := tx.QueryRow(r.Context(), `
		SELECT workspace_id::text, COALESCE(project_id::text, '')
		FROM issue WHERE id=$1 FOR UPDATE`, issueID).Scan(&workspaceID, &projectID); err != nil {
		writeProjectAccessGrantError(w, projectauth.ErrNoProjectAccess)
		return
	}
	if workspaceID != subject.WorkspaceID {
		writeProjectAccessGrantError(w, projectauth.ErrNoProjectAccess)
		return
	}
	if projectID != "" {
		writeProjectAccessGrantError(w, projectauth.ErrCrossWorkspace)
		return
	}
	issueUUID, err := util.ParseUUID(issueID)
	if err != nil {
		writeProjectAccessGrantError(w, projectauth.ErrNoProjectAccess)
		return
	}
	workspaceUUID, err := util.ParseUUID(workspaceID)
	if err != nil {
		writeProjectAccessGrantError(w, projectauth.ErrCrossWorkspace)
		return
	}
	issue, err := h.Queries.GetIssueInWorkspace(r.Context(), db.GetIssueInWorkspaceParams{ID: issueUUID, WorkspaceID: workspaceUUID})
	if err != nil || issue.ProjectID.Valid {
		writeProjectAccessGrantError(w, projectauth.ErrNoProjectAccess)
		return
	}
	allowed, reason := h.effectiveIssueAccessAllowed(r.Context(), subject, issueID, projectauth.IssueManage, true)
	if !allowed {
		if reason == "internal" {
			writeProjectAccessGrantError(w, projectauth.ErrStorageUnavailable)
		} else {
			writeProjectAccessGrantError(w, projectauth.ErrForbidden)
		}
		return
	}
	if err := validateProjectlessIssueAccessGrantSubject(r.Context(), tx, workspaceID, issueID, grant); err != nil {
		writeProjectAccessGrantError(w, err)
		return
	}
	result, err := tx.Exec(r.Context(), `
		DELETE FROM projectauth_issue_access_grants
		WHERE workspace_id=$1 AND issue_id=$2 AND subject_type=$3
		  AND subject_id=$4 AND role_key=$5 AND source='manual'`,
		workspaceID, issueID, string(grant.SubjectType), grant.SubjectID, string(grant.Role))
	if err != nil {
		logProjectAccessGrantFailure("delete_projectless_issue", grant, issueID, err)
		writeProjectAccessGrantError(w, wrapProjectPermissionRepositoryError(err))
		return
	}
	if result.RowsAffected() == 0 {
		// 2026-09-05 coder(lq): A system grant (assignee/@mention) or a stale
		// row is not a successful manual revoke. Return not-found so the caller
		// refreshes instead of showing a false success.
		logProjectAccessGrantFailure("delete_projectless_issue_noop", grant, issueID, projectauth.ErrNoProjectAccess)
		writeProjectAccessGrantError(w, projectauth.ErrNoProjectAccess)
		return
	}
	if err := (&projectAuthRepository{db: tx}).RecordAuthorizationAudit(r.Context(), projectauth.AuthorizationAuditEvent{
		WorkspaceID: workspaceID,
		IssueID:     issueID,
		ActorUserID: subject.UserID,
		Action:      "project_permission_revoked",
		Details: map[string]any{
			"project_id": "", "issue_id": issueID,
			"subject_type": string(grant.SubjectType), "subject_id": grant.SubjectID,
			"role": string(grant.Role), "permission": "", "source": string(projectauth.GrantSourceManual),
		},
	}); err != nil {
		writeProjectAccessGrantError(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeProjectAccessGrantError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// 2026-09-05 coder(lq): Validate every projectless subject against the
// current workspace, not only Owner subjects. Without this check a malformed
// or cross-workspace user/organization ID could reach the delete predicate and
// produce inconsistent authorization behavior between grant and revoke.
func validateProjectlessIssueAccessGrantSubject(ctx context.Context, tx dbExecutor, workspaceID, issueID string, grant projectauth.AccessGrant) error {
	subjectID := strings.TrimSpace(grant.SubjectID)
	switch grant.SubjectType {
	case projectauth.SubjectUser:
		if _, err := util.ParseUUID(subjectID); err != nil {
			return projectauth.ErrInvalidSubject
		}
		var exists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM member WHERE workspace_id=$1 AND user_id=$2::uuid)`, workspaceID, subjectID).Scan(&exists); err != nil {
			return wrapProjectPermissionRepositoryError(err)
		}
		if !exists {
			return projectauth.ErrInvalidSubject
		}
		if projectauth.TaskRole(grant.Role) == projectauth.TaskOwner {
			creatorID, err := (&projectAuthRepository{db: tx}).IssueCreator(ctx, issueID)
			if err != nil {
				return err
			}
			if creatorID != "" && creatorID == subjectID {
				return projectauth.ErrLastOwner
			}
		}
	case projectauth.SubjectOrganization:
		if _, err := util.ParseUUID(subjectID); err != nil {
			return projectauth.ErrInvalidSubject
		}
		var exists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM projectauth_organizations
				WHERE workspace_id=$1 AND id=$2::uuid AND status='active'
			)`, workspaceID, subjectID).Scan(&exists); err != nil {
			return wrapProjectPermissionRepositoryError(err)
		}
		if !exists {
			return projectauth.ErrInvalidSubject
		}
	case projectauth.SubjectEveryone:
		if subjectID != "" {
			return projectauth.ErrInvalidSubject
		}
	default:
		return projectauth.ErrInvalidSubject
	}
	return nil
}

func (h *Handler) RevokeIssueAccessGrant(w http.ResponseWriter, r *http.Request) {
	h.revokeIssueAccessGrant(w, r)
}

func (h *Handler) revokeAccessGrant(w http.ResponseWriter, r *http.Request, projectID, issueID string) {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeErrorCode(w, http.StatusNotFound, "project_permission_disabled", "project permissions are disabled")
		return
	}
	grant, err := decodeProjectAccessGrant(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid access grant payload")
		return
	}
	grant.ProjectID, grant.IssueID = projectID, issueID
	if !normalizeAccessGrantIDs(w, &grant) {
		return
	}
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	workspaceID := h.resolveWorkspaceID(r)
	member, err := h.getWorkspaceMember(r.Context(), userID, workspaceID)
	if err != nil {
		logProjectAccessGrantFailure("member", grant, issueID, err)
		writeProjectAccessGrantError(w, projectauth.ErrNotWorkspaceMember)
		return
	}
	actor := projectauth.Subject{UserID: userID, WorkspaceID: workspaceID, WorkspaceRole: projectauth.WorkspaceRole(member.Role)}
	if err := h.withProjectPermissionRoleTransaction(r.Context(), func(service *projectauth.Service) error {
		grant.WorkspaceID = workspaceID
		return service.RevokeAccess(r.Context(), actor, grant)
	}); err != nil {
		// 2026-09-05 coder(lq): Keep revoke failures diagnosable in local and
		// self-hosted logs while returning the existing stable API error shape.
		logProjectAccessGrantFailure("revoke", grant, issueID, err)
		writeProjectAccessGrantError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeProjectAccessGrantError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, projectauth.ErrMigrationRequired):
		writeErrorCode(w, http.StatusServiceUnavailable, "project_permission_migration_required", "project permission migration is required")
	case errors.Is(err, projectauth.ErrStorageUnavailable):
		writeErrorCode(w, http.StatusServiceUnavailable, "project_permission_unavailable", "project permission storage is unavailable")
	case errors.Is(err, projectauth.ErrInvalidRole), errors.Is(err, projectauth.ErrInvalidIssuePermission), errors.Is(err, projectauth.ErrInvalidSubject):
		writeErrorCode(w, http.StatusBadRequest, "invalid_access_grant", "invalid access grant")
	case errors.Is(err, projectauth.ErrLastOwner):
		// 2026-09-05 coder(lq): Creator Owner grants are immutable. Return a
		// conflict so the UI can explain why a downgrade/revoke was rejected
		// instead of surfacing an opaque 500 response.
		writeErrorCode(w, http.StatusConflict, "project_owner_protected", "owner permission cannot be revoked or downgraded")
	case errors.Is(err, projectauth.ErrForbidden):
		writeErrorCode(w, http.StatusForbidden, "project_permission_forbidden", "insufficient project permissions")
	case errors.Is(err, projectauth.ErrNotWorkspaceMember), errors.Is(err, projectauth.ErrNoProjectAccess), errors.Is(err, projectauth.ErrCrossWorkspace):
		writeErrorCode(w, http.StatusNotFound, "resource_not_found", "resource not found")
	case errors.Is(err, projectauth.ErrDisabled):
		writeErrorCode(w, http.StatusServiceUnavailable, "project_permission_unavailable", "project permission storage is unavailable")
	default:
		writeErrorCode(w, http.StatusInternalServerError, "project_permission_failed", "failed to update project permissions")
	}
}
