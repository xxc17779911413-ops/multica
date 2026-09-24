package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// 2026-08-27 coder(lq): Agent-level cancellation is an aggregate mutation,
// but its rows can belong to different projects. Resolve authorization first,
// then perform one UPDATE ... RETURNING so chat cleanup/broadcast semantics
// stay identical to the upstream bulk path without changing generated SQL.
func (h *Handler) cancelAgentTasksWithProjectPermission(ctx context.Context, agentID pgtype.UUID, userID, workspaceID string) ([]db.AgentTaskQueue, error) {
	tasks, err := h.Queries.ListAgentTasks(ctx, agentID)
	if err != nil {
		return nil, err
	}
	allowedIDs := make([]pgtype.UUID, 0, len(tasks))
	member, err := h.getWorkspaceMember(ctx, userID, workspaceID)
	if err != nil {
		return nil, err
	}
	subject := projectauth.Subject{UserID: userID, WorkspaceID: workspaceID, WorkspaceRole: projectauth.WorkspaceRole(member.Role)}
	for _, task := range tasks {
		switch {
		case task.IssueID.Valid:
			issue, issueErr := h.Queries.GetIssueInWorkspace(ctx, db.GetIssueInWorkspaceParams{ID: task.IssueID, WorkspaceID: parseUUID(workspaceID)})
			if issueErr != nil {
				continue
			}
			if allowed, _ := h.effectiveIssueAccessAllowed(ctx, subject, uuidToString(issue.ID), projectauth.IssueManage, true); allowed {
				allowedIDs = append(allowedIDs, task.ID)
			}
		case task.ChatSessionID.Valid:
			session, sessionErr := h.Queries.GetChatSessionInWorkspace(ctx, db.GetChatSessionInWorkspaceParams{ID: task.ChatSessionID, WorkspaceID: parseUUID(workspaceID)})
			if sessionErr != nil {
				continue
			}
			// 2026-08-27 coder(lq): Projectless chat tasks have no permission
			// scope and are hidden while the overlay is enabled.
			if !session.ProjectID.Valid {
				continue
			}
			if err := h.ProjectAuth.Check(ctx, subject, uuidToString(session.ProjectID), projectauth.IssueManage); err == nil {
				allowedIDs = append(allowedIDs, task.ID)
			}
		default:
			// 2026-08-27 coder(lq): Unscoped tasks cannot be authorized by the
			// project permission overlay.
			continue
		}
	}
	if len(allowedIDs) == 0 {
		return []db.AgentTaskQueue{}, nil
	}
	rows, err := h.DB.Query(ctx, `
		UPDATE agent_task_queue
		SET status = 'cancelled', completed_at = now(), prepare_lease_expires_at = NULL
		WHERE agent_id = $1
		  AND id = ANY($2::uuid[])
		  AND status IN ('queued', 'dispatched', 'running', 'waiting_local_directory', 'deferred')
		RETURNING *`, agentID, allowedIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return pgx.CollectRows(rows, pgx.RowToStructByName[db.AgentTaskQueue])
}

// 2026-08-27 coder(lq): Aggregated agent counters must use the same project
// visibility boundary as task history. Keeping these SQL adapters here avoids
// changing upstream sqlc query contracts while preventing counts from becoming
// a side channel for inaccessible projects.
func (h *Handler) getWorkspaceAgentRunCountsWithProjectPermission(ctx context.Context, workspaceID, userID pgtype.UUID) ([]db.GetWorkspaceAgentRunCountsRow, error) {
	query := fmt.Sprintf(`SELECT atq.agent_id, COUNT(*)::int AS run_count
		FROM agent_task_queue atq
		JOIN agent a ON a.id = atq.agent_id
		WHERE a.workspace_id = $1
		  AND atq.created_at > now() - INTERVAL '30 days'
		  AND %s
		GROUP BY atq.agent_id`, projectVisibleTaskPredicate("atq", "$1", "$2"))
	rows, err := h.DB.Query(ctx, query, workspaceID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]db.GetWorkspaceAgentRunCountsRow, 0)
	for rows.Next() {
		var row db.GetWorkspaceAgentRunCountsRow
		if err := rows.Scan(&row.AgentID, &row.RunCount); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (h *Handler) getWorkspaceAgentActivityWithProjectPermission(ctx context.Context, workspaceID, userID pgtype.UUID) ([]db.GetWorkspaceAgentActivity30dRow, error) {
	query := fmt.Sprintf(`SELECT atq.agent_id,
			DATE_TRUNC('day', atq.completed_at)::timestamptz AS bucket,
			COUNT(*)::int AS task_count,
			COUNT(*) FILTER (WHERE atq.status = 'failed')::int AS failed_count
		FROM agent_task_queue atq
		JOIN agent a ON a.id = atq.agent_id
		WHERE a.workspace_id = $1
		  AND atq.completed_at IS NOT NULL
		  AND atq.completed_at > now() - INTERVAL '30 days'
		  AND %s
		GROUP BY atq.agent_id, bucket
		ORDER BY atq.agent_id, bucket`, projectVisibleTaskPredicate("atq", "$1", "$2"))
	rows, err := h.DB.Query(ctx, query, workspaceID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]db.GetWorkspaceAgentActivity30dRow, 0)
	for rows.Next() {
		var row db.GetWorkspaceAgentActivity30dRow
		if err := rows.Scan(&row.AgentID, &row.Bucket, &row.TaskCount, &row.FailedCount); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func projectVisibleTaskPredicate(taskAlias, workspaceRef, userRef string) string {
	return projectVisibleTaskPredicateWithWorkspaceScope(taskAlias, workspaceRef, userRef, true)
}

func projectVisibleTaskPredicateWithWorkspaceScope(taskAlias, workspaceRef, userRef string, includeWorkspaceOwned bool) string {
	ownerClause := workspaceOwnerBypassPredicate(workspaceRef)
	if !includeWorkspaceOwned {
		ownerClause = "FALSE"
	}
	return fmt.Sprintf(`(
		(%s.issue_id IS NOT NULL AND EXISTS (
		SELECT 1 FROM issue acl_issue
		WHERE acl_issue.id = %s.issue_id
		  AND acl_issue.workspace_id = %s
			AND %s
		))
		OR (%s.issue_id IS NULL AND %s.chat_session_id IS NOT NULL AND EXISTS (
		SELECT 1 FROM chat_session acl_chat
		WHERE acl_chat.id = %s.chat_session_id
		  AND acl_chat.workspace_id = %s
		  AND %s
		))
		OR (%s.issue_id IS NULL AND %s.chat_session_id IS NULL AND (
			(%s AND EXISTS (SELECT 1 FROM member m WHERE m.workspace_id = %s AND m.user_id = %s::uuid AND m.role = 'owner'))
			OR %s.originator_user_id = %s::uuid
			OR %s.accountable_user_id = %s::uuid
			OR EXISTS (
				SELECT 1
				FROM agent a
				JOIN member agent_owner_member
				  ON agent_owner_member.workspace_id = a.workspace_id
				 AND agent_owner_member.user_id = a.owner_id
				WHERE a.id = %s.agent_id
				  AND a.workspace_id = %s
				  AND a.kind = 'user'
				  AND a.owner_id = %s::uuid
			)
		))
	)`, taskAlias, taskAlias, workspaceRef,
		issueProjectVisibilityPredicateWithWorkspaceScope("acl_issue", workspaceRef, userRef, includeWorkspaceOwned),
		taskAlias, taskAlias, taskAlias, workspaceRef,
		chatProjectVisibilityPredicateWithWorkspaceScope("acl_chat", workspaceRef, userRef, includeWorkspaceOwned),
		taskAlias, taskAlias, ownerClause, workspaceRef, userRef,
		taskAlias, userRef, taskAlias, userRef,
		taskAlias, workspaceRef, userRef)
}

// 2026-08-28 coder(lq): Project-bound Chats inherit project visibility. When
// project permissions are enabled, projectless sessions are excluded so chat
// task rows cannot become an unscoped authorization side channel.
func chatProjectVisibilityPredicate(chatAlias, workspaceRef, userRef string) string {
	return chatProjectVisibilityPredicateWithWorkspaceScope(chatAlias, workspaceRef, userRef, true)
}

func chatProjectVisibilityPredicateWithWorkspaceScope(chatAlias, workspaceRef, userRef string, includeWorkspaceOwned bool) string {
	ownerProjectClause := "FALSE"
	if includeWorkspaceOwned {
		ownerProjectClause = fmt.Sprintf("(%s AND EXISTS (SELECT 1 FROM member m WHERE m.workspace_id = %s AND m.user_id = %s::uuid AND m.role = 'owner'))", workspaceOwnerBypassPredicate(workspaceRef), workspaceRef, userRef)
	}
	return fmt.Sprintf(`(
		(%s.project_id IS NOT NULL AND (
			%s
			OR %s
		))
		OR (%s.project_id IS NULL AND (
			(%s AND EXISTS (SELECT 1 FROM member m WHERE m.workspace_id = %s AND m.user_id = %s::uuid AND m.role = 'owner'))
			OR %s
			OR %s
		))
	)`, chatAlias, ownerProjectClause, projectAccessPredicate(chatAlias+".project_id", workspaceRef, userRef),
		chatAlias, ownerProjectClause, workspaceRef, userRef,
		chatCreatorAccessPredicate(chatAlias, workspaceRef, userRef),
		chatAgentOwnerAccessPredicate(chatAlias, workspaceRef, userRef))
}

// 2026-09-05 coder(lq): A projectless chat creator is a native workspace
// member, not merely a matching UUID. Keep this predicate aligned with the
// task/issue creator fallback so a removed member cannot reopen old chats.
func chatCreatorAccessPredicate(chatAlias, workspaceRef, userRef string) string {
	return fmt.Sprintf(`(
		%s.creator_id = %s::uuid
		AND EXISTS (
			SELECT 1 FROM member creator_member
			WHERE creator_member.workspace_id = %s
			  AND creator_member.user_id = %s::uuid
		)
	)`, chatAlias, userRef, workspaceRef, userRef)
}

// 2026-09-05 coder(lq): User-owned Agent chats inherit visibility from the
// human owner only while that owner remains an active workspace member.
func chatAgentOwnerAccessPredicate(chatAlias, workspaceRef, userRef string) string {
	return fmt.Sprintf(`EXISTS (
		SELECT 1 FROM agent a
		WHERE a.id = %s.agent_id
		  AND a.workspace_id = %s
		  AND a.kind = 'user'
		  AND a.owner_id = %s::uuid
		  AND EXISTS (
			SELECT 1 FROM member agent_owner_member
			WHERE agent_owner_member.workspace_id = %s
			  AND agent_owner_member.user_id = a.owner_id
		)
	)`, chatAlias, workspaceRef, userRef, workspaceRef)
}

// 2026-08-28 coder(lq): Project-authenticated Chat lists must not inherit the
// upstream creator-only query. This adapter returns the same list projection
// while applying project and projectless visibility in SQL, so workspace
// owners and Agent owners can see sessions created by another member without
// changing sqlc-generated queries.
func (h *Handler) listChatSessionsWithProjectPermission(ctx context.Context, workspaceID, userID pgtype.UUID, includeArchived, includeWorkspaceOwned bool) ([]ChatSessionResponse, error) {
	query := fmt.Sprintf(`SELECT cs.id, cs.workspace_id, cs.agent_id, cs.creator_id, cs.title,
		cs.status, cs.created_at, cs.updated_at, cs.pinned_at, cs.project_id,
		CASE WHEN cs.status = 'archived' THEN 0
		     ELSE (SELECT count(*) FROM chat_message m
		             WHERE m.chat_session_id = cs.id
		               AND m.role = 'assistant'
		               AND m.created_at > cs.last_read_at)
		END::int AS unread_count,
		COALESCE(lm.content, '') AS last_message_content,
		COALESCE(lm.role, '') AS last_message_role,
		lm.created_at AS last_message_at,
		lm.failure_reason AS last_message_failure_reason,
		COALESCE(lm.message_kind, '') AS last_message_kind
	FROM chat_session cs
	LEFT JOIN LATERAL (
		SELECT content, role, created_at, failure_reason, message_kind
		FROM chat_message m
		WHERE m.chat_session_id = cs.id
		  AND m.message_kind != 'channel_command'
		ORDER BY m.created_at DESC
		LIMIT 1
	) lm ON true
	WHERE cs.workspace_id = $1
	  AND ($3::boolean OR cs.status = 'active')
	  AND %s
	  AND (cs.explicitly_created_at IS NOT NULL OR lm.created_at IS NOT NULL)
	ORDER BY (cs.pinned_at IS NOT NULL) DESC, cs.pinned_at DESC,
		         COALESCE(lm.created_at, cs.updated_at) DESC`, chatProjectVisibilityPredicateWithWorkspaceScope("cs", "$1", "$2", includeWorkspaceOwned))
	rows, err := h.DB.Query(ctx, query, workspaceID, userID, includeArchived)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ChatSessionResponse, 0)
	for rows.Next() {
		var row struct {
			ID                       pgtype.UUID
			WorkspaceID              pgtype.UUID
			AgentID                  pgtype.UUID
			CreatorID                pgtype.UUID
			Title                    string
			Status                   string
			CreatedAt                pgtype.Timestamptz
			UpdatedAt                pgtype.Timestamptz
			PinnedAt                 pgtype.Timestamptz
			ProjectID                pgtype.UUID
			UnreadCount              int32
			LastMessageContent       string
			LastMessageRole          string
			LastMessageAt            pgtype.Timestamptz
			LastMessageFailureReason pgtype.Text
			LastMessageKind          string
		}
		if err := rows.Scan(
			&row.ID, &row.WorkspaceID, &row.AgentID, &row.CreatorID, &row.Title,
			&row.Status, &row.CreatedAt, &row.UpdatedAt, &row.PinnedAt, &row.ProjectID,
			&row.UnreadCount, &row.LastMessageContent, &row.LastMessageRole,
			&row.LastMessageAt, &row.LastMessageFailureReason, &row.LastMessageKind,
		); err != nil {
			return nil, err
		}
		result = append(result, ChatSessionResponse{
			ID:          uuidToString(row.ID),
			WorkspaceID: uuidToString(row.WorkspaceID),
			AgentID:     uuidToString(row.AgentID),
			CreatorID:   uuidToString(row.CreatorID),
			ProjectID:   uuidToPtr(row.ProjectID),
			Title:       row.Title,
			Status:      row.Status,
			HasUnread:   row.UnreadCount > 0,
			UnreadCount: int(row.UnreadCount),
			LastMessage: buildChatLastMessage(row.LastMessageAt, row.LastMessageContent, row.LastMessageRole, row.LastMessageFailureReason, row.LastMessageKind),
			Pinned:      row.PinnedAt.Valid,
			CreatedAt:   timestampToString(row.CreatedAt),
			UpdatedAt:   timestampToString(row.UpdatedAt),
		})
	}
	return result, rows.Err()
}

// 2026-08-27 coder(lq): Keep the task projection rule pure so list and
// snapshot handlers share exactly the same treatment of unscoped tasks.
func taskVisibleByProjectPermission(task db.AgentTaskQueue, visibleIssueIDs, visibleChatSessionIDs map[pgtype.UUID]struct{}, visibleUnscopedTaskIDs ...map[pgtype.UUID]struct{}) bool {
	if task.IssueID.Valid {
		_, ok := visibleIssueIDs[task.IssueID]
		return ok
	}
	if task.ChatSessionID.Valid {
		_, ok := visibleChatSessionIDs[task.ChatSessionID]
		return ok
	}
	if len(visibleUnscopedTaskIDs) > 0 {
		_, ok := visibleUnscopedTaskIDs[0][task.ID]
		return ok
	}
	return false
}

func issueProjectVisibilityPredicate(issueAlias, workspaceRef, userRef string) string {
	return issueProjectVisibilityPredicateWithWorkspaceScope(issueAlias, workspaceRef, userRef, true)
}

func issueProjectVisibilityPredicateWithWorkspaceScope(issueAlias, workspaceRef, userRef string, includeWorkspaceOwned bool) string {
	return (issueVisibilitySQL{}).predicate(issueAlias, workspaceRef, userRef, includeWorkspaceOwned)
}

func (scope issueVisibilitySQL) predicate(issueAlias, workspaceRef, userRef string, includeWorkspaceOwned bool) string {
	ownerClause := "FALSE"
	if includeWorkspaceOwned {
		ownerClause = fmt.Sprintf("(%s AND EXISTS (SELECT 1 FROM member m WHERE m.workspace_id = %s AND m.user_id = %s::uuid AND m.role = 'owner'))", workspaceOwnerBypassPredicate(workspaceRef), workspaceRef, userRef)
	}
	return fmt.Sprintf(`(
		%s
		OR %s
		OR EXISTS (
			SELECT 1 FROM issue direct_parent
			WHERE direct_parent.id = %s.parent_issue_id
			  AND direct_parent.workspace_id = %s.workspace_id
			  AND %s
		)
	)`, ownerClause, scope.base(""+issueAlias, workspaceRef, userRef), issueAlias, issueAlias,
		scope.base("direct_parent", workspaceRef, userRef))
}

// base mirrors EffectiveAccessResolver.Base for the project.view permission.
// The direct-parent clause above deliberately invokes base, never predicate,
// which prevents a grandparent's permissions from reaching a grandchild.
func (scope issueVisibilitySQL) base(issueAlias, workspaceRef, userRef string) string {
	return fmt.Sprintf(`(
		%s
		OR (%s.assignee_type = 'member' AND %s.assignee_id = %s::uuid)
		OR (%s.assignee_type = 'agent' AND EXISTS (
			SELECT 1 FROM agent assignee_agent
			WHERE assignee_agent.id = %s.assignee_id
			  AND assignee_agent.workspace_id = %s.workspace_id
			  AND assignee_agent.kind = 'user'
			  AND assignee_agent.owner_id = %s::uuid
		))
		OR %s
		OR (
			%s.project_id IS NOT NULL
			AND NOT EXISTS (
				SELECT 1 FROM projectauth_issue_policies access_policy
				WHERE access_policy.workspace_id = %s.workspace_id
				  AND access_policy.issue_id = %s.id
				  AND access_policy.project_access_mode = 'restricted'
			)
			AND %s
		)
	)`, issueCreatorAccessPredicate(issueAlias, workspaceRef, userRef),
		issueAlias, issueAlias, userRef,
		issueAlias, issueAlias, issueAlias, userRef,
		scope.directAccess(issueAlias+".id", workspaceRef, userRef),
		issueAlias, issueAlias, issueAlias,
		scope.projectAccess(issueAlias+".project_id", workspaceRef, userRef))
}

// 2026-09-05 coder(lq): Projectless task grants are evaluated only against
// the current issue and only for the role's view permission. A task grant is
// deliberately absent from projectAccessPredicate so it cannot expose the
// containing project or sibling tasks.
func projectlessIssueGrantViewPredicate(issueAlias, workspaceRef, userRef string) string {
	return (issueVisibilitySQL{}).projectlessGrant(issueAlias, workspaceRef, userRef)
}

func (scope issueVisibilitySQL) projectlessGrant(issueAlias, workspaceRef, userRef string) string {
	principal := scope.principal("g")
	return fmt.Sprintf(`EXISTS (
		WITH auth_subject AS (
			SELECT %s::uuid AS workspace_id, %s::uuid AS user_id
		)
		SELECT 1
		FROM projectauth_issue_access_grants g
		CROSS JOIN auth_subject a
		WHERE g.workspace_id = a.workspace_id
		  AND g.issue_id = %s.id
		  AND %s
		  AND NOT EXISTS (
			SELECT 1 FROM projectauth_grant_constraints constraint_row
			WHERE constraint_row.workspace_id = g.workspace_id
			  AND constraint_row.grant_id = g.id
			  AND constraint_row.expires_at IS NOT NULL
			  AND constraint_row.expires_at <= now()
		  )
		  AND (
			EXISTS (
				SELECT 1
				FROM projectauth_task_roles rr
				JOIN projectauth_task_role_permissions rp ON rp.role_id = rr.id
				WHERE rr.workspace_id = a.workspace_id
				  AND rr.role_key = g.role_key
				  AND rp.permission = 'project.view'
			)
			OR (
				g.role_key IN ('owner', 'manager', 'member', 'viewer')
				AND NOT EXISTS (
					SELECT 1 FROM projectauth_task_roles rr
					WHERE rr.workspace_id = a.workspace_id AND rr.role_key = g.role_key
				)
			)
		  )
	)`, workspaceRef, userRef, issueAlias, principal)
}

// 2026-09-05 coder(lq): Resolve the effective native creator for a task in
// SQL so list/search/grouped queries honor the same immutable Owner rule as
// CheckIssue, including tasks created by user-owned agents.
func issueCreatorAccessPredicate(issueAlias, workspaceRef, userRef string) string {
	return fmt.Sprintf(`(
		(%s.creator_type = 'member' AND %s.creator_id = %s::uuid AND EXISTS (
			SELECT 1 FROM member creator_member
			WHERE creator_member.workspace_id = %s
			  AND creator_member.user_id = %s::uuid
		))
		OR (%s.creator_type = 'agent' AND EXISTS (
			SELECT 1 FROM agent a
			WHERE a.id = %s.creator_id
			  AND a.workspace_id = %s
			  AND a.kind = 'user'
			  AND a.owner_id = %s::uuid
			  AND EXISTS (
				SELECT 1 FROM member creator_member
				WHERE creator_member.workspace_id = %s
				  AND creator_member.user_id = a.owner_id
			  )
		))
	)`, issueAlias, issueAlias, userRef, workspaceRef, userRef,
		issueAlias, issueAlias, workspaceRef, userRef, workspaceRef)
}

// 2026-09-03 coder(lq): Resolve one authenticated user against a canonical
// user, organization, or everyone grant. Both project and task predicates use
// this fragment so their principal semantics cannot drift.
func accessGrantPrincipalPredicate(alias string) string {
	return (issueVisibilitySQL{}).principal(alias)
}

func (scope issueVisibilitySQL) principal(alias string) string {
	orgs := userOrganizationIDsSQL("a.workspace_id", "a.user_id")
	if scope.materialized {
		orgs = "SELECT organization_id::text FROM issue_auth_organizations"
	}
	return fmt.Sprintf(`(
		(%s.subject_type = 'user' AND %s.subject_id = a.user_id::text)
		OR (%s.subject_type = 'everyone' AND (%s.subject_id = '' OR %s.subject_id = a.workspace_id::text))
		OR (%s.subject_type = 'organization' AND %s.subject_id IN (%s))
	)`, alias, alias, alias, alias, alias, alias, alias, orgs)
}

func userOrganizationIDsSQL(workspaceRef, userRef string) string {
	return fmt.Sprintf(`
			WITH RECURSIVE user_orgs(organization_id, parent_id) AS (
				SELECT org.id, org.parent_id
				FROM projectauth_organization_members om
				JOIN projectauth_organizations org ON org.id = om.organization_id
				WHERE om.workspace_id = %[1]s
				  AND om.user_id = %[2]s
				  AND org.workspace_id = %[1]s
				  AND org.status = 'active'
				UNION
				SELECT parent.id, parent.parent_id
				FROM user_orgs child
				JOIN projectauth_organizations parent ON parent.id = child.parent_id
				WHERE parent.workspace_id = %[1]s
				  AND parent.status = 'active'
			)
			SELECT organization_id::text FROM user_orgs`, workspaceRef, userRef)
}

// 2026-09-04 coder(lq): SQL list paths can run before the first role-catalog
// read for a newly-created workspace. Keep the system-role defaults aligned
// with projectauth.Service.roleAllows until migration 439's lazy seeding has
// materialized those rows. An explicitly-created (even empty) role row wins;
// fallback is only for a role definition that does not exist yet.
func systemRoleViewPermissionPredicate(roleExpr, workspaceExpr string) string {
	return fmt.Sprintf(`(
		EXISTS (
			SELECT 1
			FROM project_permission_roles rr
			JOIN project_permission_role_permissions rp ON rp.role_id = rr.id
			WHERE rr.workspace_id = %s
			  AND rr.role_key = %s
			  AND rp.permission = 'project.view'
		)
		OR (
			%s IN ('owner', 'manager', 'member', 'viewer')
			AND NOT EXISTS (
				SELECT 1 FROM project_permission_roles rr
				WHERE rr.workspace_id = %s AND rr.role_key = %s
			)
		)
	)`, workspaceExpr, roleExpr, roleExpr, workspaceExpr, roleExpr)
}

func taskRoleViewPermissionPredicate(roleExpr, workspaceExpr string) string {
	return fmt.Sprintf(`(
		EXISTS (
			SELECT 1
			FROM projectauth_task_roles rr
			JOIN projectauth_task_role_permissions rp ON rp.role_id = rr.id
			WHERE rr.workspace_id = %s
			  AND rr.role_key = %s
			  AND rp.permission = 'project.view'
		)
		OR (
			%s IN ('owner', 'manager', 'member', 'viewer')
			AND NOT EXISTS (
				SELECT 1 FROM projectauth_task_roles rr
				WHERE rr.workspace_id = %s AND rr.role_key = %s
			)
		)
	)`, workspaceExpr, roleExpr, roleExpr, workspaceExpr, roleExpr)
}

// issueDirectAccessPredicate intentionally checks only grants attached to the
// current task. It may reveal that task in a list, but never its project or a
// sibling task. Role subjects match project roles and roles assigned directly
// on the same task, mirroring projectauth.Service.checkGrants.
// 2026-09-03 coder(lq): Keep direct task list visibility aligned with URL ACLs.
func issueDirectAccessPredicate(issueExpr, workspaceRef, userRef string) string {
	return (issueVisibilitySQL{}).directAccess(issueExpr, workspaceRef, userRef)
}

func (scope issueVisibilitySQL) directAccess(issueExpr, workspaceRef, userRef string) string {
	grantSubject := scope.principal("g")
	roleHolder := scope.principal("rg")
	return fmt.Sprintf(`EXISTS (
		WITH auth_subject AS (
			SELECT %s::uuid AS workspace_id, %s::uuid AS user_id
		)
		SELECT 1
		FROM issue direct_issue
		CROSS JOIN auth_subject a
		WHERE direct_issue.id = %s
		  AND direct_issue.workspace_id = a.workspace_id
		  AND (
		   (direct_issue.project_id IS NOT NULL AND EXISTS (
			SELECT 1
			FROM projectauth_access_grants g
			WHERE g.workspace_id = direct_issue.workspace_id
			  AND g.project_id = direct_issue.project_id
			  AND g.issue_id = direct_issue.id
			  AND (
				%s
				OR (g.subject_type = 'role' AND EXISTS (
					SELECT 1
					FROM projectauth_access_grants rg
					WHERE rg.workspace_id = direct_issue.workspace_id
					  AND rg.project_id = direct_issue.project_id
					  AND rg.issue_id = direct_issue.id
					  AND rg.role_key IS NOT NULL
					  AND %s
					  AND NOT EXISTS (
						SELECT 1 FROM projectauth_grant_constraints role_constraint
						WHERE role_constraint.workspace_id = rg.workspace_id
						  AND role_constraint.grant_id = rg.id
						  AND role_constraint.expires_at IS NOT NULL
						  AND role_constraint.expires_at <= now()
					  )
					  AND (rg.role_key = g.subject_id OR (g.subject_id = '' AND rg.role_key = g.role_key))
				))
			  )
			  AND NOT EXISTS (
				SELECT 1 FROM projectauth_grant_constraints grant_constraint
				WHERE grant_constraint.workspace_id = g.workspace_id
				  AND grant_constraint.grant_id = g.id
				  AND grant_constraint.expires_at IS NOT NULL
				  AND grant_constraint.expires_at <= now()
			  )
			  AND (
				g.permission = 'project.view'
				OR (g.role_key IS NOT NULL AND %s)
			  )
		   ))
		   OR (direct_issue.project_id IS NULL AND %s)
		  )
	)`, workspaceRef, userRef, issueExpr, grantSubject, roleHolder,
		taskRoleViewPermissionPredicate("g.role_key", "direct_issue.workspace_id"),
		scope.projectlessGrant("direct_issue", workspaceRef, userRef))
}

// 2026-08-31 coder(lq): Keep project-list visibility in one SQL adapter so
// project, task, chat and dashboard queries use the same authorization fact.
// The predicate intentionally resolves only project.view. Task-level grants
// are not considered here, which prevents a task share from exposing the
// remainder of its project.
func projectAccessPredicate(projectExpr, workspaceRef, userRef string) string {
	return (issueVisibilitySQL{}).projectAccess(projectExpr, workspaceRef, userRef)
}

func (scope issueVisibilitySQL) projectAccess(projectExpr, workspaceRef, userRef string) string {
	if scope.projectsMaterialized {
		return fmt.Sprintf("%s IN (SELECT id FROM issue_auth_projects)", projectExpr)
	}
	// 2026-09-01 coder(lq): Once the overlay is enabled, project visibility is
	// derived exclusively from the canonical grant table. The native member
	// table remains the source for workspace-owner bypass, but a legacy project
	// membership row must never make a project visible by itself.
	// 2026-09-01 coder(lq): Keep the principal expression identical for the
	// grant being evaluated and the grant that assigns a project role.
	// 2026-09-05 coder(lq): A creator fallback is valid only while the creator
	// remains a workspace member, matching the service-level hard Owner check
	// and preventing a stale creator UUID from leaking project visibility.
	// 2026-09-05 coder(lq): Keep the subquery alias private because callers may
	// evaluate this fragment against an outer issue alias named `p`.
	grantSubject := scope.principal("g")
	roleHolder := scope.principal("rg")
	return fmt.Sprintf(`EXISTS (
		WITH auth_subject AS (
			SELECT %s::uuid AS workspace_id, %s::uuid AS user_id
		)
		SELECT 1
		FROM project auth_project
		CROSS JOIN auth_subject a
		WHERE auth_project.id = %s
		  AND auth_project.workspace_id = a.workspace_id
		  AND (
			(auth_project.created_by = a.user_id AND EXISTS (
				SELECT 1 FROM member creator_member
				WHERE creator_member.workspace_id = auth_project.workspace_id
				  AND creator_member.user_id = auth_project.created_by
			))
			OR EXISTS (
			SELECT 1
			FROM projectauth_access_grants g
			WHERE g.workspace_id = auth_project.workspace_id
			  AND g.project_id = auth_project.id
			  AND g.issue_id IS NULL
			  AND (
				%s
				OR (g.subject_type = 'role' AND EXISTS (
					SELECT 1
					FROM projectauth_access_grants rg
					WHERE rg.workspace_id = auth_project.workspace_id
					  AND rg.project_id = auth_project.id
					  AND rg.issue_id IS NULL
					  AND rg.role_key IS NOT NULL
					  AND %s
					  AND (rg.role_key = g.subject_id OR (g.subject_id = '' AND rg.role_key = g.role_key))
				))
			  )
			  AND (
				g.permission = 'project.view'
				OR (g.role_key IS NOT NULL AND %s)
			  )
			)
		  )
	)`, workspaceRef, userRef, projectExpr, grantSubject, roleHolder,
		systemRoleViewPermissionPredicate("g.role_key", "auth_project.workspace_id"))
}

// workspaceOwnerBypassPredicate is embedded into all SQL visibility scopes so
// project lists, issue lists, chats, and task queues share one interpretation
// of the workspace-level owner switch. The switch now comes from the process
// environment, not workspace.settings, so deployment config is the only source
// of truth.
// 2026-09-01 coder(lq): Centralize the SQL fragment to prevent one list path
// from accidentally retaining unconditional workspace-owner visibility.
func workspaceOwnerBypassPredicate(workspaceRef string) string {
	_ = workspaceRef
	if !projectauth.WorkspaceOwnerBypassEnabledFromEnvironment() {
		return "FALSE"
	}
	return "TRUE"
}

// 2026-09-02 coder(lq): Projectless tasks remain visible only to their creator,
// assignee, or an enabled workspace-owner bypass, but participants must still
// be able to move the work forward before a project is selected. Once a
// project_id is supplied, UpdateIssue performs a separate target-project
// permission check before binding the task, so allowing mutation here cannot
// bypass the project ACL.
func projectlessIssuePermissionAllowed(issue db.Issue, userID pgtype.UUID, workspaceRole projectauth.WorkspaceRole, permission projectauth.Permission) bool {
	return projectlessIssuePermissionAllowedWithOwners(issue, userID, workspaceRole, permission, pgtype.UUID{}, pgtype.UUID{})
}

func projectlessIssuePermissionAllowedWithOwners(issue db.Issue, userID pgtype.UUID, workspaceRole projectauth.WorkspaceRole, permission projectauth.Permission, creatorOwnerID, assigneeOwnerID pgtype.UUID) bool {
	return projectlessIssuePermissionAllowedWithOwnersAndBypass(issue, userID, workspaceRole, permission, true, creatorOwnerID, assigneeOwnerID)
}

func projectlessIssuePermissionAllowedWithOwnersAndBypass(issue db.Issue, userID pgtype.UUID, workspaceRole projectauth.WorkspaceRole, permission projectauth.Permission, ownerBypassEnabled bool, creatorOwnerID, assigneeOwnerID pgtype.UUID) bool {
	if workspaceRole == projectauth.WorkspaceOwner && ownerBypassEnabled {
		return true
	}
	if !userID.Valid {
		return false
	}
	if issue.CreatorType == "member" && issue.CreatorID.Valid && issue.CreatorID == userID {
		return true
	}
	if issue.CreatorType == "agent" && creatorOwnerID.Valid && creatorOwnerID == userID {
		return true
	}
	if issue.AssigneeType.Valid && issue.AssigneeType.String == "member" && issue.AssigneeID.Valid && issue.AssigneeID == userID {
		return true
	}
	return issue.AssigneeType.Valid && issue.AssigneeType.String == "agent" && assigneeOwnerID.Valid && assigneeOwnerID == userID
}

// 2026-09-05 coder(lq): A direct member mention grants task-level Member
// access even when the task has no project. The aggregate grant table cannot
// store a NULL project_id, so resolve this narrow projectless case from the
// issue description and comments instead of weakening the owner boundary.
func (h *Handler) projectlessIssueMentionedUser(ctx context.Context, issue db.Issue, userID string) (bool, error) {
	mentioned := func(content string) bool {
		for _, mention := range util.ParseMentions(content) {
			if mention.Type == "member" && mention.ID == userID {
				return true
			}
		}
		return false
	}
	if issue.Description.Valid && mentioned(issue.Description.String) {
		return true, nil
	}
	rows, err := h.DB.Query(ctx, `SELECT content FROM comment WHERE issue_id=$1`, issue.ID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var content string
		if err := rows.Scan(&content); err != nil {
			return false, err
		}
		if mentioned(content) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return false, nil
}

// 2026-09-05 coder(lq): Read persisted task grants before the compatibility
// mention scan. This makes an @ grant visible from both the list and detail
// paths, including Agent mentions resolved to their owning human.
func (h *Handler) projectlessIssueGrantAllowed(ctx context.Context, issue db.Issue, userID string, permission projectauth.Permission) (bool, error) {
	var allowed bool
	err := h.DB.QueryRow(ctx, `
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
			  AND g.issue_id = $2
			  AND (
				(g.subject_type = 'user' AND g.subject_id = $3::text)
				OR (g.subject_type = 'everyone' AND (g.subject_id = '' OR g.subject_id = $1::text))
				OR (g.subject_type = 'organization' AND g.subject_id IN (SELECT organization_id::text FROM user_orgs))
			  )
			  AND (
				EXISTS (
					SELECT 1
					FROM project_permission_roles rr
					JOIN project_permission_role_permissions rp ON rp.role_id = rr.id
					WHERE rr.workspace_id = g.workspace_id
					  AND rr.role_key = g.role_key
					  AND rp.permission = $4
				)
				OR (
					g.role_key IN ('owner', 'manager', 'member', 'viewer')
					AND NOT EXISTS (
						SELECT 1 FROM project_permission_roles rr
						WHERE rr.workspace_id = g.workspace_id AND rr.role_key = g.role_key
					)
					AND ($4 = 'project.view' OR ($4 IN ('project.edit', 'project.issue.comment', 'project.issue.archive', 'project.agent.use') AND g.role_key IN ('owner', 'manager', 'member')) OR ($4 = 'project.issue.manage' AND g.role_key IN ('owner', 'manager')))
				)
			  )
		)`, issue.WorkspaceID, issue.ID, userID, string(permission)).Scan(&allowed)
	return allowed, err
}

// 2026-09-05 coder(lq): Keep HTTP and aggregate task entry points on the same
// projectless owner rule. The unified grant table cannot represent a task with
// no project, so creator/assignee access is resolved at runtime instead.
func (h *Handler) projectlessIssueAllowedWithWorkspaceScope(ctx context.Context, issue db.Issue, userID string, member db.Member, permission projectauth.Permission, includeWorkspaceOwned bool) (bool, string) {
	userUUID, err := util.ParseUUID(userID)
	if err != nil {
		return false, "denied"
	}
	creatorOwnerID := pgtype.UUID{}
	if issue.CreatorType == "agent" && issue.CreatorID.Valid {
		ownerID, resolveErr := resolveAgentOwnerInWorkspaceWithExecutor(ctx, h.DB, uuidToString(issue.WorkspaceID), uuidToString(issue.CreatorID))
		if resolveErr != nil {
			return false, "internal"
		}
		if ownerID != "" {
			creatorOwnerID, _ = util.ParseUUID(ownerID)
		}
	}
	assigneeOwnerID := pgtype.UUID{}
	if issue.AssigneeType.Valid && issue.AssigneeType.String == "agent" && issue.AssigneeID.Valid {
		ownerID, resolveErr := resolveAgentOwnerInWorkspaceWithExecutor(ctx, h.DB, uuidToString(issue.WorkspaceID), uuidToString(issue.AssigneeID))
		if resolveErr != nil {
			return false, "internal"
		}
		if ownerID != "" {
			assigneeOwnerID, _ = util.ParseUUID(ownerID)
		}
	}
	ownerBypassEnabled, err := h.ProjectAuth.WorkspaceOwnerBypassEnabled(ctx, uuidToString(issue.WorkspaceID))
	if err != nil {
		return false, "internal"
	}
	ownerBypassEnabled = ownerBypassEnabled && includeWorkspaceOwned
	if projectlessIssuePermissionAllowedWithOwnersAndBypass(issue, userUUID, projectauth.WorkspaceRole(member.Role), permission, ownerBypassEnabled, creatorOwnerID, assigneeOwnerID) {
		return true, ""
	}
	if granted, grantErr := h.projectlessIssueGrantAllowed(ctx, issue, userID, permission); grantErr != nil {
		return false, "internal"
	} else if granted {
		return true, ""
	}
	if mentioned, mentionErr := h.projectlessIssueMentionedUser(ctx, issue, userID); mentionErr != nil {
		return false, "internal"
	} else if mentioned {
		// A mention is equivalent to the task Member role. Keep this fallback
		// aligned with the default Member role for tasks created before the
		// projectless grant migration was applied.
		switch permission {
		case projectauth.View, projectauth.IssueComment, projectauth.IssueArchive, projectauth.AgentUse:
			return true, ""
		}
	}
	return false, "projectless"
}

// 2026-08-27 coder(lq): Dashboard rollups need a project boundary even when
// no project_id is supplied. Keep this predicate in the Handler adapter so
// the upstream sqlc queries remain untouched and the overlay can be removed
// without carrying a forked generated contract.
func dashboardProjectVisibilityPredicate(projectExpr, workspaceRef, userRef string) string {
	// 2026-09-01 coder(lq): Dashboard aggregates are another indirect
	// project-list surface. Keep workspace-owner bypass and canonical project
	// grants in the same predicate so an aggregate cannot be probed by UUID or
	// exposed through the old project_members table. Respect the same deployment
	// switch used by project/task lists.
	ownerClause := fmt.Sprintf(`(%s AND EXISTS (
		SELECT 1 FROM member m
		WHERE m.workspace_id = %s AND m.user_id = %s::uuid AND m.role = 'owner'
	))`, workspaceOwnerBypassPredicate(workspaceRef), workspaceRef, userRef)
	return fmt.Sprintf(`(%s IS NOT NULL AND (%s OR %s))`,
		projectExpr, ownerClause, projectAccessPredicate(projectExpr, workspaceRef, userRef))
}

func (h *Handler) dashboardNeedsProjectFilter(projectID pgtype.UUID) bool {
	return h.ProjectAuth != nil && h.ProjectAuth.Enabled() && !projectID.Valid
}

// 2026-08-27 coder(lq): A dashboard project_id is a project-level read and
// must be checked before the generated query runs, otherwise a member could
// probe an inaccessible project's aggregates by supplying its UUID.
func (h *Handler) requireDashboardProjectView(w http.ResponseWriter, r *http.Request, workspaceID string, projectID pgtype.UUID) bool {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() || !projectID.Valid {
		return true
	}
	return h.requireProjectPermission(w, r, uuidToString(projectID), workspaceID, projectauth.View)
}

func (h *Handler) listDashboardUsageDailyWithProjectPermission(ctx context.Context, workspaceID pgtype.UUID, userID, tz string, since pgtype.Timestamptz) ([]db.ListDashboardUsageDailyRow, error) {
	query := fmt.Sprintf(`SELECT
		DATE(bucket_hour AT TIME ZONE $3::text) AS date,
		LOWER(provider) AS provider,
		model,
		SUM(input_tokens)::bigint,
		SUM(output_tokens)::bigint,
		SUM(cache_read_tokens)::bigint,
		SUM(cache_write_tokens)::bigint,
		SUM(cost_usd_ticks)::bigint,
		SUM(COALESCE(uncosted_input_tokens, input_tokens))::bigint,
		SUM(COALESCE(uncosted_output_tokens, output_tokens))::bigint,
		SUM(COALESCE(uncosted_cache_read_tokens, cache_read_tokens))::bigint,
		SUM(COALESCE(uncosted_cache_write_tokens, cache_write_tokens))::bigint,
		SUM(task_count)::int
	FROM task_usage_hourly
	WHERE workspace_id = $1
	  AND bucket_hour >= $4::timestamptz
	  AND %s
	GROUP BY DATE(bucket_hour AT TIME ZONE $3::text), LOWER(provider), model
	ORDER BY DATE(bucket_hour AT TIME ZONE $3::text) DESC, LOWER(provider), model`, dashboardProjectVisibilityPredicate("task_usage_hourly.project_id", "$1", "$2"))
	rows, err := h.DB.Query(ctx, query, workspaceID, userID, tz, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]db.ListDashboardUsageDailyRow, 0)
	for rows.Next() {
		var row db.ListDashboardUsageDailyRow
		if err := rows.Scan(&row.Date, &row.Provider, &row.Model, &row.InputTokens, &row.OutputTokens, &row.CacheReadTokens, &row.CacheWriteTokens, &row.CostUsdTicks, &row.UncostedInputTokens, &row.UncostedOutputTokens, &row.UncostedCacheReadTokens, &row.UncostedCacheWriteTokens, &row.TaskCount); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (h *Handler) listDashboardUsageByAgentWithProjectPermission(ctx context.Context, workspaceID pgtype.UUID, userID string, since pgtype.Timestamptz) ([]db.ListDashboardUsageByAgentRow, error) {
	query := fmt.Sprintf(`SELECT
		agent_id,
		LOWER(provider) AS provider,
		model,
		SUM(input_tokens)::bigint,
		SUM(output_tokens)::bigint,
		SUM(cache_read_tokens)::bigint,
		SUM(cache_write_tokens)::bigint,
		SUM(cost_usd_ticks)::bigint,
		SUM(COALESCE(uncosted_input_tokens, input_tokens))::bigint,
		SUM(COALESCE(uncosted_output_tokens, output_tokens))::bigint,
		SUM(COALESCE(uncosted_cache_read_tokens, cache_read_tokens))::bigint,
		SUM(COALESCE(uncosted_cache_write_tokens, cache_write_tokens))::bigint,
		SUM(task_count)::int
	FROM task_usage_hourly
	WHERE workspace_id = $1
	  AND bucket_hour >= $3::timestamptz
	  AND %s
	GROUP BY agent_id, LOWER(provider), model
	ORDER BY agent_id, LOWER(provider), model`, dashboardProjectVisibilityPredicate("task_usage_hourly.project_id", "$1", "$2"))
	rows, err := h.DB.Query(ctx, query, workspaceID, userID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]db.ListDashboardUsageByAgentRow, 0)
	for rows.Next() {
		var row db.ListDashboardUsageByAgentRow
		if err := rows.Scan(&row.AgentID, &row.Provider, &row.Model, &row.InputTokens, &row.OutputTokens, &row.CacheReadTokens, &row.CacheWriteTokens, &row.CostUsdTicks, &row.UncostedInputTokens, &row.UncostedOutputTokens, &row.UncostedCacheReadTokens, &row.UncostedCacheWriteTokens, &row.TaskCount); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (h *Handler) listDashboardAgentRunTimeWithProjectPermission(ctx context.Context, workspaceID pgtype.UUID, userID string, since pgtype.Timestamptz) ([]db.ListDashboardAgentRunTimeRow, error) {
	query := fmt.Sprintf(`SELECT
		atq.agent_id,
		COALESCE(SUM(EXTRACT(EPOCH FROM (atq.completed_at - atq.started_at)))::bigint, 0)::bigint,
		COUNT(*)::int,
		COUNT(*) FILTER (WHERE atq.status = 'failed')::int,
		COUNT(*) FILTER (WHERE atq.status = 'cancelled')::int
	FROM agent_task_queue atq
	JOIN agent a ON a.id = atq.agent_id
	LEFT JOIN issue i ON i.id = atq.issue_id
	WHERE a.workspace_id = $1
	  AND atq.status IN ('completed', 'failed', 'cancelled')
	  AND atq.started_at IS NOT NULL
	  AND atq.completed_at IS NOT NULL
	  AND atq.completed_at >= $3::timestamptz
	  AND %s
	GROUP BY atq.agent_id
	ORDER BY total_seconds DESC`, dashboardProjectVisibilityPredicate("i.project_id", "$1", "$2"))
	rows, err := h.DB.Query(ctx, query, workspaceID, userID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]db.ListDashboardAgentRunTimeRow, 0)
	for rows.Next() {
		var row db.ListDashboardAgentRunTimeRow
		if err := rows.Scan(&row.AgentID, &row.TotalSeconds, &row.TaskCount, &row.FailedCount, &row.CancelledCount); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (h *Handler) listDashboardRunTimeDailyWithProjectPermission(ctx context.Context, workspaceID pgtype.UUID, userID, tz string, since pgtype.Timestamptz) ([]db.ListDashboardRunTimeDailyRow, error) {
	query := fmt.Sprintf(`SELECT
		DATE(atq.completed_at AT TIME ZONE $3::text),
		COALESCE(SUM(EXTRACT(EPOCH FROM (atq.completed_at - atq.started_at)))::bigint, 0)::bigint,
		COUNT(*)::int,
		COUNT(*) FILTER (WHERE atq.status = 'failed')::int,
		COUNT(*) FILTER (WHERE atq.status = 'cancelled')::int
	FROM agent_task_queue atq
	JOIN agent a ON a.id = atq.agent_id
	LEFT JOIN issue i ON i.id = atq.issue_id
	WHERE a.workspace_id = $1
	  AND atq.status IN ('completed', 'failed', 'cancelled')
	  AND atq.started_at IS NOT NULL
	  AND atq.completed_at IS NOT NULL
	  AND atq.completed_at >= $4::timestamptz
	  AND %s
	GROUP BY DATE(atq.completed_at AT TIME ZONE $3::text)
	ORDER BY DATE(atq.completed_at AT TIME ZONE $3::text) DESC`, dashboardProjectVisibilityPredicate("i.project_id", "$1", "$2"))
	rows, err := h.DB.Query(ctx, query, workspaceID, userID, tz, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]db.ListDashboardRunTimeDailyRow, 0)
	for rows.Next() {
		var row db.ListDashboardRunTimeDailyRow
		if err := rows.Scan(&row.Date, &row.TotalSeconds, &row.TaskCount, &row.FailedCount, &row.CancelledCount); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (h *Handler) listDashboardFailuresDailyWithProjectPermission(ctx context.Context, workspaceID pgtype.UUID, userID, tz string, since pgtype.Timestamptz) ([]db.ListDashboardFailuresDailyRow, error) {
	query := fmt.Sprintf(`SELECT
		DATE(atq.completed_at AT TIME ZONE $3::text),
		CASE WHEN atq.status = 'failed' THEN COALESCE(NULLIF(atq.failure_reason, ''), 'unclassified') ELSE '' END,
		COUNT(*)::int
	FROM agent_task_queue atq
	JOIN agent a ON a.id = atq.agent_id
	LEFT JOIN issue i ON i.id = atq.issue_id
	WHERE a.workspace_id = $1
	  AND atq.status IN ('completed', 'failed')
	  AND atq.completed_at IS NOT NULL
	  AND atq.completed_at >= $4::timestamptz
	  AND %s
	GROUP BY 1, 2
	ORDER BY 1 DESC, 2`, dashboardProjectVisibilityPredicate("i.project_id", "$1", "$2"))
	rows, err := h.DB.Query(ctx, query, workspaceID, userID, tz, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]db.ListDashboardFailuresDailyRow, 0)
	for rows.Next() {
		var row db.ListDashboardFailuresDailyRow
		if err := rows.Scan(&row.Date, &row.FailureReason, &row.TaskCount); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (h *Handler) listDashboardFailuresByAgentWithProjectPermission(ctx context.Context, workspaceID pgtype.UUID, userID string, since pgtype.Timestamptz) ([]db.ListDashboardFailuresByAgentRow, error) {
	query := fmt.Sprintf(`SELECT
		atq.agent_id,
		CASE WHEN atq.status = 'failed' THEN COALESCE(NULLIF(atq.failure_reason, ''), 'unclassified') ELSE '' END,
		COUNT(*)::int
	FROM agent_task_queue atq
	JOIN agent a ON a.id = atq.agent_id
	LEFT JOIN issue i ON i.id = atq.issue_id
	WHERE a.workspace_id = $1
	  AND atq.status IN ('completed', 'failed')
	  AND atq.completed_at IS NOT NULL
	  AND atq.completed_at >= $3::timestamptz
	  AND %s
	GROUP BY atq.agent_id, 2
	ORDER BY atq.agent_id, 2`, dashboardProjectVisibilityPredicate("i.project_id", "$1", "$2"))
	rows, err := h.DB.Query(ctx, query, workspaceID, userID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]db.ListDashboardFailuresByAgentRow, 0)
	for rows.Next() {
		var row db.ListDashboardFailuresByAgentRow
		if err := rows.Scan(&row.AgentID, &row.FailureReason, &row.TaskCount); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// 2026-08-27 coder(lq): Runtime reports are aggregate read paths, so applying
// project View at the endpoint alone is insufficient: the aggregate itself
// must exclude rows from projects outside the caller's scope. These adapters
// intentionally live beside the project-auth boundary and leave the upstream
// runtime_usage sqlc queries unchanged for low-friction upgrades.
func (h *Handler) listRuntimeUsageWithProjectPermission(ctx context.Context, runtimeID, workspaceID, userID pgtype.UUID, tz string, since pgtype.Timestamptz) ([]db.ListRuntimeUsageRow, error) {
	query := fmt.Sprintf(`SELECT
		DATE(bucket_hour AT TIME ZONE $4::text) AS date,
		LOWER(provider) AS provider,
		model,
		SUM(input_tokens)::bigint,
		SUM(output_tokens)::bigint,
		SUM(cache_read_tokens)::bigint,
		SUM(cache_write_tokens)::bigint,
		SUM(cost_usd_ticks)::bigint,
		SUM(COALESCE(uncosted_input_tokens, input_tokens))::bigint,
		SUM(COALESCE(uncosted_output_tokens, output_tokens))::bigint,
		SUM(COALESCE(uncosted_cache_read_tokens, cache_read_tokens))::bigint,
		SUM(COALESCE(uncosted_cache_write_tokens, cache_write_tokens))::bigint
	FROM task_usage_hourly
	WHERE runtime_id = $1
	  AND bucket_hour >= $5::timestamptz
	  AND %s
	GROUP BY DATE(bucket_hour AT TIME ZONE $4::text), LOWER(provider), model
	ORDER BY DATE(bucket_hour AT TIME ZONE $4::text) DESC, LOWER(provider), model`, dashboardProjectVisibilityPredicate("task_usage_hourly.project_id", "$2", "$3"))
	rows, err := h.DB.Query(ctx, query, runtimeID, workspaceID, userID, tz, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]db.ListRuntimeUsageRow, 0)
	for rows.Next() {
		var row db.ListRuntimeUsageRow
		if err := rows.Scan(&row.Date, &row.Provider, &row.Model, &row.InputTokens, &row.OutputTokens, &row.CacheReadTokens, &row.CacheWriteTokens, &row.CostUsdTicks, &row.UncostedInputTokens, &row.UncostedOutputTokens, &row.UncostedCacheReadTokens, &row.UncostedCacheWriteTokens); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (h *Handler) getRuntimeTaskHourlyActivityWithProjectPermission(ctx context.Context, runtimeID, workspaceID, userID pgtype.UUID, tz string) ([]db.GetRuntimeTaskHourlyActivityRow, error) {
	query := fmt.Sprintf(`SELECT EXTRACT(HOUR FROM atq.started_at AT TIME ZONE $4::text)::int AS hour,
		COUNT(*)::int AS count
	FROM agent_task_queue atq
	WHERE atq.runtime_id = $1
	  AND atq.started_at IS NOT NULL
	  AND %s
	GROUP BY hour
	ORDER BY hour`, projectVisibleTaskPredicate("atq", "$2", "$3"))
	rows, err := h.DB.Query(ctx, query, runtimeID, workspaceID, userID, tz)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]db.GetRuntimeTaskHourlyActivityRow, 0)
	for rows.Next() {
		var row db.GetRuntimeTaskHourlyActivityRow
		if err := rows.Scan(&row.Hour, &row.Count); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (h *Handler) listRuntimeUsageByAgentWithProjectPermission(ctx context.Context, runtimeID, workspaceID, userID pgtype.UUID, since pgtype.Timestamptz) ([]db.ListRuntimeUsageByAgentRow, error) {
	query := fmt.Sprintf(`SELECT
		atq.agent_id,
		LOWER(tu.provider) AS provider,
		tu.model,
		SUM(tu.input_tokens)::bigint,
		SUM(tu.output_tokens)::bigint,
		SUM(tu.cache_read_tokens)::bigint,
		SUM(tu.cache_write_tokens)::bigint,
		COALESCE(SUM(tu.cost_usd_ticks), 0)::bigint,
		COALESCE(SUM(tu.input_tokens) FILTER (WHERE tu.cost_usd_ticks IS NULL), 0)::bigint,
		COALESCE(SUM(tu.output_tokens) FILTER (WHERE tu.cost_usd_ticks IS NULL), 0)::bigint,
		COALESCE(SUM(tu.cache_read_tokens) FILTER (WHERE tu.cost_usd_ticks IS NULL), 0)::bigint,
		COALESCE(SUM(tu.cache_write_tokens) FILTER (WHERE tu.cost_usd_ticks IS NULL), 0)::bigint,
		COUNT(DISTINCT tu.task_id)::int
	FROM task_usage tu
	JOIN agent_task_queue atq ON atq.id = tu.task_id
	WHERE atq.runtime_id = $1
	  AND tu.created_at >= $4::timestamptz
	  AND %s
	GROUP BY atq.agent_id, LOWER(tu.provider), tu.model
	ORDER BY atq.agent_id, LOWER(tu.provider), tu.model`, projectVisibleTaskPredicate("atq", "$2", "$3"))
	rows, err := h.DB.Query(ctx, query, runtimeID, workspaceID, userID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]db.ListRuntimeUsageByAgentRow, 0)
	for rows.Next() {
		var row db.ListRuntimeUsageByAgentRow
		if err := rows.Scan(&row.AgentID, &row.Provider, &row.Model, &row.InputTokens, &row.OutputTokens, &row.CacheReadTokens, &row.CacheWriteTokens, &row.CostUsdTicks, &row.UncostedInputTokens, &row.UncostedOutputTokens, &row.UncostedCacheReadTokens, &row.UncostedCacheWriteTokens, &row.TaskCount); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (h *Handler) getRuntimeUsageByHourWithProjectPermission(ctx context.Context, runtimeID, workspaceID, userID pgtype.UUID, tz string, since pgtype.Timestamptz) ([]db.GetRuntimeUsageByHourRow, error) {
	query := fmt.Sprintf(`SELECT
		EXTRACT(HOUR FROM tu.created_at AT TIME ZONE $4::text)::int,
		tu.model,
		SUM(tu.input_tokens)::bigint,
		SUM(tu.output_tokens)::bigint,
		SUM(tu.cache_read_tokens)::bigint,
		SUM(tu.cache_write_tokens)::bigint,
		COALESCE(SUM(tu.cost_usd_ticks), 0)::bigint,
		COALESCE(SUM(tu.input_tokens) FILTER (WHERE tu.cost_usd_ticks IS NULL), 0)::bigint,
		COALESCE(SUM(tu.output_tokens) FILTER (WHERE tu.cost_usd_ticks IS NULL), 0)::bigint,
		COALESCE(SUM(tu.cache_read_tokens) FILTER (WHERE tu.cost_usd_ticks IS NULL), 0)::bigint,
		COALESCE(SUM(tu.cache_write_tokens) FILTER (WHERE tu.cost_usd_ticks IS NULL), 0)::bigint,
		COUNT(DISTINCT tu.task_id)::int
	FROM task_usage tu
	JOIN agent_task_queue atq ON atq.id = tu.task_id
	WHERE atq.runtime_id = $1
	  AND tu.created_at >= $5::timestamptz
	  AND %s
	GROUP BY EXTRACT(HOUR FROM tu.created_at AT TIME ZONE $4::text), tu.model
	ORDER BY hour, tu.model`, projectVisibleTaskPredicate("atq", "$2", "$3"))
	rows, err := h.DB.Query(ctx, query, runtimeID, workspaceID, userID, tz, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]db.GetRuntimeUsageByHourRow, 0)
	for rows.Next() {
		var row db.GetRuntimeUsageByHourRow
		if err := rows.Scan(&row.Hour, &row.Model, &row.InputTokens, &row.OutputTokens, &row.CacheReadTokens, &row.CacheWriteTokens, &row.CostUsdTicks, &row.UncostedInputTokens, &row.UncostedOutputTokens, &row.UncostedCacheReadTokens, &row.UncostedCacheWriteTokens, &row.TaskCount); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// 2026-08-27 coder(lq): Notifications carry only an issue id, so resolve the
// issue's project in one SQL predicate before returning or counting it. This
// keeps inbox authorization in the Handler adapter while the policy package
// remains independent of the upstream sqlc models.
func inboxIssueProjectVisibilityPredicate(inboxAlias, workspaceRef, userRef string) string {
	return inboxIssueProjectVisibilityPredicateWithWorkspaceScope(inboxAlias, workspaceRef, userRef, true)
}

// 2026-09-01 coder(lq): Inbox counters and summaries must use the same
// workspace-owner scope as the inbox list, otherwise unread badges can reveal
// activity from projects hidden by the owner toggle.
func inboxIssueProjectVisibilityPredicateWithWorkspaceScope(inboxAlias, workspaceRef, userRef string, includeWorkspaceOwned bool) string {
	return fmt.Sprintf(`(%s.issue_id IS NULL OR EXISTS (
		SELECT 1 FROM issue acl_issue
		WHERE acl_issue.id = %s.issue_id
		  AND acl_issue.workspace_id = %s
		  AND %s
	))`, inboxAlias, inboxAlias, workspaceRef,
		issueProjectVisibilityPredicateWithWorkspaceScope("acl_issue", workspaceRef, userRef, includeWorkspaceOwned))
}

// 2026-09-02 coder(lq): Archived issues stay out of live inbox counts, but
// bare system notifications with no issue_id still count as normal.
func inboxIssueNotArchivedPredicate(inboxAlias string) string {
	return fmt.Sprintf(`(%s.issue_id IS NULL OR EXISTS (
		SELECT 1 FROM issue active_issue
		WHERE active_issue.id = %s.issue_id
		  AND active_issue.archived_at IS NULL
	))`, inboxAlias, inboxAlias)
}

// 2026-08-27 coder(lq): Batch the project View check for issue ids used by
// inbox and pin endpoints. The one round trip avoids an authorization N+1
// while preserving the same workspace-owner/admin and project-member rules.
func (h *Handler) visibleIssueIDsByProjectPermission(ctx context.Context, workspaceID, userID pgtype.UUID, issueIDs []pgtype.UUID) (map[pgtype.UUID]struct{}, error) {
	return h.visibleIssueIDsByProjectPermissionWithWorkspaceScope(ctx, workspaceID, userID, issueIDs, true)
}

// 2026-09-01 coder(lq): Keep the task-page owner toggle effective on every
// batched issue read path, including open-only lists and child hydration.
func (h *Handler) visibleIssueIDsByProjectPermissionWithWorkspaceScope(ctx context.Context, workspaceID, userID pgtype.UUID, issueIDs []pgtype.UUID, includeWorkspaceOwned bool) (map[pgtype.UUID]struct{}, error) {
	visible := make(map[pgtype.UUID]struct{}, len(issueIDs))
	if len(issueIDs) == 0 || h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return visible, nil
	}
	query := fmt.Sprintf(`SELECT requested.id
		FROM unnest($2::uuid[]) requested(id)
		JOIN issue i ON i.id = requested.id AND i.workspace_id = $1
		WHERE %s`, issueProjectVisibilityPredicateWithWorkspaceScope("i", "$1", "$3", includeWorkspaceOwned))
	rows, err := h.DB.Query(ctx, query, workspaceID, issueIDs, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id pgtype.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		visible[id] = struct{}{}
	}
	return visible, rows.Err()
}

// CanMemberViewIssue is the notification pipeline's authorization adapter.
// It deliberately includes the current workspace-membership check performed
// by HTTP middleware, because background event listeners do not pass through
// that middleware before writing inbox rows or publishing WebSocket events.
// 2026-09-10 coder(lq): Keep notification targets aligned with the task page
// so former members and parent-only subscribers never receive dead links.
func (h *Handler) CanMemberViewIssue(ctx context.Context, workspaceID, userID, issueID string) (bool, error) {
	if _, err := h.getWorkspaceMember(ctx, userID, workspaceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return true, nil
	}

	workspaceUUID, err := util.ParseUUID(workspaceID)
	if err != nil {
		return false, fmt.Errorf("parse notification workspace id: %w", err)
	}
	userUUID, err := util.ParseUUID(userID)
	if err != nil {
		return false, fmt.Errorf("parse notification user id: %w", err)
	}
	issueUUID, err := util.ParseUUID(issueID)
	if err != nil {
		return false, fmt.Errorf("parse notification issue id: %w", err)
	}

	visible, err := h.visibleIssueIDsByProjectPermissionWithWorkspaceScope(
		ctx,
		workspaceUUID,
		userUUID,
		[]pgtype.UUID{issueUUID},
		true,
	)
	if err != nil {
		return false, err
	}
	_, allowed := visible[issueUUID]
	return allowed, nil
}

// 2026-08-27 coder(lq): Filter task projections in one authorization pass so
// history and presence endpoints cannot expose runs outside the caller's
// View scope. Issue-backed tasks use the same project/projectless predicate as
// issue lists; chat-only tasks use the corresponding Chat visibility rule.
func (h *Handler) filterTasksByProjectPermission(ctx context.Context, workspaceID, userID string, tasks []db.AgentTaskQueue) ([]db.AgentTaskQueue, error) {
	return h.filterTasksByProjectPermissionWithWorkspaceScope(ctx, workspaceID, userID, tasks, true)
}

// 2026-09-01 coder(lq): Keep the task-page owner toggle effective for every
// task projection, while the wrapper preserves compatibility for callers that
// do not carry a task-page view setting.
func (h *Handler) filterTasksByProjectPermissionWithWorkspaceScope(ctx context.Context, workspaceID, userID string, tasks []db.AgentTaskQueue, includeWorkspaceOwned bool) ([]db.AgentTaskQueue, error) {
	if h.ProjectAuth == nil || len(tasks) == 0 {
		return tasks, nil
	}
	if h.ProjectAuth.ShadowEnabled() {
		h.shadowIssueBatchVisibility(ctx, workspaceID, userID, tasks)
		return tasks, nil
	}
	if !h.ProjectAuth.Enabled() {
		return tasks, nil
	}
	if userID == "" {
		return []db.AgentTaskQueue{}, nil
	}
	issueIDs := make([]pgtype.UUID, 0, len(tasks))
	chatSessionIDs := make([]pgtype.UUID, 0, len(tasks))
	taskIDs := make([]pgtype.UUID, 0, len(tasks))
	seen := make(map[pgtype.UUID]struct{}, len(tasks))
	seenChats := make(map[pgtype.UUID]struct{}, len(tasks))
	for _, task := range tasks {
		if task.ID.Valid {
			taskIDs = append(taskIDs, task.ID)
		}
		if task.IssueID.Valid {
			if _, ok := seen[task.IssueID]; !ok {
				seen[task.IssueID] = struct{}{}
				issueIDs = append(issueIDs, task.IssueID)
			}
		}
		if task.ChatSessionID.Valid {
			if _, ok := seenChats[task.ChatSessionID]; !ok {
				seenChats[task.ChatSessionID] = struct{}{}
				chatSessionIDs = append(chatSessionIDs, task.ChatSessionID)
			}
		}
	}
	visible, err := h.visibleIssueIDsByProjectPermissionWithWorkspaceScope(ctx, parseUUID(workspaceID), parseUUID(userID), issueIDs, includeWorkspaceOwned)
	if err != nil {
		return nil, err
	}
	visibleChats, err := h.visibleChatSessionIDsByProjectPermissionWithWorkspaceScope(ctx, parseUUID(workspaceID), parseUUID(userID), chatSessionIDs, includeWorkspaceOwned)
	if err != nil {
		return nil, err
	}
	visibleUnscoped, err := h.visibleUnscopedTaskIDsByProjectPermissionWithWorkspaceScope(ctx, parseUUID(workspaceID), parseUUID(userID), taskIDs, includeWorkspaceOwned)
	if err != nil {
		return nil, err
	}
	filtered := make([]db.AgentTaskQueue, 0, len(tasks))
	for _, task := range tasks {
		if taskVisibleByProjectPermission(task, visible, visibleChats, visibleUnscoped) {
			filtered = append(filtered, task)
		}
	}
	return filtered, nil
}

// shadowIssueBatchVisibility evaluates only issue-backed queue rows because
// EffectiveAccessResolver's resource is a task Issue. Chat-only and unscoped
// rows retain their legacy behavior and are intentionally excluded from the
// comparison denominator. Shadow failures are observable but never affect the
// response returned to the caller.
func (h *Handler) shadowIssueBatchVisibility(ctx context.Context, workspaceID, userID string, tasks []db.AgentTaskQueue) {
	started := time.Now()
	defer func() { h.Metrics.ObserveProjectAuthorization("batch", time.Since(started)) }()
	if workspaceID == "" || userID == "" || h.EffectiveIssueAccess == nil {
		h.Metrics.RecordProjectAuthorizationShadow("batch", "error")
		return
	}
	issueIDs := make([]string, 0, len(tasks))
	seen := make(map[string]struct{}, len(tasks))
	for _, task := range tasks {
		if !task.IssueID.Valid {
			continue
		}
		issueID := uuidToString(task.IssueID)
		if _, duplicate := seen[issueID]; duplicate {
			continue
		}
		seen[issueID] = struct{}{}
		issueIDs = append(issueIDs, issueID)
	}
	if len(issueIDs) == 0 {
		return
	}
	accessByIssue, err := h.EffectiveIssueAccess.ResolveIssues(ctx, projectauth.Subject{UserID: userID, WorkspaceID: workspaceID}, issueIDs)
	if err != nil {
		h.Metrics.RecordProjectAuthorizationShadow("batch", "error")
		return
	}
	result := "match_allow"
	for _, issueID := range issueIDs {
		access, ok := accessByIssue[issueID]
		if !ok || !permissionListContains(access.Permissions, projectauth.View) {
			result = "candidate_deny"
			break
		}
	}
	h.Metrics.RecordProjectAuthorizationShadow("batch", result)
}

func permissionListContains(permissions []projectauth.Permission, want projectauth.Permission) bool {
	for _, permission := range permissions {
		if permission == want {
			return true
		}
	}
	return false
}

// 2026-08-28 coder(lq): Unscoped queue rows have no Issue/ChatSession row to
// join. Authorize them from their human attribution or the owning user of the
// executing Agent, while keeping the workspace boundary in SQL.
func (h *Handler) visibleUnscopedTaskIDsByProjectPermission(ctx context.Context, workspaceID, userID pgtype.UUID, taskIDs []pgtype.UUID) (map[pgtype.UUID]struct{}, error) {
	return h.visibleUnscopedTaskIDsByProjectPermissionWithWorkspaceScope(ctx, workspaceID, userID, taskIDs, true)
}

// 2026-09-01 coder(lq): Apply the same owner-scope switch to projectless
// queue rows used by task history and agent snapshots.
func (h *Handler) visibleUnscopedTaskIDsByProjectPermissionWithWorkspaceScope(ctx context.Context, workspaceID, userID pgtype.UUID, taskIDs []pgtype.UUID, includeWorkspaceOwned bool) (map[pgtype.UUID]struct{}, error) {
	visible := make(map[pgtype.UUID]struct{}, len(taskIDs))
	if len(taskIDs) == 0 || h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return visible, nil
	}
	// 2026-09-01 coder(lq): Apply the workspace-owner bypass switch to
	// projectless queue rows as well; otherwise task history could leak rows
	// after an owner disables workspace-wide project access.
	ownerClause := workspaceOwnerBypassPredicate("$1")
	if !includeWorkspaceOwned {
		ownerClause = "FALSE"
	}
	rows, err := h.DB.Query(ctx, fmt.Sprintf(`
		SELECT atq.id
		FROM unnest($3::uuid[]) requested(id)
		JOIN agent_task_queue atq ON atq.id = requested.id
		JOIN agent a ON a.id = atq.agent_id AND a.workspace_id = $1
		WHERE atq.issue_id IS NULL AND atq.chat_session_id IS NULL
		  AND (
			(%s AND EXISTS (SELECT 1 FROM member m WHERE m.workspace_id = $1 AND m.user_id = $2 AND m.role = 'owner'))
			OR atq.originator_user_id = $2
			OR atq.accountable_user_id = $2
			OR (
				a.kind = 'user'
				AND a.owner_id = $2
				AND EXISTS (
					SELECT 1
					FROM member agent_owner_member
					WHERE agent_owner_member.workspace_id = a.workspace_id
					  AND agent_owner_member.user_id = a.owner_id
				)
			)
		  )`, ownerClause), workspaceID, userID, taskIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id pgtype.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		visible[id] = struct{}{}
	}
	return visible, rows.Err()
}

// 2026-08-28 coder(lq): The upstream pending-chat query is creator-scoped,
// which is too narrow once project and projectless visibility are enabled.
// Load the workspace set here and let the shared permission adapter filter it
// by project, Chat creator, and Agent owner without changing sqlc output.
func (h *Handler) listPendingChatTasksWithProjectPermission(ctx context.Context, workspaceID pgtype.UUID) ([]db.ListPendingChatTasksByCreatorRow, error) {
	rows, err := h.DB.Query(ctx, `
		SELECT atq.id AS task_id, atq.status, atq.chat_session_id, cs.agent_id
		FROM agent_task_queue atq
		JOIN chat_session cs ON cs.id = atq.chat_session_id
		WHERE atq.chat_session_id IS NOT NULL
		  AND atq.status IN ('queued', 'dispatched', 'running', 'waiting_local_directory', 'deferred')
		  AND atq.regenerate_quick_actions_for IS NULL
		  AND cs.workspace_id = $1
		ORDER BY atq.created_at DESC`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]db.ListPendingChatTasksByCreatorRow, 0)
	for rows.Next() {
		var row db.ListPendingChatTasksByCreatorRow
		if err := rows.Scan(&row.TaskID, &row.Status, &row.ChatSessionID, &row.AgentID); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// 2026-08-27 coder(lq): Resolve chat-session visibility in one query to avoid
// an authorization round trip per task. Projectless Chat sessions use their
// creator, Agent-owner, and workspace-owner visibility rule.
func (h *Handler) visibleChatSessionIDsByProjectPermission(ctx context.Context, workspaceID, userID pgtype.UUID, sessionIDs []pgtype.UUID) (map[pgtype.UUID]struct{}, error) {
	return h.visibleChatSessionIDsByProjectPermissionWithWorkspaceScope(ctx, workspaceID, userID, sessionIDs, true)
}

// 2026-09-01 coder(lq): Carry the task-page owner toggle into chat-backed
// task projections as well as issue-backed projections.
func (h *Handler) visibleChatSessionIDsByProjectPermissionWithWorkspaceScope(ctx context.Context, workspaceID, userID pgtype.UUID, sessionIDs []pgtype.UUID, includeWorkspaceOwned bool) (map[pgtype.UUID]struct{}, error) {
	visible := make(map[pgtype.UUID]struct{}, len(sessionIDs))
	if len(sessionIDs) == 0 || h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return visible, nil
	}
	query := fmt.Sprintf(`SELECT requested.id
		FROM unnest($2::uuid[]) requested(id)
		JOIN chat_session cs ON cs.id = requested.id AND cs.workspace_id = $1
		WHERE %s`, chatProjectVisibilityPredicateWithWorkspaceScope("cs", "$1", "$3", includeWorkspaceOwned))
	rows, err := h.DB.Query(ctx, query, workspaceID, sessionIDs, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id pgtype.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		visible[id] = struct{}{}
	}
	return visible, rows.Err()
}

// 2026-08-27 coder(lq): The workspace-working-agents projection exposes one
// aggregate row per agent, but its upstream shape only carries issue IDs.
// For chat/mixed rows, verify every running task in the row is visible so a
// hidden project chat cannot leak the agent name or running count.
func (h *Handler) visibleWorkingAgentIDsByProjectPermission(ctx context.Context, workspaceID, userID pgtype.UUID, agentIDs []pgtype.UUID) (map[pgtype.UUID]struct{}, error) {
	return h.visibleWorkingAgentIDsByProjectPermissionWithWorkspaceScope(ctx, workspaceID, userID, agentIDs, true)
}

// 2026-09-01 coder(lq): The working-agents projection is a task-page
// side-channel, so it must honor the same workspace-owner bypass setting as
// the primary task list.
func (h *Handler) visibleWorkingAgentIDsByProjectPermissionWithWorkspaceScope(ctx context.Context, workspaceID, userID pgtype.UUID, agentIDs []pgtype.UUID, includeWorkspaceOwned bool) (map[pgtype.UUID]struct{}, error) {
	visible := make(map[pgtype.UUID]struct{}, len(agentIDs))
	if len(agentIDs) == 0 || h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return visible, nil
	}
	query := fmt.Sprintf(`SELECT atq.agent_id
		FROM agent_task_queue atq
		JOIN agent a ON a.id = atq.agent_id AND a.workspace_id = $1
		WHERE atq.agent_id = ANY($3::uuid[]) AND atq.status = 'running'
		GROUP BY atq.agent_id
		HAVING COUNT(*) FILTER (WHERE %s) = COUNT(*)`, projectVisibleTaskPredicateWithWorkspaceScope("atq", "$1", "$2", includeWorkspaceOwned))
	rows, err := h.DB.Query(ctx, query, workspaceID, userID, agentIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id pgtype.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		visible[id] = struct{}{}
	}
	return visible, rows.Err()
}

// 2026-08-27 coder(lq): Pending chat rows do not include their task's issue
// or session project in the upstream query shape. Resolve those links here so
// the aggregate FAB endpoints apply the same project boundary as transcript
// reads; tasks without a project-bound issue or chat session remain hidden.
func (h *Handler) filterPendingChatTasksByProjectPermissionWithWorkspaceScope(ctx context.Context, workspaceID, userID string, rows []db.ListPendingChatTasksByCreatorRow, includeWorkspaceOwned bool) ([]db.ListPendingChatTasksByCreatorRow, error) {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() || len(rows) == 0 {
		return rows, nil
	}
	issueIDs := make([]pgtype.UUID, 0, len(rows))
	chatSessionIDs := make([]pgtype.UUID, 0, len(rows))
	taskIDs := make([]pgtype.UUID, 0, len(rows))
	tasks := make([]db.AgentTaskQueue, len(rows))
	for i, row := range rows {
		task, taskErr := h.Queries.GetAgentTask(ctx, row.TaskID)
		if taskErr != nil {
			return nil, taskErr
		}
		tasks[i] = task
		if task.ID.Valid {
			taskIDs = append(taskIDs, task.ID)
		}
		if task.IssueID.Valid {
			issueIDs = append(issueIDs, task.IssueID)
		}
		if task.ChatSessionID.Valid {
			chatSessionIDs = append(chatSessionIDs, task.ChatSessionID)
		}
	}
	visibleIssues, err := h.visibleIssueIDsByProjectPermissionWithWorkspaceScope(ctx, parseUUID(workspaceID), parseUUID(userID), issueIDs, includeWorkspaceOwned)
	if err != nil {
		return nil, err
	}
	visibleChats, err := h.visibleChatSessionIDsByProjectPermissionWithWorkspaceScope(ctx, parseUUID(workspaceID), parseUUID(userID), chatSessionIDs, includeWorkspaceOwned)
	if err != nil {
		return nil, err
	}
	visibleUnscoped, err := h.visibleUnscopedTaskIDsByProjectPermissionWithWorkspaceScope(ctx, parseUUID(workspaceID), parseUUID(userID), taskIDs, includeWorkspaceOwned)
	if err != nil {
		return nil, err
	}
	filtered := make([]db.ListPendingChatTasksByCreatorRow, 0, len(rows))
	for i, row := range rows {
		// 2026-08-27 coder(lq): Keep pending-chat aggregation identical to
		// task history: issue context wins when both links exist, while
		// projectless chats and unscoped tasks use their creator/Agent-owner rule.
		if !taskVisibleByProjectPermission(tasks[i], visibleIssues, visibleChats, visibleUnscoped) {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered, nil
}

func (h *Handler) filterPendingChatTasksByProjectPermission(ctx context.Context, workspaceID, userID string, rows []db.ListPendingChatTasksByCreatorRow) ([]db.ListPendingChatTasksByCreatorRow, error) {
	return h.filterPendingChatTasksByProjectPermissionWithWorkspaceScope(ctx, workspaceID, userID, rows, true)
}

// 2026-08-27 coder(lq): Project pins use the same visibility scope as project
// lists. Returning a set lets callers filter mixed pin types without probing
// each project individually.
// 2026-09-03 coder(lq): Keep the owner-visibility switch consistent for
// secondary project consumers (pins, saved views, autopilot). The variadic
// argument preserves source compatibility for older callers that use the
// default inclusive scope.
func (h *Handler) visibleProjectIDSet(ctx context.Context, workspaceID, userID string, scope ...bool) (map[pgtype.UUID]struct{}, error) {
	visible := make(map[pgtype.UUID]struct{})
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return visible, nil
	}
	includeWorkspaceOwned := true
	if len(scope) > 0 {
		includeWorkspaceOwned = scope[0]
	}
	ids, err := h.ProjectAuth.ScopeWithWorkspaceOwned(ctx, projectauth.Subject{UserID: userID, WorkspaceID: workspaceID}, includeWorkspaceOwned)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		parsed := parseUUID(id)
		if parsed.Valid {
			visible[parsed] = struct{}{}
		}
	}
	return visible, nil
}

// 2026-08-24 coder(lq): Keep HTTP/error mapping in this thin adapter so the
// independent projectauth policy stays free of chi and generated DB models.
func (h *Handler) requireProjectPermission(w http.ResponseWriter, r *http.Request, projectID, workspaceID string, permission projectauth.Permission) bool {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return true
	}
	userID, ok := requireUserID(w, r)
	if !ok {
		return false
	}
	if workspaceID == "" {
		writeError(w, http.StatusBadRequest, "workspace_id is required")
		return false
	}
	member, err := h.getWorkspaceMember(r.Context(), userID, workspaceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return false
	}
	subject := projectauth.Subject{
		UserID:        userID,
		WorkspaceID:   workspaceID,
		WorkspaceRole: projectauth.WorkspaceRole(member.Role),
	}
	if err := h.ProjectAuth.RequireWithWorkspaceScope(r.Context(), subject, projectID, permission, includeWorkspaceOwnedFromRequest(r)); err != nil {
		// Project membership is intentionally indistinguishable from a missing
		// project to avoid leaking project IDs across the workspace boundary.
		if errors.Is(err, projectauth.ErrMigrationRequired) {
			writeErrorCode(w, http.StatusServiceUnavailable, "project_permission_migration_required", "project permission migration is required")
		} else if errors.Is(err, projectauth.ErrStorageUnavailable) || errors.Is(err, projectauth.ErrDisabled) {
			writeErrorCode(w, http.StatusServiceUnavailable, "project_permission_unavailable", "project permission storage is unavailable")
		} else if errors.Is(err, projectauth.ErrNotWorkspaceMember) || errors.Is(err, projectauth.ErrNoProjectAccess) {
			writeError(w, http.StatusNotFound, "project not found")
		} else if errors.Is(err, projectauth.ErrForbidden) {
			writeErrorCode(w, http.StatusForbidden, "project_permission_forbidden", "insufficient project permissions")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to check project permissions")
		}
		return false
	}
	return true
}

// 2026-08-27 coder(lq): Project-bound tasks inherit the issue's project;
// projectless tasks are visible only to their creator, member assignee, or
// workspace owner while the project-permission overlay is on.
func (h *Handler) requireIssueProjectPermission(w http.ResponseWriter, r *http.Request, issue db.Issue, permission projectauth.Permission) bool {
	ok, reason := h.issueProjectAllowedWithWorkspaceScope(r, issue, permission, includeWorkspaceOwnedFromRequest(r))
	if ok {
		return true
	}
	if reason == "projectless" {
		writeError(w, http.StatusNotFound, "task is not attached to a project")
	} else if reason == "migration" {
		writeErrorCode(w, http.StatusServiceUnavailable, "project_permission_migration_required", "project permission migration is required")
	} else if reason == "unavailable" {
		writeErrorCode(w, http.StatusServiceUnavailable, "project_permission_unavailable", "project permission storage is unavailable")
	} else if reason == "internal" {
		writeError(w, http.StatusInternalServerError, "failed to check project permissions")
	} else if reason == "forbidden" {
		writeErrorCode(w, http.StatusForbidden, "project_permission_forbidden", "insufficient project permissions")
	} else {
		writeError(w, http.StatusNotFound, "project not found")
	}
	return false
}

// 2026-08-24 coder(lq): Allow list handlers to filter unauthorized tasks
// without writing an HTTP response halfway through a successful page.
func (h *Handler) issueProjectAllowed(r *http.Request, issue db.Issue, permission projectauth.Permission) (bool, string) {
	return h.issueProjectAllowedWithWorkspaceScope(r, issue, permission, true)
}

// 2026-09-01 coder(lq): Query visibility is intentionally one-way: false can
// only remove the workspace-owner bypass, never grant additional access.
func includeWorkspaceOwnedFromRequest(r *http.Request) bool {
	return r.URL.Query().Get("include_workspace_owned") != "false"
}

func (h *Handler) issueProjectAllowedWithWorkspaceScope(r *http.Request, issue db.Issue, permission projectauth.Permission, includeWorkspaceOwned bool) (bool, string) {
	if h.ProjectAuth == nil {
		return true, ""
	}
	shadow := h.ProjectAuth.ShadowEnabled()
	if !h.ProjectAuth.Enabled() && !shadow {
		return true, ""
	}
	subject, reason := h.issuePermissionSubject(r, issue)
	if reason != "" {
		if shadow {
			h.Metrics.RecordProjectAuthorizationShadow("single", "candidate_deny")
			return true, ""
		}
		return false, reason
	}
	allowed, reason := h.effectiveIssueAccessAllowed(r.Context(), subject, uuidToString(issue.ID), permission, includeWorkspaceOwned)
	if shadow {
		result := "candidate_deny"
		if allowed {
			result = "match_allow"
		} else if reason == "unavailable" || reason == "migration" || reason == "internal" {
			result = "error"
		}
		h.Metrics.RecordProjectAuthorizationShadow("single", result)
		return true, ""
	}
	return allowed, reason
}

// issuePermissionSubject binds agent-process traffic to the human who
// originated the durable task. A task token therefore never inherits the
// runtime owner/server credential's broader rights. It also rechecks AgentUse
// on the source task for every issue read/write, so a revoke takes effect while
// an agent is already running rather than only at enqueue/claim boundaries.
func (h *Handler) issuePermissionSubject(r *http.Request, target db.Issue) (projectauth.Subject, string) {
	workspaceID := uuidToString(target.WorkspaceID)
	requestUser := requestUserID(r)
	actorType, actorID := h.resolveActor(r, requestUser, workspaceID)
	userID := requestUser
	if actorType == "agent" {
		task, ok := h.taskFromRequestHeader(r)
		if !ok || uuidToString(task.AgentID) != actorID || !task.OriginatorUserID.Valid {
			return projectauth.Subject{}, "denied"
		}
		userID = uuidToString(task.OriginatorUserID)
		// Autopilot and other scheduled runs carry no source issue, so there
		// is no AgentUse on a source issue left to re-check. Bind the subject
		// to the originator -- the same principal the list/search predicates
		// authorize against -- and let the target issue pass through the
		// ordinary View/Edit gate below. Refusing those tasks outright made
		// by-ID reads and write-backs fail with 404 "project not found" while
		// list/search kept working, which is the inconsistency this closes.
		if task.IssueID.Valid {
			source, err := h.Queries.GetIssue(r.Context(), task.IssueID)
			if err != nil || source.WorkspaceID != target.WorkspaceID {
				return projectauth.Subject{}, "denied"
			}
			sourceSubject := projectauth.Subject{UserID: userID, WorkspaceID: workspaceID}
			if allowed, sourceReason := h.effectiveIssueAccessAllowed(r.Context(), sourceSubject, uuidToString(source.ID), projectauth.AgentUse, true); !allowed {
				return projectauth.Subject{}, sourceReason
			}
		}
	}
	if userID == "" {
		return projectauth.Subject{}, "denied"
	}
	member, err := h.getWorkspaceMember(r.Context(), userID, workspaceID)
	if err != nil {
		return projectauth.Subject{}, "denied"
	}
	return projectauth.Subject{UserID: userID, WorkspaceID: workspaceID, WorkspaceRole: projectauth.WorkspaceRole(member.Role)}, ""
}

// authorizeIssueAgentUse is shared by enqueue and claim. Both phases call the
// same EffectiveAccessResolver and record only identifiers/decision metadata;
// issue bodies and ACL contents never enter authorization logs.
func (h *Handler) authorizeIssueAgentUse(ctx context.Context, issue db.Issue, originatorUserID pgtype.UUID, phase string) error {
	if h.ProjectAuth == nil {
		return nil
	}
	shadow := h.ProjectAuth.ShadowEnabled()
	if !h.ProjectAuth.Enabled() && !shadow {
		return nil
	}
	if !originatorUserID.Valid {
		h.Metrics.RecordProjectAuthorizationAgentClaim(phase, "deny")
		if shadow {
			return nil
		}
		return projectauth.ErrForbidden
	}
	subject := projectauth.Subject{UserID: uuidToString(originatorUserID), WorkspaceID: uuidToString(issue.WorkspaceID)}
	resolver := h.EffectiveIssueAccess
	if resolver == nil && h.DB != nil {
		if repo, ok := newProjectAuthRepository(h.DB).(projectauth.EffectiveAccessRepository); ok {
			resolver = projectauth.NewEffectiveAccessResolver(repo)
		}
	}
	if resolver == nil {
		return projectauth.ErrDisabled
	}
	err := resolver.CanIssue(ctx, subject, uuidToString(issue.ID), projectauth.AgentUse)
	if err == nil {
		h.Metrics.RecordProjectAuthorizationAgentClaim(phase, "allow")
		return nil
	}
	result := "deny"
	if errors.Is(err, projectauth.ErrStorageUnavailable) || errors.Is(err, projectauth.ErrMigrationRequired) || errors.Is(err, projectauth.ErrDisabled) {
		result = "error"
	}
	h.Metrics.RecordProjectAuthorizationAgentClaim(phase, result)
	if shadow {
		h.Metrics.RecordProjectAuthorizationShadow("single", "candidate_deny")
		return nil
	}
	if h.DB == nil {
		return projectauth.ErrStorageUnavailable
	}
	auditErr := (&projectAuthRepository{db: h.DB}).RecordAuthorizationAudit(ctx, projectauth.AuthorizationAuditEvent{
		WorkspaceID: subject.WorkspaceID,
		IssueID:     issueIDString(issue),
		ActorUserID: subject.UserID,
		Action:      "task_agent_use_denied",
		Details:     map[string]any{"phase": phase, "permission": projectauth.AgentUse},
	})
	if auditErr != nil {
		return projectauth.ErrStorageUnavailable
	}
	return err
}

func issueIDString(issue db.Issue) string { return uuidToString(issue.ID) }

// requireRestrictedSourcePublishAccess prevents a task running from a
// restricted issue from using a broader issue as an output channel merely
// because its originator inherits that target's project role. The destination
// needs a task-local authorization source (or the explicit workspace-owner
// bypass), which keeps restricted content inside its task boundary by default.
func (h *Handler) requireRestrictedSourcePublishAccess(w http.ResponseWriter, r *http.Request, target db.Issue) bool {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return true
	}
	requestUser := requestUserID(r)
	actorType, _ := h.resolveActor(r, requestUser, uuidToString(target.WorkspaceID))
	if actorType != "agent" {
		return true
	}
	task, ok := h.taskFromRequestHeader(r)
	if !ok || !task.IssueID.Valid || !task.OriginatorUserID.Valid {
		writeErrorCode(w, http.StatusForbidden, "task_publish_forbidden", "agent task authorization is unavailable")
		return false
	}
	if uuidToString(task.IssueID) == uuidToString(target.ID) {
		return true
	}
	source, err := h.Queries.GetIssue(r.Context(), task.IssueID)
	if err != nil || source.WorkspaceID != target.WorkspaceID {
		writeErrorCode(w, http.StatusForbidden, "task_publish_forbidden", "agent task authorization is invalid")
		return false
	}
	resolver := h.EffectiveIssueAccess
	if resolver == nil && h.DB != nil {
		if repo, repoOK := newProjectAuthRepository(h.DB).(projectauth.EffectiveAccessRepository); repoOK {
			resolver = projectauth.NewEffectiveAccessResolver(repo)
		}
	}
	if resolver == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, "project_permission_unavailable", "task authorization is unavailable")
		return false
	}
	subject := projectauth.Subject{UserID: uuidToString(task.OriginatorUserID), WorkspaceID: uuidToString(target.WorkspaceID)}
	sourceAccess, err := resolver.ResolveIssue(r.Context(), subject, uuidToString(source.ID))
	if err != nil {
		status := http.StatusForbidden
		code := "task_publish_forbidden"
		message := "agent task authorization is invalid"
		if errors.Is(err, projectauth.ErrStorageUnavailable) || errors.Is(err, projectauth.ErrMigrationRequired) || errors.Is(err, projectauth.ErrDisabled) {
			status, code, message = http.StatusServiceUnavailable, "project_permission_unavailable", "task authorization is unavailable"
		}
		writeErrorCode(w, status, code, message)
		return false
	}
	if sourceAccess.ProjectAccessMode != projectauth.ProjectAccessRestricted {
		return true
	}
	explanation, err := resolver.ExplainIssue(r.Context(), subject, uuidToString(target.ID), projectauth.IssueComment)
	if err != nil {
		status := http.StatusForbidden
		code := "task_publish_forbidden"
		message := "restricted task cannot publish to this task"
		if errors.Is(err, projectauth.ErrStorageUnavailable) || errors.Is(err, projectauth.ErrMigrationRequired) || errors.Is(err, projectauth.ErrDisabled) {
			status, code, message = http.StatusServiceUnavailable, "project_permission_unavailable", "task authorization is unavailable"
		}
		writeErrorCode(w, status, code, message)
		return false
	}
	for _, source := range explanation.Sources {
		if source.Source != projectauth.AccessSourceProjectDirect &&
			source.Source != projectauth.AccessSourceProjectOrg &&
			source.Source != projectauth.AccessSourceProjectEveryone &&
			source.Source != projectauth.AccessSourceParentIssue {
			return true
		}
	}
	writeErrorCode(w, http.StatusForbidden, "task_publish_forbidden", "restricted task requires explicit target-task permission before publishing")
	return false
}

// effectiveIssueAccessAllowed is the single handler adapter from an
// authenticated subject to an effective task decision. HTTP, plugin and
// aggregate paths all use it so their inheritance semantics cannot drift.
func (h *Handler) effectiveIssueAccessAllowed(ctx context.Context, subject projectauth.Subject, issueID string, permission projectauth.Permission, includeWorkspaceOwned bool) (bool, string) {
	started := time.Now()
	result := "deny"
	defer func() {
		h.Metrics.ObserveProjectAuthorization("single", time.Since(started))
		h.Metrics.RecordProjectAuthorizationDecision("resolve", result)
	}()
	resolver := h.EffectiveIssueAccess
	if resolver == nil && h.DB != nil {
		if repo, ok := newProjectAuthRepository(h.DB).(projectauth.EffectiveAccessRepository); ok {
			resolver = projectauth.NewEffectiveAccessResolver(repo)
		}
	}
	if resolver == nil {
		result = "error"
		return false, "unavailable"
	}
	explanation, err := resolver.ExplainIssue(ctx, subject, issueID, permission)
	if err != nil {
		result = "error"
		if errors.Is(err, projectauth.ErrMigrationRequired) {
			return false, "migration"
		}
		if errors.Is(err, projectauth.ErrStorageUnavailable) || errors.Is(err, projectauth.ErrDisabled) {
			return false, "unavailable"
		}
		if errors.Is(err, projectauth.ErrForbidden) {
			return false, "forbidden"
		}
		if errors.Is(err, projectauth.ErrInvalidIssuePermission) || errors.Is(err, projectauth.ErrInvalidRoleScope) || errors.Is(err, projectauth.ErrCrossWorkspace) {
			return false, "internal"
		}
		return false, "denied"
	}
	if !explanation.Allowed {
		return false, "forbidden"
	}
	if includeWorkspaceOwned {
		result = "allow"
		return true, ""
	}
	for _, source := range explanation.Sources {
		if source.Source != projectauth.AccessSourceWorkspaceOwner {
			result = "allow"
			return true, ""
		}
	}
	return false, "forbidden"
}

// 2026-08-24 coder(lq): Agent runs are task side effects, so they inherit the
// same project boundary as the issue and additionally require AgentUse.
func (h *Handler) issueAgentAllowed(r *http.Request, issue db.Issue) bool {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return true
	}
	allowed, _ := h.issueProjectAllowed(r, issue, projectauth.AgentUse)
	return allowed
}

func (h *Handler) requireNewIssueProjectPermission(w http.ResponseWriter, r *http.Request, workspaceID string, projectID pgtype.UUID, permission projectauth.Permission) bool {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return true
	}
	if !projectID.Valid {
		// 2026-09-06 coder(lq): Project permissions apply only when a task is
		// explicitly bound to a project. Projectless tasks keep the legacy
		// workspace/creator access rules and remain valid create targets.
		return true
	}
	return h.requireProjectPermission(w, r, uuidToString(projectID), workspaceID, permission)
}

// Parent-child links are task access edges independent of project ownership.
// Linking requires the parent's task-scoped child-create permission. The
// caller separately checks IssueCreate on an explicitly selected target
// project, so same-project, cross-project and projectless children all share
// one rule without treating a project role as a task role.
func (h *Handler) requireParentIssueProjectPermission(w http.ResponseWriter, r *http.Request, parent db.Issue, _ pgtype.UUID) bool {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return true
	}
	return h.requireIssueProjectPermission(w, r, parent, projectauth.IssueChildCreate)
}
