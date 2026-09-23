package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/attribution"
	"github.com/multica-ai/multica/server/internal/service"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// 2026-08-27 coder(lq): Keep business-event membership wiring in one adapter
// so upstream project, issue, and comment handlers only call a narrow helper.
func promoteProjectMemberWithExecutor(ctx context.Context, executor dbExecutor, projectID, userID string, role projectauth.ProjectRole) error {
	if executor == nil || projectID == "" || userID == "" {
		return nil
	}
	return projectauth.New(newProjectAuthRepository(executor), true).PromoteMember(ctx, projectID, userID, role)
}

// 2026-09-07 coder(lq): Preserve the project-description mention behavior
// used by project create/update. Mentioned human members receive the project
// Viewer role; task/comment mentions are reconciled separately below.
func promoteMentionedMembersWithExecutor(ctx context.Context, executor dbExecutor, projectID, content string) error {
	for _, mention := range util.ParseMentions(content) {
		if mention.Type != "member" {
			continue
		}
		if err := promoteProjectMemberWithExecutor(ctx, executor, projectID, mention.ID, projectauth.ProjectViewer); err != nil {
			return err
		}
	}
	return nil
}

// 2026-08-28 coder(lq): Agents are permission aliases for their owning user.
// Resolve through the project workspace in the same query so an agent from a
// different workspace can never create a project grant accidentally.
func resolveAgentOwnerWithExecutor(ctx context.Context, executor dbExecutor, projectID, agentID string) (string, error) {
	if executor == nil || projectID == "" || agentID == "" {
		return "", nil
	}
	projectUUID, err := util.ParseUUID(projectID)
	if err != nil {
		return "", nil
	}
	agentUUID, err := util.ParseUUID(agentID)
	if err != nil {
		return "", nil
	}
	var ownerID pgtype.UUID
	err = executor.QueryRow(ctx, `
		SELECT a.owner_id
		FROM agent a
		JOIN project p ON p.workspace_id = a.workspace_id
		WHERE a.id = $1 AND p.id = $2 AND a.kind = 'user'`, agentUUID, projectUUID).Scan(&ownerID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	if !ownerID.Valid {
		return "", nil
	}
	return uuidToString(ownerID), nil
}

// 2026-08-28 coder(lq): Projectless issues still treat an Agent as its owning
// user, but there is no project row to anchor the lookup. Keep the workspace
// predicate explicit so an Agent from another workspace cannot grant access.
func resolveAgentOwnerInWorkspaceWithExecutor(ctx context.Context, executor dbExecutor, workspaceID, agentID string) (string, error) {
	if executor == nil || workspaceID == "" || agentID == "" {
		return "", nil
	}
	workspaceUUID, err := util.ParseUUID(workspaceID)
	if err != nil {
		return "", nil
	}
	agentUUID, err := util.ParseUUID(agentID)
	if err != nil {
		return "", nil
	}
	var ownerID pgtype.UUID
	err = executor.QueryRow(ctx, `
		SELECT owner_id
		FROM agent
		WHERE id = $1 AND workspace_id = $2 AND kind = 'user'`, agentUUID, workspaceUUID).Scan(&ownerID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	if !ownerID.Valid {
		return "", nil
	}
	return uuidToString(ownerID), nil
}

func promoteMemberLeadWithExecutor(ctx context.Context, executor dbExecutor, projectID string, leadType pgtype.Text, leadID pgtype.UUID) error {
	if !leadType.Valid || !leadID.Valid {
		return nil
	}
	leadUserID := ""
	switch leadType.String {
	case "member":
		leadUserID = uuidToString(leadID)
	case "agent":
		var err error
		leadUserID, err = resolveAgentOwnerWithExecutor(ctx, executor, projectID, uuidToString(leadID))
		if err != nil {
			return err
		}
	default:
		return nil
	}
	return promoteProjectMemberWithExecutor(ctx, executor, projectID, leadUserID, projectauth.ProjectOwner)
}

func resolveIssueAssigneeUserWithExecutor(ctx context.Context, executor dbExecutor, projectID string, assigneeType pgtype.Text, assigneeID pgtype.UUID) (string, error) {
	if !assigneeType.Valid || !assigneeID.Valid {
		return "", nil
	}
	switch assigneeType.String {
	case "member":
		return uuidToString(assigneeID), nil
	case "agent":
		return resolveAgentOwnerWithExecutor(ctx, executor, projectID, uuidToString(assigneeID))
	default:
		return "", nil
	}
}

// 2026-09-04 coder(lq): A task creator must retain Owner access to that task
// even when project-level access is restricted. Agent-authored tasks resolve
// to the owning human so the unified grant table remains user-scoped.
func resolveIssueCreatorUserWithExecutor(ctx context.Context, executor dbExecutor, issue db.Issue) (string, error) {
	if !issue.CreatorID.Valid {
		return "", nil
	}
	switch issue.CreatorType {
	case "member":
		return uuidToString(issue.CreatorID), nil
	case "agent":
		if issue.ProjectID.Valid {
			return resolveAgentOwnerWithExecutor(ctx, executor, uuidToString(issue.ProjectID), uuidToString(issue.CreatorID))
		}
		return resolveAgentOwnerInWorkspaceWithExecutor(ctx, executor, uuidToString(issue.WorkspaceID), uuidToString(issue.CreatorID))
	default:
		return "", nil
	}
}

// 2026-09-09 coder(lq): A human who delegates work to an Agent receives native
// notifications for tasks that Agent creates. Mirror that same delegated-human
// decision into task Member access so the subsequent inbox REST refresh can
// show and open the notification without granting project-wide permissions.
func resolveDelegatedIssueMemberWithExecutor(
	ctx context.Context,
	executor dbExecutor,
	workspaceID pgtype.UUID,
	creatorType string,
	originType pgtype.Text,
	originID pgtype.UUID,
) (string, error) {
	if executor == nil || creatorType != "agent" || !workspaceID.Valid || !originType.Valid || !originID.Valid {
		return "", nil
	}

	facts, err := db.New(executor).GetDelegatedSubscriptionFacts(ctx, db.GetDelegatedSubscriptionFactsParams{
		OriginTaskID: originID,
		WorkspaceID:  workspaceID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}

	human, _, ok := attribution.DelegatedSubscriber(attribution.SubscriptionFacts{
		CreatorType:      creatorType,
		OriginType:       originType.String,
		OriginOriginator: facts.OriginatorUserID,
		OriginRootSource: attribution.Source(facts.RootSource.String),
	})
	if !ok {
		return "", nil
	}

	// 2026-09-09 coder(lq): The originator is stamped when the Agent task is
	// queued. Re-check current workspace membership before materializing access
	// so a removed user cannot regain task visibility through a still-running
	// delegated task.
	var activeMember bool
	if err := executor.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM member WHERE workspace_id=$1 AND user_id=$2
		)`, workspaceID, human).Scan(&activeMember); err != nil {
		return "", err
	}
	if !activeMember {
		return "", nil
	}
	return uuidToString(human), nil
}

// 2026-09-01 coder(lq): Reconcile mention grants from the complete issue
// surface (description plus every comment). Grants are source=system, so a
// removed mention can be revoked safely without touching manual task shares;
// keeping the aggregate set also avoids revoking a user mentioned elsewhere
// on the same task. Mentions and assignees both receive the task Member role.
func syncIssueMentionAccessWithExecutor(ctx context.Context, executor dbExecutor, issueID, projectID, description string) error {
	desired := make(map[string]struct{})
	var workspaceUUID pgtype.UUID
	var creatorType string
	var originType pgtype.Text
	var originID pgtype.UUID
	issueQuery := `SELECT workspace_id, creator_type, origin_type, origin_id FROM issue WHERE id=$1`
	issueArgs := []any{issueID}
	if projectID != "" {
		issueQuery += ` AND project_id=$2`
		issueArgs = append(issueArgs, projectID)
	}
	if err := executor.QueryRow(ctx, issueQuery, issueArgs...).Scan(&workspaceUUID, &creatorType, &originType, &originID); err != nil {
		return err
	}
	workspaceID := uuidToString(workspaceUUID)
	// Mentions a manager explicitly withdrew stay withdrawn until the mention is
	// newer than the withdrawal (migration 528). Without this the reconciliation
	// would restore the revoked grant on the very next comment, because the text
	// still names the person.
	revokedAt, revokedDescriptionDigest, err := loadIssueMentionRevocations(ctx, executor, workspaceID, issueID)
	if err != nil {
		return err
	}
	descriptionDigest := mentionTextDigest(description)
	addMentions := func(content string, changedAt time.Time, isDescription bool) error {
		for _, mention := range util.ParseMentions(content) {
			if mention.Type != "member" && mention.Type != "agent" {
				continue
			}
			userID := mention.ID
			if mention.Type == "agent" {
				var err error
				if projectID != "" {
					userID, err = resolveAgentOwnerWithExecutor(ctx, executor, projectID, mention.ID)
				} else {
					userID, err = resolveAgentOwnerInWorkspaceWithExecutor(ctx, executor, workspaceID, mention.ID)
				}
				if err != nil {
					return err
				}
			}
			if userID == "" {
				continue
			}
			if _, already := desired[userID]; already {
				continue
			}
			if at, revoked := revokedAt[userID]; revoked {
				// A comment's own timestamps say whether it was written or edited
				// after the withdrawal. The description carries no timestamp of its
				// own, so it counts again only once that text actually changed.
				fresh := changedAt.After(at)
				if isDescription {
					fresh = descriptionDigest != revokedDescriptionDigest[userID]
				}
				if !fresh {
					continue
				}
			}
			desired[userID] = struct{}{}
		}
		return nil
	}
	if err := addMentions(description, time.Time{}, true); err != nil {
		return err
	}
	rows, err := executor.Query(ctx, `SELECT content, GREATEST(created_at, updated_at) FROM comment WHERE issue_id=$1`, issueID)
	if err != nil {
		return err
	}
	// 2026-09-04 coder(lq): Materialize comment content before resolving Agent
	// mentions. resolveAgentOwnerWithExecutor issues a QueryRow on the same
	// transaction connection; doing that while this result set is open makes
	// pgx return "conn busy".
	type commentMentionSource struct {
		content   string
		changedAt time.Time
	}
	commentContents := make([]commentMentionSource, 0)
	for rows.Next() {
		var source commentMentionSource
		if err := rows.Scan(&source.content, &source.changedAt); err != nil {
			rows.Close()
			return err
		}
		commentContents = append(commentContents, source)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, source := range commentContents {
		if err := addMentions(source.content, source.changedAt, false); err != nil {
			return err
		}
	}
	// Keep an assignee's automatic Member grant while reconciling mentions.
	// This helper is also called from comment transactions, so read the current
	// assignment from the same transaction instead of relying on a stale issue
	// value supplied by the caller.
	var assigneeType pgtype.Text
	var assigneeID pgtype.UUID
	assigneeQuery := `SELECT assignee_type, assignee_id FROM issue WHERE id=$1`
	assigneeArgs := []any{issueID}
	if projectID != "" {
		assigneeQuery += ` AND project_id=$2`
		assigneeArgs = append(assigneeArgs, projectID)
	}
	if err := executor.QueryRow(ctx, assigneeQuery, assigneeArgs...).Scan(&assigneeType, &assigneeID); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	} else {
		var assigneeUserID string
		var resolveErr error
		if projectID != "" {
			assigneeUserID, resolveErr = resolveIssueAssigneeUserWithExecutor(ctx, executor, projectID, assigneeType, assigneeID)
		} else {
			switch {
			case assigneeType.Valid && assigneeType.String == "member":
				assigneeUserID = uuidToString(assigneeID)
			case assigneeType.Valid && assigneeType.String == "agent":
				var workspaceID string
				if err := executor.QueryRow(ctx, `SELECT workspace_id::text FROM issue WHERE id=$1`, issueID).Scan(&workspaceID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				assigneeUserID, resolveErr = resolveAgentOwnerInWorkspaceWithExecutor(ctx, executor, workspaceID, uuidToString(assigneeID))
			}
		}
		if resolveErr != nil {
			return resolveErr
		}
		if assigneeUserID != "" {
			desired[assigneeUserID] = struct{}{}
		}
	}

	delegatedUserID, err := resolveDelegatedIssueMemberWithExecutor(
		ctx, executor, workspaceUUID, creatorType, originType, originID,
	)
	if err != nil {
		return err
	}
	if delegatedUserID != "" {
		desired[delegatedUserID] = struct{}{}
	}

	var currentRows pgx.Rows
	if projectID != "" {
		currentRows, err = executor.Query(ctx, `
			SELECT subject_id FROM projectauth_access_grants
			WHERE issue_id=$1 AND project_id=$2 AND subject_type='user'
			  AND role_key=$3 AND permission IS NULL AND source='system'`, issueID, projectID, string(projectauth.TaskMember))
	} else {
		currentRows, err = executor.Query(ctx, `
			SELECT subject_id FROM projectauth_issue_access_grants
			WHERE issue_id=$1 AND subject_type='user' AND role_key=$2 AND source='system'`, issueID, string(projectauth.TaskMember))
	}
	if err != nil {
		return err
	}
	var current []string
	for currentRows.Next() {
		var userID string
		if err := currentRows.Scan(&userID); err != nil {
			currentRows.Close()
			return err
		}
		current = append(current, userID)
	}
	if err := currentRows.Err(); err != nil {
		currentRows.Close()
		return err
	}
	currentRows.Close()
	for _, userID := range current {
		if _, keep := desired[userID]; keep {
			continue
		}
		var deleteErr error
		if projectID != "" {
			_, deleteErr = executor.Exec(ctx, `DELETE FROM projectauth_access_grants
				WHERE issue_id=$1 AND project_id=$2 AND subject_type='user' AND subject_id=$3
				  AND role_key=$4 AND permission IS NULL AND source='system'`, issueID, projectID, userID, string(projectauth.TaskMember))
		} else {
			_, deleteErr = executor.Exec(ctx, `DELETE FROM projectauth_issue_access_grants
				WHERE issue_id=$1 AND subject_type='user' AND subject_id=$2
				  AND role_key=$3 AND source='system'`, issueID, userID, string(projectauth.TaskMember))
		}
		if deleteErr != nil {
			return deleteErr
		}
	}
	for userID := range desired {
		var upsertErr error
		if projectID != "" {
			upsertErr = upsertIssueAccessGrant(ctx, executor, issueID, projectID, userID, projectauth.TaskMember)
		} else {
			upsertErr = upsertProjectlessIssueAccessGrant(ctx, executor, issueID, userID, projectauth.TaskMember)
		}
		if upsertErr != nil {
			return upsertErr
		}
	}
	return nil
}

// 2026-09-01 coder(lq): Synchronize automatic task grants after every issue
// write. Assignee and mention grants use the task Member role and are
// reconciled against current issue/comment content. Manual grants remain
// untouched because only source=system rows are removed.
func syncIssueAccessWithExecutor(ctx context.Context, executor dbExecutor, previous *db.Issue, issue db.Issue) error {
	if previous != nil && previous.ProjectID.Valid && (!issue.ProjectID.Valid || previous.ProjectID != issue.ProjectID) {
		_, err := executor.Exec(ctx, `DELETE FROM projectauth_access_grants WHERE issue_id=$1 AND source='system'`, uuidToString(issue.ID))
		if err != nil {
			return err
		}
	}
	issueID := uuidToString(issue.ID)
	if issue.ProjectID.Valid {
		// 2026-09-05 coder(lq): A task moved into a project no longer uses the
		// projectless grant store. Remove only automatic rows; manual grants are
		// intentionally preserved for the task-level API to reconcile.
		if _, err := executor.Exec(ctx, `DELETE FROM projectauth_issue_access_grants WHERE issue_id=$1 AND source='system'`, issueID); err != nil {
			return err
		}
	} else {
		creatorUserID, err := resolveIssueCreatorUserWithExecutor(ctx, executor, issue)
		if err != nil {
			return err
		}
		if creatorUserID != "" {
			if err := upsertProjectlessIssueAccessGrant(ctx, executor, issueID, creatorUserID, projectauth.TaskOwner); err != nil {
				return err
			}
		}
		return syncIssueMentionAccessWithExecutor(ctx, executor, issueID, "", issue.Description.String)
	}
	projectID := uuidToString(issue.ProjectID)
	creatorUserID, err := resolveIssueCreatorUserWithExecutor(ctx, executor, issue)
	if err != nil {
		return err
	}
	if creatorUserID != "" {
		if err := upsertIssueAccessGrant(ctx, executor, issueID, projectID, creatorUserID, projectauth.TaskOwner); err != nil {
			return err
		}
	}
	currentAssignee, err := resolveIssueAssigneeUserWithExecutor(ctx, executor, projectID, issue.AssigneeType, issue.AssigneeID)
	if err != nil {
		return err
	}
	previousAssignee := ""
	if previous != nil && previous.ProjectID.Valid && previous.ProjectID == issue.ProjectID {
		previousAssignee, err = resolveIssueAssigneeUserWithExecutor(ctx, executor, projectID, previous.AssigneeType, previous.AssigneeID)
		if err != nil {
			return err
		}
	}
	if previousAssignee != "" && previousAssignee != currentAssignee {
		if _, err := executor.Exec(ctx, `DELETE FROM projectauth_access_grants
			WHERE issue_id=$1 AND project_id=$2 AND subject_type='user' AND subject_id=$3
			  AND role_key=$4 AND permission IS NULL AND source='system'`, issueID, projectID, previousAssignee, string(projectauth.TaskMember)); err != nil {
			return err
		}
	}
	if currentAssignee != "" {
		if err := upsertIssueAccessGrant(ctx, executor, issueID, projectID, currentAssignee, projectauth.TaskMember); err != nil {
			return err
		}
	}
	return syncIssueMentionAccessWithExecutor(ctx, executor, issueID, projectID, issue.Description.String)
}

// 2026-09-05 coder(lq): Projectless issues need the same immutable creator,
// assignee, and mention roles as project-bound issues, but cannot use the
// project grant table because its project_id is intentionally NOT NULL.
func upsertProjectlessIssueAccessGrant(ctx context.Context, executor dbExecutor, issueID, userID string, role projectauth.TaskRole) error {
	var workspaceID string
	if err := executor.QueryRow(ctx, `SELECT workspace_id::text FROM issue WHERE id=$1`, issueID).Scan(&workspaceID); err != nil {
		return err
	}
	// 2026-09-05 coder(lq): A task creator is always Owner. If the creator is
	// also mentioned or assigned, normalize that automatic Member upsert to the
	// immutable Owner row instead of leaving two conflicting system roles.
	var creatorID string
	if err := executor.QueryRow(ctx, `
		SELECT CASE
			WHEN i.creator_type = 'member' THEN i.creator_id::text
			WHEN i.creator_type = 'agent' AND a.kind = 'user' AND a.owner_id IS NOT NULL THEN a.owner_id::text
			ELSE ''
		END
		FROM issue i
		LEFT JOIN agent a
		  ON a.id=i.creator_id AND a.workspace_id=i.workspace_id AND a.kind='user'
		WHERE i.id=$1::uuid AND i.project_id IS NULL`, issueID).Scan(&creatorID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if creatorID != "" && creatorID == userID && role == projectauth.TaskMember {
		role = projectauth.TaskOwner
		if _, err := executor.Exec(ctx, `
			DELETE FROM projectauth_issue_access_grants
			WHERE issue_id=$1::uuid AND subject_type='user' AND subject_id=$2
			  AND role_key=$3 AND source='system'`, issueID, userID, string(projectauth.TaskMember)); err != nil {
			return err
		}
	}
	_, err := executor.Exec(ctx, `
		INSERT INTO projectauth_issue_access_grants
			(workspace_id, issue_id, subject_type, subject_id, role_key, source, granted_by)
		VALUES ($1::uuid, $2::uuid, 'user', $3::text, $4, 'system', $5::uuid)
		ON CONFLICT (workspace_id, issue_id, subject_type, subject_id, role_key, source) DO NOTHING`,
		workspaceID, issueID, userID, string(role), userID)
	return err
}

// 2026-08-31 coder(lq): Keep automatic assignee/mention grants mirrored into
// the unified source while legacy issue_permissions remains available for
// rollback and older handlers. The canonical grant is always a task role;
// the legacy project.view row is compatibility data only.
func upsertIssueAccessGrant(ctx context.Context, executor dbExecutor, issueID, projectID, userID string, role projectauth.TaskRole) error {
	// 2026-09-05 coder(lq): Normalize every automatic task grant against the
	// task creator, not only the initial create path. A creator can also be the
	// assignee or a mention target; those events must not leave a duplicate
	// system Member row beside the immutable Owner row.
	var creatorID string
	err := executor.QueryRow(ctx, `
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
		WHERE i.id = $1::uuid AND i.project_id = $2::uuid`, issueID, projectID).Scan(&creatorID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if creatorID != "" && creatorID == userID {
		role = projectauth.TaskOwner
		if _, err := executor.Exec(ctx, `
			DELETE FROM projectauth_access_grants
			WHERE issue_id=$1::uuid AND project_id=$2::uuid AND subject_type='user'
			  AND subject_id=$3 AND role_key=$4 AND permission IS NULL AND source='system'`,
			issueID, projectID, userID, string(projectauth.TaskMember)); err != nil {
			return err
		}
	}
	if _, err := executor.Exec(ctx, `
		INSERT INTO issue_permissions (issue_id, project_id, user_id, permission, granted_by)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$3::uuid)
		ON CONFLICT (issue_id,user_id,permission) DO NOTHING`, issueID, projectID, userID, string(projectauth.View)); err != nil {
		return err
	}
	_, err = executor.Exec(ctx, `
		INSERT INTO projectauth_access_grants (workspace_id, project_id, issue_id, subject_type, subject_id, role_key, permission, source, granted_by)
		SELECT p.workspace_id, $2::uuid, $1::uuid, 'user', $3::text, $4, NULL, 'system', $3::uuid
		FROM project p WHERE p.id=$2::uuid
		ON CONFLICT DO NOTHING`, issueID, projectID, userID, string(role))
	return err
}

// 2026-08-27 coder(lq): All IssueService.Create transports use the same
// optional transaction hook, keeping projectauth out of the upstream service.
func (h *Handler) issueAccessBeforeCommit() func(context.Context, pgx.Tx, db.Issue) error {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return nil
	}
	return func(ctx context.Context, tx pgx.Tx, issue db.Issue) error {
		return syncIssueAccessWithExecutor(ctx, tx, nil, issue)
	}
}

var errIssueRelationshipForbidden = errors.New("issue relationship permission denied")

// validateIssueRelationshipWithExecutor re-checks the final relationship
// while the write transaction is still open. The early HTTP checks provide a
// useful response; this check closes project/parent/archive races and is the
// authority used by create and update.
func validateIssueRelationshipWithExecutor(ctx context.Context, executor dbExecutor, subject projectauth.Subject, issue db.Issue) error {
	if issue.ParentIssueID.Valid {
		var parentWorkspace pgtype.UUID
		var archivedAt pgtype.Timestamptz
		if err := executor.QueryRow(ctx, `
			SELECT workspace_id, archived_at
			FROM issue
			WHERE id=$1::uuid AND workspace_id=$2::uuid`, issue.ParentIssueID, issue.WorkspaceID).Scan(&parentWorkspace, &archivedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return service.ErrParentIssueNotFound
			}
			return err
		}
		if archivedAt.Valid {
			return service.ErrArchivedParentIssue
		}

		var cyclic bool
		if err := executor.QueryRow(ctx, `
			WITH RECURSIVE ancestors(id, parent_issue_id) AS (
				SELECT id, parent_issue_id FROM issue WHERE id=$1::uuid AND workspace_id=$2::uuid
				UNION
				SELECT i.id, i.parent_issue_id
				FROM issue i JOIN ancestors a ON i.id=a.parent_issue_id
				WHERE i.workspace_id=$2::uuid
			)
			SELECT EXISTS (SELECT 1 FROM ancestors WHERE id=$3::uuid)`, issue.ParentIssueID, issue.WorkspaceID, issue.ID).Scan(&cyclic); err != nil {
			return err
		}
		if cyclic {
			return errors.New("circular parent relationship detected")
		}

		repo := &projectAuthRepository{db: executor}
		access, err := projectauth.NewEffectiveAccessResolver(repo).ExplainIssue(ctx, subject, uuidToString(issue.ParentIssueID), projectauth.IssueChildCreate)
		if err != nil {
			return err
		}
		if !access.Allowed {
			return errIssueRelationshipForbidden
		}
	}
	if issue.ProjectID.Valid {
		repo := &projectAuthRepository{db: executor}
		if err := projectauth.New(repo, true).Check(ctx, subject, uuidToString(issue.ProjectID), projectauth.IssueCreate); err != nil {
			if errors.Is(err, projectauth.ErrForbidden) || errors.Is(err, projectauth.ErrNoProjectAccess) || errors.Is(err, projectauth.ErrNotWorkspaceMember) {
				return errIssueRelationshipForbidden
			}
			return err
		}
	}
	return nil
}

func (h *Handler) issueAccessBeforeCommitForSubject(subject projectauth.Subject) func(context.Context, pgx.Tx, db.Issue) error {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return nil
	}
	return func(ctx context.Context, tx pgx.Tx, issue db.Issue) error {
		if err := validateIssueRelationshipWithExecutor(ctx, tx, subject, issue); err != nil {
			return err
		}
		if !h.ProjectAuth.Enabled() {
			return nil
		}
		return syncIssueAccessWithExecutor(ctx, tx, nil, issue)
	}
}

// IssueAccessBeforeCommitForChannel exposes the narrow transaction hook needed
// by the channel engine without coupling that integration package to Handler's
// projectauth implementation.
// 2026-09-05 coder(lq): Wire channel-created task owners through the same
// atomic grant path as HTTP, onboarding, and autopilot issue creation.
func (h *Handler) IssueAccessBeforeCommitForChannel() func(context.Context, pgx.Tx, db.Issue) error {
	return h.issueAccessBeforeCommit()
}

// 2026-08-27 coder(lq): Ordinary issue updates do not otherwise need a
// transaction. Open one only while project authorization is enabled so the
// issue assignment/mention and its inherited project role cannot diverge.
func (h *Handler) updateIssueWithProjectAccess(ctx context.Context, workspaceID pgtype.UUID, statusKey string, params db.UpdateIssueParams, subjects ...projectauth.Subject) (db.Issue, error) {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		var issue db.Issue
		err := h.runWithIssueStatusGuard(ctx, workspaceID, statusKey, func(q *db.Queries) error {
			var updateErr error
			issue, updateErr = q.UpdateIssue(ctx, params)
			return updateErr
		})
		return issue, err
	}
	if h.TxStarter == nil {
		return db.Issue{}, errors.New("project access issue update requires transaction starter")
	}
	tx, err := h.TxStarter.Begin(ctx)
	if err != nil {
		return db.Issue{}, fmt.Errorf("begin project access issue update: %w", err)
	}
	defer tx.Rollback(ctx)

	qtx := h.Queries.WithTx(tx)
	if err := assertIssueStatusStillActive(ctx, qtx, workspaceID, statusKey); err != nil {
		return db.Issue{}, err
	}
	previous, err := qtx.GetIssueInWorkspace(ctx, db.GetIssueInWorkspaceParams{ID: params.ID, WorkspaceID: workspaceID})
	if err != nil {
		return db.Issue{}, err
	}
	issue, err := qtx.UpdateIssue(ctx, params)
	if err != nil {
		return db.Issue{}, err
	}
	if len(subjects) > 0 {
		if err := validateIssueRelationshipWithExecutor(ctx, tx, subjects[0], issue); err != nil {
			return db.Issue{}, err
		}
	}
	if h.ProjectAuth.Enabled() {
		if err := syncIssueAccessWithExecutor(ctx, tx, &previous, issue); err != nil {
			return db.Issue{}, fmt.Errorf("promote issue project access: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return db.Issue{}, fmt.Errorf("commit project access issue update: %w", err)
	}
	return issue, nil
}

// 2026-08-27 coder(lq): Persist a human comment and Member task access in one
// PostgreSQL transaction. Native comment triggers still handle agent/squad
// execution; this adapter also maps Agent mentions to their owner's Member
// grant without creating a separate Agent permission record.
func (h *Handler) createCommentWithProjectAccess(ctx context.Context, issue db.Issue, params db.CreateCommentParams) (db.CreateCommentRow, error) {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		return h.Queries.CreateComment(ctx, params)
	}
	if h.TxStarter == nil {
		return db.CreateCommentRow{}, errors.New("project access comment create requires transaction starter")
	}
	tx, err := h.TxStarter.Begin(ctx)
	if err != nil {
		return db.CreateCommentRow{}, fmt.Errorf("begin project access comment create: %w", err)
	}
	defer tx.Rollback(ctx)

	created, err := h.Queries.WithTx(tx).CreateComment(ctx, params)
	if err != nil {
		return db.CreateCommentRow{}, err
	}
	projectID := ""
	if issue.ProjectID.Valid {
		projectID = uuidToString(issue.ProjectID)
	}
	if err := syncIssueMentionAccessWithExecutor(ctx, tx, uuidToString(issue.ID), projectID, issue.Description.String); err != nil {
		return db.CreateCommentRow{}, fmt.Errorf("promote comment mention project access: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return db.CreateCommentRow{}, fmt.Errorf("commit project access comment create: %w", err)
	}
	return created, nil
}

// loadIssueMentionRevocations reads the withdrawal watermark every mention on
// this task is judged against, plus the description digest captured when it was
// withdrawn.
func loadIssueMentionRevocations(ctx context.Context, executor dbExecutor, workspaceID, issueID string) (map[string]time.Time, map[string]string, error) {
	revokedAt := make(map[string]time.Time)
	descriptionDigest := make(map[string]string)
	rows, err := executor.Query(ctx, `
		SELECT subject_id, revoked_at, description_digest
		FROM projectauth_issue_mention_revocations
		WHERE workspace_id=$1 AND issue_id=$2`, workspaceID, issueID)
	if err != nil {
		return revokedAt, descriptionDigest, err
	}
	defer rows.Close()
	for rows.Next() {
		var subjectID, digest string
		var at time.Time
		if err := rows.Scan(&subjectID, &at, &digest); err != nil {
			return revokedAt, descriptionDigest, err
		}
		revokedAt[subjectID] = at
		descriptionDigest[subjectID] = digest
	}
	return revokedAt, descriptionDigest, rows.Err()
}

// mentionTextDigest fingerprints the description so a withdrawal can tell "this
// text still names them" from "this text changed since I withdrew it".
func mentionTextDigest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
