package handler

import "fmt"

// 2026-09-14 coder(lq): The zero scope retains the standalone ACL predicates.
// Heavy reads reuse those same rules with statement-local materialized sets;
// nothing survives a request, so revocation needs no cache invalidation.
type issueVisibilitySQL struct {
	materialized         bool
	projectsMaterialized bool
}

func issueVisibilityCTEs(workspaceRef, userRef string, includeWorkspaceOwned bool) string {
	principals := issueVisibilitySQL{materialized: true}
	issues := issueVisibilitySQL{materialized: true, projectsMaterialized: true}
	return fmt.Sprintf(`WITH issue_auth_organizations(organization_id) AS MATERIALIZED (
		%s
	), issue_auth_projects AS MATERIALIZED (
		SELECT visible_project.id FROM project visible_project
		WHERE visible_project.workspace_id = %s AND %s
	), issue_auth_visible AS MATERIALIZED (
		SELECT visible_issue.id FROM issue visible_issue
		WHERE visible_issue.workspace_id = %s AND %s
	)
	`, userOrganizationIDsSQL(workspaceRef, userRef), workspaceRef,
		principals.projectAccess("visible_project.id", workspaceRef, userRef), workspaceRef,
		issues.predicate("visible_issue", workspaceRef, userRef, includeWorkspaceOwned))
}

// 2026-09-14 coder(lq): Match issue_effective_status exactly: canonical keys
// take precedence over catalog overrides, and unknown keys stay nonterminal.
func terminalIssueStatusSetSQL(workspaceRef string) string {
	return fmt.Sprintf(`SELECT key FROM (VALUES ('done'), ('cancelled')) canonical(key)
		UNION
		SELECT key FROM issue_status
		WHERE workspace_id = %s AND category IN ('done', 'cancelled')
		  AND key NOT IN ('backlog', 'todo', 'in_progress', 'in_review', 'done', 'blocked', 'cancelled')`, workspaceRef)
}

func childIssueProgressAuthorizedSQL(includeWorkspaceOwned bool) string {
	return issueVisibilityCTEs("$1", "$2", includeWorkspaceOwned) + fmt.Sprintf(`
	SELECT i.parent_issue_id,
		COUNT(*)::bigint AS total,
		COUNT(*) FILTER (WHERE i.status IN (%s))::bigint AS done
	FROM issue i
	JOIN issue_auth_visible child_visible ON child_visible.id = i.id
	JOIN issue_auth_visible parent_visible ON parent_visible.id = i.parent_issue_id
	WHERE i.workspace_id = $1
	GROUP BY i.parent_issue_id`, terminalIssueStatusSetSQL("$1"))
}
