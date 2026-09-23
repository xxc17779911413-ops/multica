package handler

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// 2026-09-14 coder(lq): Compare materialized reads with the standalone policy,
// then exercise HTTP pagination and revocation on the same isolated fixture.
func TestIssueVisibilityCTEsMatchStandalonePolicy(t *testing.T) {
	ws := dbfx.Workspace(t, "Visibility SQL", "visibility-sql")
	user := dbfx.User(t, "Visibility reader", "visibility-sql@example.test")
	fx := testutil.New(testPool, ws, testUserID)
	fx.Member(t, ws, user, "member")
	fx.Member(t, ws, testUserID, "owner")
	project := fx.Project(t, "Shared project")
	privateProject := fx.Project(t, "Task shares only")
	creatorProject := fx.Project(t, "Creator fallback", testutil.Cols{"created_by": user})
	parent := fx.Issue(t, "Parent", testutil.Cols{"project_id": project})
	privateParent := fx.Issue(t, "Private parent", testutil.Cols{"project_id": privateProject})
	fx.Issue(t, "Done child", testutil.Cols{"project_id": project, "parent_issue_id": parent, "status": "done"})
	fx.Issue(t, "Archived child", testutil.Cols{"project_id": project, "parent_issue_id": parent, "status": "cancelled", "archived_at": testutil.Raw("now()")})
	fx.Issue(t, "Hidden child", testutil.Cols{"project_id": privateProject, "parent_issue_id": parent})
	fx.Issue(t, "Visible child hidden parent", testutil.Cols{"project_id": project, "parent_issue_id": privateParent})
	fx.Issue(t, "Task creator", testutil.Cols{"project_id": privateProject, "creator_id": user})
	fx.Issue(t, "Project creator", testutil.Cols{"project_id": creatorProject})
	fx.Issue(t, "Projectless assignee", testutil.Cols{"assignee_type": "member", "assignee_id": user})
	sharedTask := fx.Issue(t, "Direct share", testutil.Cols{"project_id": privateProject, "parent_issue_id": parent})
	roleTask := fx.Issue(t, "Task role", testutil.Cols{"project_id": privateProject, "parent_issue_id": parent})
	projectless := fx.Issue(t, "Projectless share", testutil.Cols{"parent_issue_id": parent})
	org := fx.Insert(t, "projectauth_organizations", testutil.Cols{"workspace_id": ws, "provider": "test", "external_id": "parent"})
	childOrg := fx.Insert(t, "projectauth_organizations", testutil.Cols{"workspace_id": ws, "provider": "test", "external_id": "child", "parent_id": org})
	fx.InsertNoID(t, "projectauth_organization_members", testutil.Cols{"workspace_id": ws, "organization_id": childOrg, "user_id": user}, "workspace_id = $1 AND user_id = $2", ws, user)
	grant := func(projectID string, issueID any, subjectType, subjectID string, extra testutil.Cols) {
		cols := testutil.Cols{"workspace_id": ws, "project_id": projectID, "issue_id": issueID, "subject_type": subjectType, "subject_id": subjectID}
		for key, value := range extra {
			cols[key] = value
		}
		fx.Insert(t, "projectauth_access_grants", cols)
	}
	grant(project, nil, "organization", org, testutil.Cols{"role_key": "viewer"})
	grant(privateProject, sharedTask, "user", user, testutil.Cols{"permission": "project.view"})
	grant(privateProject, roleTask, "user", user, testutil.Cols{"role_key": "task-only"})
	grant(privateProject, roleTask, "role", "task-only", testutil.Cols{"permission": "project.view"})
	// 2026-09-14 coder(lq): A sibling's role must not activate a project-wide grant.
	grant(privateProject, nil, "role", "task-only", testutil.Cols{"permission": "project.view"})
	fx.Insert(t, "projectauth_issue_access_grants", testutil.Cols{"workspace_id": ws, "issue_id": projectless, "subject_type": "everyone", "subject_id": ws, "role_key": "viewer"})

	check := func(t *testing.T, reader string, includeOwned bool) {
		t.Helper()
		old := "SELECT i.id FROM issue i WHERE i.workspace_id = $1 AND " + issueProjectVisibilityPredicateWithWorkspaceScope("i", "$1", "$2", includeOwned)
		ctes := issueVisibilityCTEs("$1", "$2", includeOwned)
		difference := ctes + fmt.Sprintf(`SELECT count(*) FROM (
			((%s) EXCEPT ALL (SELECT id FROM issue_auth_visible))
			UNION ALL
			((SELECT id FROM issue_auth_visible) EXCEPT ALL (%s))
		) differences`, old, old)
		if n := fx.Count(t, difference, ws, reader); n != 0 {
			t.Fatalf("materialized visibility differs by %d rows", n)
		}
		oldProgress := fmt.Sprintf(`SELECT i.parent_issue_id, count(*)::bigint total,
			count(*) FILTER (WHERE issue_effective_status(i.workspace_id, i.status) IN ('done', 'cancelled'))::bigint done
			FROM issue i JOIN issue p ON p.id = i.parent_issue_id AND p.workspace_id = i.workspace_id
			WHERE i.workspace_id = $1 AND %s AND %s GROUP BY i.parent_issue_id`,
			issueProjectVisibilityPredicateWithWorkspaceScope("i", "$1", "$2", includeOwned),
			issueProjectVisibilityPredicateWithWorkspaceScope("p", "$1", "$2", includeOwned))
		var before, after []byte
		fx.QueryRow(t, "SELECT COALESCE(jsonb_agg(row ORDER BY parent_issue_id), '[]') FROM ("+oldProgress+") row", ws, reader).Scan(&before)
		fx.QueryRow(t, "SELECT COALESCE(jsonb_agg(row ORDER BY parent_issue_id), '[]') FROM ("+childIssueProgressAuthorizedSQL(includeOwned)+") row", ws, reader).Scan(&after)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("progress mismatch: old=%s new=%s", before, after)
		}
	}
	for _, bypass := range []string{"true", "false"} {
		t.Run("owner-bypass-"+bypass, func(t *testing.T) {
			t.Setenv("PROJECT_OWNER_BYPASS_ENABLED", bypass)
			for _, reader := range []string{user, testUserID} {
				for _, includeOwned := range []bool{true, false} {
					check(t, reader, includeOwned)
				}
			}
		})
	}
	t.Setenv("PROJECT_OWNER_BYPASS_ENABLED", "false")
	previous := testHandler.ProjectAuth
	testHandler.ProjectAuth = projectauth.New(newProjectAuthRepository(testPool), true)
	t.Cleanup(func() { testHandler.ProjectAuth = previous })
	var expected int
	fx.QueryRow(t, issueVisibilityCTEs("$1", "$2", true)+`SELECT count(*) FROM issue i
		WHERE i.id IN (SELECT id FROM issue_auth_visible) AND i.archived_at IS NULL`, ws, user).Scan(&expected)
	for _, offset := range []int{0, 1, expected + 10} {
		req := newRequestAs(user, http.MethodGet, fmt.Sprintf("/api/issues?limit=1&offset=%d", offset), nil)
		req.Header.Set("X-Workspace-ID", ws)
		response := testutil.Call(t, testHandler.ListIssues, req).Want(http.StatusOK).Map()
		if response["total"] != float64(expected) {
			t.Fatalf("offset=%d total=%v want %d", offset, response["total"], expected)
		}
	}
	check(t, user, true)
	fx.Exec(t, "UPDATE projectauth_organizations SET parent_id = $1 WHERE id = $2", childOrg, org)
	check(t, user, true)
	fx.Exec(t, "UPDATE projectauth_organizations SET status = 'disabled' WHERE id = $1", org)
	check(t, user, true)
	// 2026-09-14 coder(lq): An empty role must disable the missing-role fallback.
	fx.Insert(t, "project_permission_roles", testutil.Cols{"workspace_id": ws, "role_key": "viewer", "name": "No view"})
	check(t, user, true)
	fx.Exec(t, "DELETE FROM projectauth_access_grants WHERE workspace_id = $1 AND subject_type = 'user'", ws)
	check(t, user, true)
	fx.Exec(t, "DELETE FROM member WHERE workspace_id = $1 AND user_id = $2", ws, user)
	check(t, user, true)
}

func TestTerminalIssueStatusSetMatchesEffectiveStatus(t *testing.T) {
	ws := dbfx.Workspace(t, "Status SQL", "status-sql")
	fx := testutil.New(testPool, ws, testUserID)
	for _, pair := range [][2]string{{"done", "todo"}, {"todo", "done"}, {"custom_done", "done"}, {"custom_cancelled", "cancelled"}, {"custom_active", "in_progress"}} {
		fx.Insert(t, "issue_status", testutil.Cols{"workspace_id": ws, "key": pair[0], "name": pair[0], "category": pair[1], "color": "#000000", "position": 0})
	}
	query := fmt.Sprintf(`SELECT count(*) FROM (
		VALUES ('backlog'), ('todo'), ('in_progress'), ('in_review'), ('done'), ('blocked'), ('cancelled'),
		('custom_done'), ('custom_cancelled'), ('custom_active'), ('unknown')
	) statuses(status)
	WHERE (issue_effective_status($1, status) IN ('done', 'cancelled'))
	IS DISTINCT FROM (status IN (%s))`, terminalIssueStatusSetSQL("$1"))
	if n := fx.Count(t, query, ws); n != 0 {
		t.Fatalf("terminal status set differs for %d keys", n)
	}
}

// 2026-09-14 coder(lq): Synthetic baseline sized like the reported incident.
// Run only against a disposable test database; no production records are used.
func BenchmarkIssueVisibilitySQL(b *testing.B) {
	for _, projects := range []int{1, 10} {
		b.Run(fmt.Sprintf("projects_%d", projects), func(b *testing.B) {
			benchmarkIssueVisibilitySQL(b, projects)
		})
	}
}

func benchmarkIssueVisibilitySQL(b *testing.B, projectCount int) {
	b.Setenv("PROJECT_OWNER_BYPASS_ENABLED", "false")
	ws := dbfx.Workspace(b, "Visibility benchmark", "visibility-benchmark")
	user := dbfx.User(b, "Benchmark reader", "visibility-benchmark@example.test")
	fx := testutil.New(testPool, ws, testUserID)
	fx.Member(b, ws, user, "member")
	projects := make([]string, projectCount)
	for i := range projects {
		projects[i] = fx.Project(b, fmt.Sprintf("Benchmark project %d", i))
	}
	project := projects[0]
	parent := fx.Issue(b, "Parent", testutil.Cols{"project_id": project})
	org := fx.Insert(b, "projectauth_organizations", testutil.Cols{"workspace_id": ws, "provider": "test", "external_id": "benchmark"})
	fx.InsertNoID(b, "projectauth_organization_members", testutil.Cols{"workspace_id": ws, "organization_id": org, "user_id": user}, "workspace_id = $1", ws)
	fx.Exec(b, `INSERT INTO issue (workspace_id, project_id, parent_issue_id, title, status, priority, creator_type, creator_id, number, position)
		SELECT $1, ($2::uuid[])[1 + (n - 1) % cardinality($2::uuid[])], $3, 'Child ' || n, CASE WHEN n % 2 = 0 THEN 'done' ELSE 'todo' END,
		'none', 'member', $4, n + 1, n FROM generate_series(1, 700) n`, ws, projects, parent, testUserID)
	fx.Cleanup(b, "DELETE FROM issue WHERE workspace_id = $1 AND parent_issue_id = $2", ws, parent)
	fx.Exec(b, `INSERT INTO projectauth_access_grants (workspace_id, project_id, subject_type, subject_id, role_key)
		SELECT $1, ($2::uuid[])[1 + (n - 1) % cardinality($2::uuid[])], 'organization',
		CASE WHEN n > 1300 - cardinality($2::uuid[]) THEN $3 ELSE gen_random_uuid()::text END, 'viewer'
		FROM generate_series(1, 1300) n`, ws, projects, org)
	fx.Cleanup(b, "DELETE FROM projectauth_access_grants WHERE workspace_id = $1", ws)
	fx.Exec(b, "ANALYZE issue")
	fx.Exec(b, "ANALYZE projectauth_access_grants")
	predicate := issueProjectVisibilityPredicateWithWorkspaceScope("i", "$1", "$2", true)
	oldProgress := fmt.Sprintf(`SELECT i.parent_issue_id, count(*) total,
		count(*) FILTER (WHERE issue_effective_status(i.workspace_id, i.status) IN ('done', 'cancelled')) done
		FROM issue i JOIN issue p ON p.id = i.parent_issue_id AND p.workspace_id = i.workspace_id
		WHERE i.workspace_id = $1 AND %s AND %s GROUP BY i.parent_issue_id`, predicate,
		issueProjectVisibilityPredicateWithWorkspaceScope("p", "$1", "$2", true))
	for _, scenario := range []struct{ name, sql string }{
		{"count_before", "SELECT count(*) FROM issue i WHERE i.workspace_id = $1 AND " + predicate},
		{"count_after", issueVisibilityCTEs("$1", "$2", true) + "SELECT count(*) FROM issue i WHERE i.workspace_id = $1 AND i.id IN (SELECT id FROM issue_auth_visible)"},
		{"progress_before", "SELECT COALESCE(sum(total) + sum(done), 0)::bigint FROM (" + oldProgress + ") progress"},
		{"progress_after", "SELECT COALESCE(sum(total) + sum(done), 0)::bigint FROM (" + childIssueProgressAuthorizedSQL(true) + ") progress"},
		{"selective_before", "SELECT count(*) FROM issue i WHERE i.workspace_id = $1 AND i.id = $3 AND " + predicate},
		{"selective_after", issueVisibilityCTEs("$1", "$2", true) + "SELECT count(*) FROM issue i WHERE i.workspace_id = $1 AND i.id = $3 AND i.id IN (SELECT id FROM issue_auth_visible)"},
	} {
		b.Run(scenario.name, func(b *testing.B) {
			args := []any{ws, user}
			if scenario.name == "selective_before" || scenario.name == "selective_after" {
				args = append(args, parent)
			}
			// 2026-09-14 coder(lq): Warm both plans past pgx/Postgres preparation
			// thresholds so repeated samples do not compare different plan modes.
			for range 10 {
				var count int
				if err := testPool.QueryRow(context.Background(), scenario.sql, args...).Scan(&count); err != nil {
					b.Fatal(err)
				}
			}
			for b.Loop() {
				var count int
				if err := testPool.QueryRow(context.Background(), scenario.sql, args...).Scan(&count); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
