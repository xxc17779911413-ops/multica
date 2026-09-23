package handler

import (
	"context"
	"net/http"
	"testing"

	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/internal/util"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// LC-797: every HTTP task guard must use EffectiveAccessResolver semantics.
// In particular, restricted disables only the current task's project source,
// while the direct parent's Base remains effective.
func TestIssueGuardUsesEffectiveAccessResolver(t *testing.T) {
	t.Setenv("PROJECT_OWNER_BYPASS_ENABLED", "false")
	ctx := context.Background()
	ws := dbfx.Workspace(t, "Effective guard", "effective-guard")
	reader := dbfx.User(t, "Effective reader", "effective-reader@example.test")
	fx := testutil.New(testPool, ws, testUserID)
	fx.Member(t, ws, reader, "member")
	project := fx.Project(t, "Effective project")
	parent := fx.Issue(t, "Effective parent", testutil.Cols{"project_id": project})
	child := fx.Issue(t, "Restricted child", testutil.Cols{"project_id": project, "parent_issue_id": parent})
	fx.Insert(t, "projectauth_access_grants", testutil.Cols{
		"workspace_id": ws, "project_id": project, "subject_type": "user", "subject_id": reader, "role_key": "viewer",
	})
	fx.InsertNoID(t, "projectauth_issue_policies", testutil.Cols{
		"workspace_id": ws, "issue_id": child, "project_access_mode": "restricted", "policy_version": 1,
	}, "workspace_id = $1 AND issue_id = $2", ws, child)

	previous := testHandler.ProjectAuth
	testHandler.ProjectAuth = projectauth.New(newProjectAuthRepository(testPool), true)
	t.Cleanup(func() { testHandler.ProjectAuth = previous })

	load := func(id string) bool {
		issueID, err := util.ParseUUID(id)
		if err != nil {
			t.Fatalf("parse issue %s: %v", id, err)
		}
		issue, err := testHandler.Queries.GetIssue(ctx, issueID)
		if err != nil {
			t.Fatalf("load issue %s: %v", id, err)
		}
		req := newRequestAs(reader, http.MethodGet, "/api/issues/"+id+"?workspace_id="+ws, nil)
		allowed, _ := testHandler.issueProjectAllowed(req, issue, projectauth.View)
		return allowed
	}

	if !load(child) {
		t.Fatal("restricted child should inherit the direct parent's project-backed Base")
	}
	fx.Exec(t, "UPDATE issue SET parent_issue_id = NULL WHERE id = $1", child)
	if load(child) {
		t.Fatal("restricted task without a direct source must not inherit its own project")
	}
}
