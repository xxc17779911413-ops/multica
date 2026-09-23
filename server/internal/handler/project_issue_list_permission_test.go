package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// 2026-08-27 coder(lq): Guard the two workspace-wide list surfaces together.
// Historical task grants must not bypass the project-level visibility boundary.
func TestProjectAndIssueListsRespectCurrentUserPermissions(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}

	ctx := context.Background()
	t.Setenv("PROJECT_OWNER_BYPASS_ENABLED", "true")
	memberID := createSecondWorkspaceMember(t)
	adminID := createPlainMember(t, "project-list-admin")
	if _, err := testPool.Exec(ctx, `UPDATE member SET role = 'admin' WHERE workspace_id = $1 AND user_id = $2`, testWorkspaceID, adminID); err != nil {
		t.Fatalf("promote project list admin: %v", err)
	}
	// 2026-09-20 coder(lq): The project fixtures below must have a creator that
	// is neither the owner, the granted member, nor the admin. Creating them as
	// the workspace owner gave the owner task-creator access, which is a
	// separate, legitimate path from the workspace-owner scope this test is
	// trying to measure — the assertion then failed for the wrong reason.
	creatorID := createPlainMember(t, "project-list-neutral-creator")
	projectIDs := make([]string, 2)
	issueIDs := make([]string, 2)
	projectlessIssueIDs := make([]string, 2)
	for i := range projectIDs {
		if err := testPool.QueryRow(ctx, `
			INSERT INTO project (workspace_id, title)
			VALUES ($1, $2)
			RETURNING id
		`, testWorkspaceID, fmt.Sprintf("Permission list project %d", i)).Scan(&projectIDs[i]); err != nil {
			t.Fatalf("create project %d: %v", i, err)
		}
		if err := testPool.QueryRow(ctx, `
			INSERT INTO issue (
				workspace_id, project_id, title, status, priority,
				creator_type, creator_id, number, position
			)
			VALUES (
				$1, $2, $3, 'todo', 'none', 'member', $4,
				(SELECT COALESCE(MAX(number), 0) + 1 FROM issue WHERE workspace_id = $1),
				100
			)
			RETURNING id
		`, testWorkspaceID, projectIDs[i], fmt.Sprintf("Permission list issue %d", i), creatorID).Scan(&issueIDs[i]); err != nil {
			t.Fatalf("create issue %d: %v", i, err)
		}
	}
	for i, values := range []struct {
		creatorType string
		creatorID   string
		assigneeID  *string
	}{
		{creatorType: "member", creatorID: memberID},
		{creatorType: "member", creatorID: testUserID, assigneeID: &memberID},
	} {
		var assigneeType any
		var assigneeID any
		if values.assigneeID != nil {
			assigneeType = "member"
			assigneeID = *values.assigneeID
		}
		if err := testPool.QueryRow(ctx, `
			INSERT INTO issue (
				workspace_id, title, status, priority,
				creator_type, creator_id, assignee_type, assignee_id,
				number, position
			)
			VALUES ($1, $2, 'todo', 'none', $3, $4, $5, $6,
				(SELECT COALESCE(MAX(number), 0) + 1 FROM issue WHERE workspace_id = $1),
				100)
			RETURNING id
		`, testWorkspaceID, fmt.Sprintf("Projectless permission issue %d", i), values.creatorType, values.creatorID, assigneeType, assigneeID).Scan(&projectlessIssueIDs[i]); err != nil {
			t.Fatalf("create projectless issue %d: %v", i, err)
		}
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(ctx, `DELETE FROM project WHERE id = ANY($1::uuid[])`, projectIDs)
		_, _ = testPool.Exec(ctx, `DELETE FROM issue WHERE id = ANY($1::uuid[])`, projectlessIssueIDs)
	})

	repository := &projectAuthRepository{db: testPool}
	if err := repository.AddProjectMember(ctx, projectIDs[0], memberID, projectauth.ProjectViewer); err != nil {
		t.Fatalf("grant visible project: %v", err)
	}
	// 2026-09-05 coder(lq): A task-member grant is intentionally limited to the
	// mention-specific view/comment permissions; an edit grant must not make the
	// task visible or add the user to the project.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO issue_permissions (issue_id, project_id, user_id, permission, granted_by)
		VALUES ($1, $2, $3, 'project.edit', $3)
	`, issueIDs[1], projectIDs[1], memberID); err != nil {
		t.Fatalf("grant legacy issue permission: %v", err)
	}

	previous := testHandler.ProjectAuth
	testHandler.ProjectAuth = projectauth.New(newProjectAuthRepository(testPool), true)
	t.Cleanup(func() { testHandler.ProjectAuth = previous })

	projectIDsFor := func(t *testing.T, userID string, includeWorkspaceOwned ...bool) map[string]bool {
		t.Helper()
		recorder := httptest.NewRecorder()
		path := "/api/projects?workspace_id=" + testWorkspaceID
		if len(includeWorkspaceOwned) > 0 && !includeWorkspaceOwned[0] {
			path += "&include_workspace_owned=false"
		}
		testHandler.ListProjects(recorder, newRequestAs(userID, http.MethodGet,
			path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("ListProjects: got %d: %s", recorder.Code, recorder.Body.String())
		}
		var response struct {
			Projects []ProjectResponse `json:"projects"`
		}
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatalf("decode projects: %v", err)
		}
		result := make(map[string]bool, len(response.Projects))
		for _, project := range response.Projects {
			result[project.ID] = true
		}
		return result
	}

	issueIDsFor := func(t *testing.T, userID string, includeWorkspaceOwned ...bool) map[string]bool {
		t.Helper()
		recorder := httptest.NewRecorder()
		path := "/api/issues?workspace_id=" + testWorkspaceID + "&limit=100"
		if len(includeWorkspaceOwned) > 0 && !includeWorkspaceOwned[0] {
			path += "&include_workspace_owned=false"
		}
		testHandler.ListIssues(recorder, newRequestAs(userID, http.MethodGet,
			path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("ListIssues: got %d: %s", recorder.Code, recorder.Body.String())
		}
		var response struct {
			Issues []IssueResponse `json:"issues"`
		}
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatalf("decode issues: %v", err)
		}
		result := make(map[string]bool, len(response.Issues))
		for _, issue := range response.Issues {
			result[issue.ID] = true
		}
		return result
	}

	memberProjects := projectIDsFor(t, memberID)
	if !memberProjects[projectIDs[0]] || memberProjects[projectIDs[1]] {
		t.Fatalf("member projects = %v; want only %s", memberProjects, projectIDs[0])
	}
	memberIssues := issueIDsFor(t, memberID)
	if !memberIssues[issueIDs[0]] || memberIssues[issueIDs[1]] {
		t.Fatalf("member issues = %v; want only %s", memberIssues, issueIDs[0])
	}
	for _, issueID := range projectlessIssueIDs {
		if !memberIssues[issueID] {
			t.Fatalf("member cannot see projectless issue %s; issues = %v", issueID, memberIssues)
		}
	}

	adminProjects := projectIDsFor(t, adminID)
	if len(adminProjects) != 0 {
		t.Fatalf("workspace admin without project grant can see projects = %v; want none", adminProjects)
	}
	adminIssues := issueIDsFor(t, adminID)
	if len(adminIssues) != 0 {
		t.Fatalf("workspace admin without project grant can see issues = %v; want none", adminIssues)
	}
	if err := repository.AddProjectMember(ctx, projectIDs[1], adminID, projectauth.ProjectViewer); err != nil {
		t.Fatalf("grant admin visible project: %v", err)
	}
	adminProjects = projectIDsFor(t, adminID)
	if !adminProjects[projectIDs[1]] || adminProjects[projectIDs[0]] {
		t.Fatalf("workspace admin projects after explicit grant = %v; want only %s", adminProjects, projectIDs[1])
	}
	adminIssues = issueIDsFor(t, adminID)
	if !adminIssues[issueIDs[1]] || adminIssues[issueIDs[0]] {
		t.Fatalf("workspace admin issues after explicit grant = %v; want only %s", adminIssues, issueIDs[1])
	}

	ownerProjects := projectIDsFor(t, testUserID)
	ownerIssues := issueIDsFor(t, testUserID)
	for i := range projectIDs {
		if !ownerProjects[projectIDs[i]] || !ownerIssues[issueIDs[i]] {
			t.Fatalf("workspace owner missing project/issue %d", i)
		}
	}

	ownerProjectsWithoutWorkspaceScope := projectIDsFor(t, testUserID, false)
	if len(ownerProjectsWithoutWorkspaceScope) != 0 {
		t.Fatalf("workspace owner projects with workspace scope hidden = %v; want none", ownerProjectsWithoutWorkspaceScope)
	}
	ownerIssuesWithoutWorkspaceScope := issueIDsFor(t, testUserID, false)
	for _, issueID := range issueIDs {
		if ownerIssuesWithoutWorkspaceScope[issueID] {
			t.Fatalf("workspace owner can see ungranted project issue %s with workspace scope hidden: %v", issueID, ownerIssuesWithoutWorkspaceScope)
		}
	}
	// A task's creator keeps access whichever workspace-owner scope is
	// requested: creator access is task-scoped and is asserted separately with
	// the owner switch disabled below. So only the projectless issue created by
	// another member must disappear here.
	if ownerIssuesWithoutWorkspaceScope[projectlessIssueIDs[0]] {
		t.Fatalf("workspace owner can see a projectless issue created by another member %s with workspace scope hidden: %v",
			projectlessIssueIDs[0], ownerIssuesWithoutWorkspaceScope)
	}
	if !ownerIssuesWithoutWorkspaceScope[projectlessIssueIDs[1]] {
		t.Fatalf("workspace owner lost the projectless issue they created %s with workspace scope hidden: %v",
			projectlessIssueIDs[1], ownerIssuesWithoutWorkspaceScope)
	}
	if err := repository.AddProjectMember(ctx, projectIDs[0], testUserID, projectauth.ProjectViewer); err != nil {
		t.Fatalf("grant owner explicit visible project: %v", err)
	}
	ownerProjectsWithoutWorkspaceScope = projectIDsFor(t, testUserID, false)
	if !ownerProjectsWithoutWorkspaceScope[projectIDs[0]] || ownerProjectsWithoutWorkspaceScope[projectIDs[1]] {
		t.Fatalf("workspace owner projects with explicit grant and workspace scope hidden = %v; want only %s", ownerProjectsWithoutWorkspaceScope, projectIDs[0])
	}
	ownerIssuesWithoutWorkspaceScope = issueIDsFor(t, testUserID, false)
	if !ownerIssuesWithoutWorkspaceScope[issueIDs[0]] || ownerIssuesWithoutWorkspaceScope[issueIDs[1]] {
		t.Fatalf("workspace owner issues with explicit grant and workspace scope hidden = %v; want only %s", ownerIssuesWithoutWorkspaceScope, issueIDs[0])
	}

	t.Setenv("PROJECT_OWNER_BYPASS_ENABLED", "false")
	ownerProjects = projectIDsFor(t, testUserID)
	if !ownerProjects[projectIDs[0]] || ownerProjects[projectIDs[1]] {
		t.Fatalf("workspace owner projects with bypass disabled = %v; want only explicit grant %s", ownerProjects, projectIDs[0])
	}
	ownerIssues = issueIDsFor(t, testUserID)
	if !ownerIssues[issueIDs[0]] || ownerIssues[issueIDs[1]] {
		t.Fatalf("workspace owner issues with bypass disabled = %v; want only explicit grant %s", ownerIssues, issueIDs[0])
	}
	if ownerIssues[projectlessIssueIDs[0]] || !ownerIssues[projectlessIssueIDs[1]] {
		t.Fatalf("workspace owner projectless issues with bypass disabled = %v; want only creator-owned issue %s", ownerIssues, projectlessIssueIDs[1])
	}
}
