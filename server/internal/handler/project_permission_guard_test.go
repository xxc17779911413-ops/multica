package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// 2026-09-02 coder(lq): A project viewer may read an issue but must not mutate
// its conversation; comments use the dedicated issue-comment permission.
func TestCreateCommentRequiresProjectIssueCommentPermission(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	ctx := context.Background()
	var viewerID, projectID, issueID string
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user" (name, email)
		VALUES ('Project viewer guard', 'project-viewer-guard@multica.test')
		RETURNING id`).Scan(&viewerID); err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	t.Cleanup(func() { _, _ = testPool.Exec(ctx, `DELETE FROM "user" WHERE id = $1`, viewerID) })
	if _, err := testPool.Exec(ctx, `INSERT INTO member (workspace_id, user_id, role) VALUES ($1, $2, 'member')`, testWorkspaceID, viewerID); err != nil {
		t.Fatalf("add viewer workspace member: %v", err)
	}
	if err := testPool.QueryRow(ctx, `INSERT INTO project (workspace_id, title) VALUES ($1, 'Project viewer guard') RETURNING id`, testWorkspaceID).Scan(&projectID); err != nil {
		t.Fatalf("create project: %v", err)
	}
	t.Cleanup(func() { _, _ = testPool.Exec(ctx, `DELETE FROM project WHERE id = $1`, projectID) })
	repository := &projectAuthRepository{db: testPool}
	if err := repository.AddProjectMember(ctx, projectID, testUserID, projectauth.ProjectOwner); err != nil {
		t.Fatalf("add project owner: %v", err)
	}
	if err := repository.AddProjectMember(ctx, projectID, viewerID, projectauth.ProjectViewer); err != nil {
		t.Fatalf("add project viewer: %v", err)
	}
	if err := testPool.QueryRow(ctx, `
		INSERT INTO issue (workspace_id, project_id, title, status, priority, creator_type, creator_id, number, position)
		VALUES ($1, $2, 'Project viewer guard issue', 'todo', 'none', 'member', $3,
			(SELECT COALESCE(MAX(number), 0) + 1 FROM issue WHERE workspace_id = $1), 100)
		RETURNING id
	`, testWorkspaceID, projectID, testUserID).Scan(&issueID); err != nil {
		t.Fatalf("create issue: %v", err)
	}
	t.Cleanup(func() { _, _ = testPool.Exec(ctx, `DELETE FROM issue WHERE id = $1`, issueID) })

	previous := testHandler.ProjectAuth
	testHandler.ProjectAuth = projectauth.New(newProjectAuthRepository(testPool), true)
	t.Cleanup(func() { testHandler.ProjectAuth = previous })
	w := httptest.NewRecorder()
	req := newRequestAs(viewerID, http.MethodPost, "/api/issues/"+issueID+"/comments?workspace_id="+testWorkspaceID, map[string]any{"content": "should be rejected"})
	req = withURLParam(req, "id", issueID)
	testHandler.CreateComment(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer CreateComment: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// 2026-08-27 coder(lq): Comment reactions mutate task conversation state, so
// both add and remove must inherit the task project's Edit permission.
func TestCommentReactionRequiresProjectEditPermission(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	ctx := context.Background()
	deniedID := createSecondWorkspaceMember(t)
	var projectID, issueID, commentID string
	if err := testPool.QueryRow(ctx, `
		INSERT INTO project (workspace_id, title) VALUES ($1, 'Comment reaction permission guard') RETURNING id
	`, testWorkspaceID).Scan(&projectID); err != nil {
		t.Fatalf("create project: %v", err)
	}
	t.Cleanup(func() { _, _ = testPool.Exec(ctx, `DELETE FROM project WHERE id = $1`, projectID) })
	if err := (&projectAuthRepository{db: testPool}).AddProjectMember(ctx, projectID, testUserID, projectauth.ProjectOwner); err != nil {
		t.Fatalf("seed project owner: %v", err)
	}
	if err := testPool.QueryRow(ctx, `
		INSERT INTO issue (
			workspace_id, project_id, title, status, priority, creator_type, creator_id, number, position
		)
		VALUES ($1, $2, 'Comment reaction permission guard issue', 'todo', 'none', 'member', $3,
			(SELECT COALESCE(MAX(number), 0) + 1 FROM issue WHERE workspace_id = $1), 100)
		RETURNING id
	`, testWorkspaceID, projectID, testUserID).Scan(&issueID); err != nil {
		t.Fatalf("create issue: %v", err)
	}
	if err := testPool.QueryRow(ctx, `
		INSERT INTO comment (workspace_id, issue_id, author_type, author_id, content)
		VALUES ($1, $2, 'member', $3, 'reaction guard comment')
		RETURNING id
	`, testWorkspaceID, issueID, testUserID).Scan(&commentID); err != nil {
		t.Fatalf("create comment: %v", err)
	}

	previous := testHandler.ProjectAuth
	testHandler.ProjectAuth = projectauth.New(newProjectAuthRepository(testPool), true)
	t.Cleanup(func() { testHandler.ProjectAuth = previous })

	ownerAdd := httptest.NewRecorder()
	ownerAddReq := withURLParam(newRequestAs(testUserID, http.MethodPost,
		"/api/comments/"+commentID+"/reactions?workspace_id="+testWorkspaceID,
		map[string]any{"emoji": "thumbs_up"}), "commentId", commentID)
	testHandler.AddReaction(ownerAdd, ownerAddReq)
	if ownerAdd.Code != http.StatusCreated {
		t.Fatalf("owner AddReaction: expected 201, got %d: %s", ownerAdd.Code, ownerAdd.Body.String())
	}

	deniedAdd := httptest.NewRecorder()
	deniedAddReq := withURLParam(newRequestAs(deniedID, http.MethodPost,
		"/api/comments/"+commentID+"/reactions?workspace_id="+testWorkspaceID,
		map[string]any{"emoji": "heart"}), "commentId", commentID)
	testHandler.AddReaction(deniedAdd, deniedAddReq)
	if deniedAdd.Code != http.StatusForbidden {
		t.Fatalf("unauthorized AddReaction: expected 403, got %d: %s", deniedAdd.Code, deniedAdd.Body.String())
	}

	deniedRemove := httptest.NewRecorder()
	deniedRemoveReq := withURLParam(newRequestAs(deniedID, http.MethodDelete,
		"/api/comments/"+commentID+"/reactions?workspace_id="+testWorkspaceID,
		map[string]any{"emoji": "thumbs_up"}), "commentId", commentID)
	testHandler.RemoveReaction(deniedRemove, deniedRemoveReq)
	if deniedRemove.Code != http.StatusForbidden {
		t.Fatalf("unauthorized RemoveReaction: expected 403, got %d: %s", deniedRemove.Code, deniedRemove.Body.String())
	}

	var reactionCount int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM comment_reaction WHERE comment_id = $1`, commentID).Scan(&reactionCount); err != nil {
		t.Fatalf("count comment reactions: %v", err)
	}
	if reactionCount != 1 {
		t.Fatalf("unauthorized reaction mutations changed count to %d, want 1", reactionCount)
	}
}

// 2026-08-27 coder(lq): A saved project view is an indirect issue query
// surface, so it must inherit project View permission even when the view is
// shared or owned by another member.
func TestProjectScopedIssueViewInheritsProjectViewPermission(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	ctx := context.Background()
	var projectID, viewID string
	if err := testPool.QueryRow(ctx, `
		INSERT INTO project (workspace_id, title) VALUES ($1, 'Project view permission guard') RETURNING id
	`, testWorkspaceID).Scan(&projectID); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := (&projectAuthRepository{db: testPool}).AddProjectMember(ctx, projectID, testUserID, projectauth.ProjectOwner); err != nil {
		t.Fatalf("seed project owner: %v", err)
	}
	if err := testPool.QueryRow(ctx, `
		INSERT INTO issue_view (workspace_id, owner_id, name, scope_type, scope_id, visibility, definition_version, query, display)
		VALUES ($1, $2, 'Guarded project view', 'project', $3, 'workspace', 1, '{}', '{}')
		RETURNING id
	`, testWorkspaceID, testUserID, projectID).Scan(&viewID); err != nil {
		t.Fatalf("seed project view: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(ctx, `DELETE FROM pinned_item WHERE item_type = 'view' AND item_id = $1`, viewID)
		_, _ = testPool.Exec(ctx, `DELETE FROM issue_view WHERE id = $1`, viewID)
		_, _ = testPool.Exec(ctx, `DELETE FROM project WHERE id = $1`, projectID)
	})

	previous := testHandler.ProjectAuth
	testHandler.ProjectAuth = projectauth.New(newProjectAuthRepository(testPool), true)
	t.Cleanup(func() { testHandler.ProjectAuth = previous })
	deniedID := createSecondWorkspaceMember(t)

	create := httptest.NewRecorder()
	testHandler.CreateIssueView(create, newRequestAs(deniedID, http.MethodPost, "/api/issue-views?workspace_id="+testWorkspaceID, map[string]any{
		"name":       "Should be denied",
		"scope_type": "project",
		"scope_id":   projectID,
		"query":      map[string]any{},
	}))
	if create.Code != http.StatusForbidden {
		t.Fatalf("unauthorized project view create: expected 403, got %d: %s", create.Code, create.Body.String())
	}

	list := httptest.NewRecorder()
	testHandler.ListIssueViews(list, newRequestAs(deniedID, http.MethodGet,
		"/api/issue-views?workspace_id="+testWorkspaceID+"&scope_type=project&scope_id="+projectID, nil))
	if list.Code != http.StatusOK {
		t.Fatalf("unauthorized project view list: expected 200, got %d: %s", list.Code, list.Body.String())
	}
	var views []IssueViewResponse
	if err := json.NewDecoder(list.Body).Decode(&views); err != nil {
		t.Fatalf("decode project view list: %v", err)
	}
	for _, view := range views {
		if view.ID == viewID {
			t.Fatal("unauthorized project view leaked into list")
		}
	}

	get := httptest.NewRecorder()
	getReq := withURLParam(newRequestAs(deniedID, http.MethodGet, "/api/issue-views/"+viewID+"?workspace_id="+testWorkspaceID, nil), "id", viewID)
	testHandler.GetIssueViewByID(get, getReq)
	if get.Code != http.StatusNotFound {
		t.Fatalf("unauthorized project view read: expected 404, got %d: %s", get.Code, get.Body.String())
	}

	ownerPin := httptest.NewRecorder()
	testHandler.CreatePin(ownerPin, newRequestAs(testUserID, http.MethodPost, "/api/pins?workspace_id="+testWorkspaceID, map[string]any{
		"item_type": "view",
		"item_id":   viewID,
	}))
	if ownerPin.Code != http.StatusCreated {
		t.Fatalf("owner project view pin: expected 201, got %d: %s", ownerPin.Code, ownerPin.Body.String())
	}

	deniedPin := httptest.NewRecorder()
	testHandler.CreatePin(deniedPin, newRequestAs(deniedID, http.MethodPost, "/api/pins?workspace_id="+testWorkspaceID, map[string]any{
		"item_type": "view",
		"item_id":   viewID,
	}))
	if deniedPin.Code != http.StatusNotFound {
		t.Fatalf("unauthorized project view pin: expected 404, got %d: %s", deniedPin.Code, deniedPin.Body.String())
	}

	deniedPins := httptest.NewRecorder()
	testHandler.ListPins(deniedPins, newRequestAs(deniedID, http.MethodGet,
		"/api/pins?workspace_id="+testWorkspaceID+"&include=view", nil))
	if deniedPins.Code != http.StatusOK {
		t.Fatalf("unauthorized project view pin list: expected 200, got %d: %s", deniedPins.Code, deniedPins.Body.String())
	}
	var pins []PinnedItemResponse
	if err := json.NewDecoder(deniedPins.Body).Decode(&pins); err != nil {
		t.Fatalf("decode project view pin list: %v", err)
	}
	for _, pin := range pins {
		if pin.ItemType == "view" && pin.ItemID == viewID {
			t.Fatal("unauthorized project view pin leaked into list")
		}
	}
}

// 2026-08-27 coder(lq): Project-scoped view preferences must not become an
// oracle for projects that the caller cannot view, even though preferences are
// stored per user and do not themselves contain issue rows.
func TestProjectScopedIssueViewPreferenceInheritsProjectViewPermission(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	ctx := context.Background()
	var projectID string
	if err := testPool.QueryRow(ctx, `
		INSERT INTO project (workspace_id, title) VALUES ($1, 'Project preference permission guard') RETURNING id
	`, testWorkspaceID).Scan(&projectID); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := (&projectAuthRepository{db: testPool}).AddProjectMember(ctx, projectID, testUserID, projectauth.ProjectOwner); err != nil {
		t.Fatalf("seed project owner: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(ctx, `DELETE FROM issue_view_preference WHERE workspace_id = $1 AND scope_id = $2`, testWorkspaceID, projectID)
		_, _ = testPool.Exec(ctx, `DELETE FROM project WHERE id = $1`, projectID)
	})

	previous := testHandler.ProjectAuth
	testHandler.ProjectAuth = projectauth.New(newProjectAuthRepository(testPool), true)
	t.Cleanup(func() { testHandler.ProjectAuth = previous })
	deniedID := createSecondWorkspaceMember(t)

	ownerPut := httptest.NewRecorder()
	testHandler.PutIssueViewPreference(ownerPut, newRequestAs(testUserID, http.MethodPut, "/api/issue-view-preferences", map[string]any{
		"scope_type": "project",
		"scope_id":   projectID,
		"prefs":      map[string]any{"hidden": []string{"builtin:all"}},
	}))
	if ownerPut.Code != http.StatusOK {
		t.Fatalf("owner project preference put: expected 200, got %d: %s", ownerPut.Code, ownerPut.Body.String())
	}

	deniedGet := httptest.NewRecorder()
	testHandler.GetIssueViewPreference(deniedGet, newRequestAs(deniedID, http.MethodGet,
		"/api/issue-view-preferences?scope_type=project&scope_id="+projectID, nil))
	if deniedGet.Code != http.StatusForbidden {
		t.Fatalf("unauthorized project preference get: expected 403, got %d: %s", deniedGet.Code, deniedGet.Body.String())
	}

	deniedPut := httptest.NewRecorder()
	testHandler.PutIssueViewPreference(deniedPut, newRequestAs(deniedID, http.MethodPut, "/api/issue-view-preferences", map[string]any{
		"scope_type": "project",
		"scope_id":   projectID,
		"prefs":      map[string]any{"hidden": []string{}},
	}))
	if deniedPut.Code != http.StatusForbidden {
		t.Fatalf("unauthorized project preference put: expected 403, got %d: %s", deniedPut.Code, deniedPut.Body.String())
	}
}

// 2026-08-27 coder(lq): MoveIssue must enforce mutation permission before
// parsing move fields or resolving anchors, otherwise a viewer can distinguish
// validation errors and probe target-task metadata despite lacking Edit access.
func TestMoveIssueRequiresProjectEditPermissionBeforeValidation(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	ctx := context.Background()
	var projectID, issueID string
	if err := testPool.QueryRow(ctx, `
		INSERT INTO project (workspace_id, title) VALUES ($1, 'Move permission guard') RETURNING id
	`, testWorkspaceID).Scan(&projectID); err != nil {
		t.Fatalf("create project: %v", err)
	}
	repository := &projectAuthRepository{db: testPool}
	if err := repository.AddProjectMember(ctx, projectID, testUserID, projectauth.ProjectOwner); err != nil {
		t.Fatalf("seed project owner: %v", err)
	}
	if err := testPool.QueryRow(ctx, `
		INSERT INTO issue (
			workspace_id, project_id, title, status, priority, creator_type, creator_id,
			number, position
		)
		VALUES ($1, $2, 'Move permission guard issue', 'todo', 'none', 'member', $3,
			(SELECT COALESCE(MAX(number), 0) + 1 FROM issue WHERE workspace_id = $1), 100)
		RETURNING id
	`, testWorkspaceID, projectID, testUserID).Scan(&issueID); err != nil {
		t.Fatalf("create issue: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(ctx, `DELETE FROM issue WHERE id = $1`, issueID)
		_, _ = testPool.Exec(ctx, `DELETE FROM project WHERE id = $1`, projectID)
	})

	previous := testHandler.ProjectAuth
	testHandler.ProjectAuth = projectauth.New(newProjectAuthRepository(testPool), true)
	t.Cleanup(func() { testHandler.ProjectAuth = previous })
	viewerID := createSecondWorkspaceMember(t)
	if err := repository.AddProjectMember(ctx, projectID, viewerID, projectauth.ProjectViewer); err != nil {
		t.Fatalf("seed project viewer: %v", err)
	}

	w := httptest.NewRecorder()
	req := newRequestAs(viewerID, http.MethodPost, "/api/issues/"+issueID+"/move?workspace_id="+testWorkspaceID, map[string]any{
		"unsupported": true,
	})
	req = withURLParam(req, "id", issueID)
	testHandler.MoveIssue(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer MoveIssue: expected 403 before validation, got %d: %s", w.Code, w.Body.String())
	}
}

// 2026-08-27 coder(lq): A create-trigger preview is authorization-sensitive
// metadata. A project viewer (and a non-member) must not receive agent
// readiness for a project they cannot create issues in.
func TestPreviewIssueTriggerCreateRequiresProjectIssueCreatePermission(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	ctx := context.Background()
	var projectID string
	if err := testPool.QueryRow(ctx, `
		INSERT INTO project (workspace_id, title) VALUES ($1, 'Preview permission guard') RETURNING id
	`, testWorkspaceID).Scan(&projectID); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := (&projectAuthRepository{db: testPool}).AddProjectMember(ctx, projectID, testUserID, projectauth.ProjectOwner); err != nil {
		t.Fatalf("seed project owner: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(ctx, `DELETE FROM project WHERE id = $1`, projectID)
	})

	previous := testHandler.ProjectAuth
	testHandler.ProjectAuth = projectauth.New(newProjectAuthRepository(testPool), true)
	t.Cleanup(func() { testHandler.ProjectAuth = previous })
	deniedID := createSecondWorkspaceMember(t)

	w := httptest.NewRecorder()
	req := newRequestAs(deniedID, http.MethodPost,
		"/api/issues/preview-trigger?workspace_id="+testWorkspaceID,
		map[string]any{
			"is_create":     true,
			"project_id":    projectID,
			"assignee_type": "agent",
			"assignee_id":   seededReadyAgentID(t),
			"status":        "todo",
		})
	testHandler.PreviewIssueTrigger(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unauthorized create preview: expected 403, got %d: %s", w.Code, w.Body.String())
	}
	create := httptest.NewRecorder()
	testHandler.CreateIssue(create, newRequestAs(deniedID, http.MethodPost,
		"/api/issues?workspace_id="+testWorkspaceID,
		map[string]any{"title": "Unauthorized project create guard", "project_id": projectID}))
	if create.Code != http.StatusForbidden {
		t.Fatalf("unauthorized project create: expected 403, got %d: %s", create.Code, create.Body.String())
	}
}

// 2026-09-06 coder(lq): Project permissions gate only project-bound creates;
// projectless tasks remain valid even when the authorization overlay is on.
func TestProjectlessIssueCreateAndTriggerPreviewAllowedWhenPermissionsEnabled(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	previous := testHandler.ProjectAuth
	testHandler.ProjectAuth = projectauth.New(newProjectAuthRepository(testPool), true)
	t.Cleanup(func() { testHandler.ProjectAuth = previous })
	title := "Projectless issue permission guard " + t.Name()
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM issue WHERE workspace_id = $1 AND title = $2`, testWorkspaceID, title)
	})

	preview := httptest.NewRecorder()
	testHandler.PreviewIssueTrigger(preview, newRequestAs(testUserID, http.MethodPost,
		"/api/issues/preview-trigger?workspace_id="+testWorkspaceID,
		map[string]any{"is_create": true, "status": "todo"}))
	if preview.Code != http.StatusOK {
		t.Fatalf("projectless create preview: expected 200, got %d: %s", preview.Code, preview.Body.String())
	}

	// 2026-09-11 coder(lq): Earlier fixtures insert issue numbers directly;
	// align the workspace allocator before exercising the real create path.
	if _, err := testPool.Exec(context.Background(), `
		UPDATE workspace
		SET issue_counter = GREATEST(
			issue_counter,
			(SELECT COALESCE(MAX(number), 0) FROM issue WHERE workspace_id = $1)
		)
		WHERE id = $1
	`, testWorkspaceID); err != nil {
		t.Fatalf("synchronize issue counter: %v", err)
	}

	create := httptest.NewRecorder()
	testHandler.CreateIssue(create, newRequestAs(testUserID, http.MethodPost,
		"/api/issues?workspace_id="+testWorkspaceID,
		map[string]any{"title": title}))
	if create.Code != http.StatusCreated {
		t.Fatalf("projectless create: expected 201, got %d: %s", create.Code, create.Body.String())
	}
}
