package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/multica-ai/multica/server/internal/testutil"
)

// Mentioning somebody grants task access, and the grant is stored. Creating and
// editing a comment reconcile that stored text against the mentions; deleting one
// used to skip the reconciliation, so the access outlived the mention that
// justified it and only an unrelated comment edit would ever withdraw it.
func TestDeletingAMentionCommentWithdrawsTheAccessItGranted(t *testing.T) {
	ctx := context.Background()
	ws := dbfx.Workspace(t, "Mention delete", "mention-delete")
	fx := testutil.New(testPool, ws, testUserID)
	// The actor must be a member of this workspace: the delete path resolves them
	// before it looks at the comment.
	fx.Member(t, ws, testUserID, "owner")
	mentioned := dbfx.User(t, "Mention delete person", "mention-delete@example.test")
	fx.Member(t, ws, mentioned, "member")
	project := fx.Project(t, "Mention delete project")
	// The description stays clean: the only mention lives in the comment under
	// test, so withdrawing it must withdraw the access.
	issue := fx.Issue(t, "Mention delete task", testutil.Cols{"project_id": project})
	comment := fx.Comment(t, issue, "please look [@Mention delete person](mention://member/"+mentioned+")")

	issueRow, err := testHandler.Queries.GetIssue(ctx, parseUUID(issue))
	if err != nil {
		t.Fatalf("load issue: %v", err)
	}
	if err := syncPrivateCommentMentionAccess(ctx, testPool, issueRow); err != nil {
		t.Fatalf("reconcile mentions: %v", err)
	}
	mentionGrants := func() int {
		var count int
		fx.QueryRow(t, `SELECT count(*) FROM projectauth_access_grants
			WHERE workspace_id=$1 AND issue_id=$2 AND subject_type='user' AND subject_id=$3 AND source='system'`,
			ws, issue, mentioned).Scan(&count)
		return count
	}
	if mentionGrants() == 0 {
		t.Fatal("the mention did not grant access, so the delete cannot prove anything")
	}

	var visible int
	fx.QueryRow(t, `SELECT count(*) FROM comment WHERE id=$1 AND workspace_id=$2`, comment, ws).Scan(&visible)
	if visible != 1 {
		t.Fatalf("fixture comment is not visible in its own workspace (rows=%d)", visible)
	}

	w := httptest.NewRecorder()
	r := newRequestAs(testUserID, http.MethodDelete, "/api/comments/"+comment, nil)
	r.Header.Set("X-Workspace-ID", ws)
	testHandler.DeleteComment(w, withURLParam(r, "commentId", comment))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete comment: status=%d body=%s", w.Code, w.Body.String())
	}
	if remaining := mentionGrants(); remaining != 0 {
		t.Fatalf("access survived the comment that granted it: %d grant(s) remain", remaining)
	}
}
