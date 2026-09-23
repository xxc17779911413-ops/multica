package handler

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/testutil"
)

// Withdrawing a mention has to survive the reconciliation that runs on every
// later comment — otherwise the grant returns on the next edit — while a genuinely
// new mention must still grant again. The withdrawal is a watermark, not a ban.
func TestRevokingAMentionKeepsItRevokedUntilMentionedAgain(t *testing.T) {
	enableProjectAuthorizationForTest(t)
	ctx := context.Background()
	ws := dbfx.Workspace(t, "Mention revoke", "mention-revoke")
	fx := testutil.New(testPool, ws, testUserID)
	fx.Member(t, ws, testUserID, "owner")
	manager := dbfx.User(t, "Mention revoke manager", "mention-revoke-manager@example.test")
	mentioned := dbfx.User(t, "Mention revoke person", "mention-revoke-person@example.test")
	for _, user := range []string{manager, mentioned} {
		fx.Member(t, ws, user, "member")
	}
	project := fx.Project(t, "Mention revoke project")
	issue := fx.Issue(t, "Mention revoke task", testutil.Cols{"project_id": project})
	// The manager holds the task: the revoke endpoint is behind the same manage
	// gate as every other authorization write.
	fx.Insert(t, "projectauth_access_grants", testutil.Cols{"workspace_id": ws, "project_id": project, "issue_id": issue, "subject_type": "user", "subject_id": manager, "role_key": "manager", "source": "manual"})

	reconcile := func() {
		t.Helper()
		issueRow, err := testHandler.Queries.GetIssue(ctx, parseUUID(issue))
		if err != nil {
			t.Fatalf("load issue: %v", err)
		}
		if err := syncPrivateCommentMentionAccess(ctx, testPool, issueRow); err != nil {
			t.Fatalf("reconcile mentions: %v", err)
		}
	}
	mentionGrants := func() int {
		var count int
		fx.QueryRow(t, `SELECT count(*) FROM projectauth_access_grants
			WHERE workspace_id=$1 AND issue_id=$2 AND subject_type='user' AND subject_id=$3 AND source='system'`,
			ws, issue, mentioned).Scan(&count)
		return count
	}

	fx.Comment(t, issue, "first [@Mention revoke person](mention://member/"+mentioned+")")
	reconcile()
	if mentionGrants() == 0 {
		t.Fatal("the mention did not grant access, so there is nothing to withdraw")
	}

	req := newRequestAs(manager, http.MethodPost, "/api/issues/"+issue+"/access-control/revoke-mention",
		map[string]any{"subject_id": mentioned})
	req.Header.Set("X-Workspace-ID", ws)
	w := callIssueAccessEndpoint(testHandler.RevokeIssueMentionAccess, withURLParam(req, "id", issue))
	if w.Code != http.StatusOK {
		t.Fatalf("revoke mention: status=%d body=%s", w.Code, w.Body.String())
	}
	if mentionGrants() != 0 {
		t.Fatal("the withdrawn mention still grants access")
	}

	// The text still names them, so the next reconciliation must NOT hand the
	// grant back: that is the whole point of remembering the withdrawal.
	reconcile()
	if mentionGrants() != 0 {
		t.Fatal("reconciliation restored the withdrawn mention")
	}

	// A later mention is a new decision by a human and grants again.
	fx.Comment(t, issue, "asking again [@Mention revoke person](mention://member/"+mentioned+")",
		testutil.Cols{"created_at": time.Now().Add(time.Minute), "updated_at": time.Now().Add(time.Minute)})
	reconcile()
	if mentionGrants() == 0 {
		t.Fatal("mentioning the person again did not grant access")
	}
}
