package handler

import (
	"net/http"

	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// 2026-09-02 coder(lq): Keep archive mutations in their own handler so the
// retention feature remains easy to carry across upstream upgrades.

// rejectArchivedIssueMutation blocks operations that change task progress or
// launch new work. Comments, reactions, and comment attachments remain
// writable because they are part of the task conversation. Task-owned
// attachments are task-body mutations and are blocked while the issue is
// archived.
func rejectArchivedIssueMutation(w http.ResponseWriter, issue db.Issue) bool {
	if !issue.ArchivedAt.Valid {
		return false
	}
	writeError(w, http.StatusConflict, "archived task cannot be modified; restore it first")
	return true
}

// 2026-09-02 coder(lq): Archive keeps the timeline readable, but it must not
// create new execution work from comments or trigger previews.
func issueArchiveSuppressesAgentTriggers(issue db.Issue) bool {
	return issue.ArchivedAt.Valid
}
