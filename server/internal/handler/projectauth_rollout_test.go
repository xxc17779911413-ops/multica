package handler

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/metrics"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

type rolloutEffectiveResolver struct {
	resolved []string
	access   map[string]projectauth.EffectiveIssueAccess
}

func (r *rolloutEffectiveResolver) ResolveIssue(context.Context, projectauth.Subject, string) (projectauth.EffectiveIssueAccess, error) {
	return projectauth.EffectiveIssueAccess{}, nil
}
func (r *rolloutEffectiveResolver) ResolveIssues(_ context.Context, _ projectauth.Subject, issueIDs []string) (map[string]projectauth.EffectiveIssueAccess, error) {
	r.resolved = append([]string(nil), issueIDs...)
	return r.access, nil
}
func (r *rolloutEffectiveResolver) CanIssue(context.Context, projectauth.Subject, string, projectauth.Permission) error {
	return nil
}
func (r *rolloutEffectiveResolver) ExplainIssue(context.Context, projectauth.Subject, string, projectauth.Permission) (projectauth.PermissionExplanation, error) {
	return projectauth.PermissionExplanation{}, nil
}
func (r *rolloutEffectiveResolver) PreviewIssuePolicyChange(context.Context, projectauth.Subject, string, projectauth.ProjectAccessMode) (projectauth.PolicyImpact, error) {
	return projectauth.PolicyImpact{}, nil
}

func TestProjectAuthorizationActivationGate(t *testing.T) {
	tests := []struct {
		phase  projectauth.RolloutPhase
		want   bool
		status int
	}{
		{projectauth.RolloutOff, false, 404},
		{projectauth.RolloutShadow, false, 404},
		{projectauth.RolloutReader, true, 200},
		{projectauth.RolloutWriter, true, 200},
		{projectauth.RolloutRestricted, true, 200},
	}
	for _, tt := range tests {
		h := &Handler{ProjectAuth: projectauth.NewWithRollout(nil, tt.phase)}
		response := httptest.NewRecorder()
		got := h.requireProjectAuthorizationEnabled(response)
		if got != tt.want || response.Code != tt.status {
			t.Errorf("phase=%s: got (%v,%d), want (%v,%d)", tt.phase, got, response.Code, tt.want, tt.status)
		}
	}
}

func TestProjectAuthorizationShadowBatchNeverFiltersLegacyRows(t *testing.T) {
	issueID := parseUUID("0199aaef-0170-7000-8000-000000000001")
	resolver := &rolloutEffectiveResolver{access: map[string]projectauth.EffectiveIssueAccess{
		uuidToString(issueID): {IssueID: uuidToString(issueID)},
	}}
	h := &Handler{
		ProjectAuth:          projectauth.NewWithRollout(nil, projectauth.RolloutShadow),
		EffectiveIssueAccess: resolver,
		Metrics:              metrics.NewBusinessMetrics(),
	}
	tasks := []db.AgentTaskQueue{{ID: pgtype.UUID{Bytes: [16]byte{1}, Valid: true}, IssueID: issueID}}
	got, err := h.filterTasksByProjectPermissionWithWorkspaceScope(context.Background(), "workspace", "user", tasks, true)
	if err != nil {
		t.Fatalf("shadow filter: %v", err)
	}
	if len(got) != len(tasks) {
		t.Fatalf("shadow filter returned %d rows, want legacy %d", len(got), len(tasks))
	}
	if len(resolver.resolved) != 1 || resolver.resolved[0] != uuidToString(issueID) {
		t.Fatalf("shadow batch resolved %#v", resolver.resolved)
	}
}
