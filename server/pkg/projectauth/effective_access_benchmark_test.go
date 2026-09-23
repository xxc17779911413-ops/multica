package projectauth

import (
	"context"
	"fmt"
	"testing"
)

var (
	benchmarkIssueAccess  EffectiveIssueAccess
	benchmarkBatchAccess  map[string]EffectiveIssueAccess
	benchmarkExplanation  PermissionExplanation
	benchmarkPolicyImpact PolicyImpact
)

// BenchmarkEffectiveAccessResolver is an algorithmic regression baseline. It
// deliberately uses the in-memory repository so storage latency can be
// measured separately with production-scale SQL and HTTP load tests.
func BenchmarkEffectiveAccessResolver(b *testing.B) {
	repo := effectiveFixture()
	repo.issueGrants["task"] = []AccessGrant{{
		ID: "direct", WorkspaceID: "ws", ProjectID: "project", IssueID: "task",
		SubjectType: SubjectUser, SubjectID: "user", Role: RoleKey(TaskMember), Scope: RoleScopeTask,
	}}
	repo.projectGrants["project"] = []AccessGrant{{
		ID: "project", WorkspaceID: "ws", ProjectID: "project",
		SubjectType: SubjectEveryone, Role: RoleKey(ProjectViewer), Scope: RoleScopeProject,
	}}
	issueIDs := make([]string, 100)
	for index := range issueIDs {
		issueID := fmt.Sprintf("task-%03d", index)
		issueIDs[index] = issueID
		repo.resources[issueID] = IssueAccessResource{
			WorkspaceID: "ws", IssueID: issueID, ProjectID: "project", ProjectWorkspaceID: "ws",
			CreatorUserID: "other", ProjectAccessMode: ProjectAccessInherit, PolicyVersion: 1,
		}
	}
	resolver := NewEffectiveAccessResolver(repo)
	subject := Subject{UserID: "user", WorkspaceID: "ws"}
	ctx := context.Background()

	b.Run("single", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			access, err := resolver.ResolveIssue(ctx, subject, "task")
			if err != nil {
				b.Fatal(err)
			}
			benchmarkIssueAccess = access
		}
	})
	b.Run("batch-100", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			access, err := resolver.ResolveIssues(ctx, subject, issueIDs)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkBatchAccess = access
		}
	})
	b.Run("explain", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			explanation, err := resolver.ExplainIssue(ctx, subject, "task", View)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkExplanation = explanation
		}
	})
	b.Run("preview", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			impact, err := resolver.PreviewIssuePolicyChange(ctx, subject, "task", ProjectAccessRestricted)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkPolicyImpact = impact
		}
	})
}
