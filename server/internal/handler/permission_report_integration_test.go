package handler

import (
	"context"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

func TestPermissionReportKeepsRoleScopesAndTaskInheritanceBoundaries(t *testing.T) {
	ctx := context.Background()
	ws := dbfx.Workspace(t, "Effective access dashboard", "effective-access-dashboard")
	fx := testutil.New(testPool, ws, testUserID)
	member := dbfx.User(t, "Dashboard member", "dashboard-member@example.test")
	fx.Member(t, ws, member, "member")
	project := fx.Project(t, "Dashboard project")
	inheritIssue := fx.Issue(t, "Inherited task", testutil.Cols{"project_id": project})
	restrictedIssue := fx.Issue(t, "Restricted task", testutil.Cols{"project_id": project})

	fx.Insert(t, "projectauth_access_grants", testutil.Cols{
		"workspace_id": ws, "project_id": project, "subject_type": "user",
		"subject_id": member, "role_key": "member", "source": "manual",
	})
	fx.Insert(t, "projectauth_access_grants", testutil.Cols{
		"workspace_id": ws, "project_id": project, "issue_id": restrictedIssue,
		"subject_type": "user", "subject_id": member, "role_key": "viewer", "source": "manual",
	})
	fx.InsertNoID(t, "projectauth_issue_policies", testutil.Cols{
		"workspace_id": ws, "issue_id": restrictedIssue, "project_access_mode": "restricted", "policy_version": 2,
	}, "workspace_id=$1 AND issue_id=$2", ws, restrictedIssue)

	repo := &projectAuthRepository{db: testPool}
	result, err := repo.ListPermissionReport(ctx, projectauth.PermissionReportFilter{
		WorkspaceID: ws, UserID: member, Scope: "issue", Limit: 1000,
	})
	if err != nil {
		t.Fatalf("ListPermissionReport: %v", err)
	}
	var sawInherited, sawRestrictedDirect bool
	for _, row := range result.Rows {
		if row.Permission == projectauth.IssueCreate || row.Permission == projectauth.MemberManage || row.Permission == projectauth.SettingsManage {
			t.Fatalf("project-only permission leaked to task row: %#v", row)
		}
		if row.IssueID == inheritIssue && row.InheritedFromProject {
			sawInherited = true
			if row.RoleScope != projectauth.RoleScopeProject || row.SourceResourceScope != projectauth.RoleScopeProject || row.ProjectAccessMode != projectauth.ProjectAccessInherit {
				t.Fatalf("invalid inherited explanation: %#v", row)
			}
		}
		if row.IssueID == restrictedIssue && row.InheritedFromProject {
			t.Fatalf("restricted task inherited project access: %#v", row)
		}
		if row.IssueID == restrictedIssue && !row.InheritedFromProject {
			sawRestrictedDirect = true
			if row.RoleScope != projectauth.RoleScopeTask || row.SourceResourceScope != projectauth.RoleScopeTask || row.PolicyVersion != 2 {
				t.Fatalf("invalid task explanation: %#v", row)
			}
		}
	}
	if !sawInherited || !sawRestrictedDirect {
		t.Fatalf("missing expected rows: inherited=%v restricted_direct=%v rows=%d", sawInherited, sawRestrictedDirect, len(result.Rows))
	}
}

func TestPermissionReportOmitsExpiredTaskGrant(t *testing.T) {
	ctx := context.Background()
	ws := dbfx.Workspace(t, "Expired dashboard grant", "expired-dashboard-grant")
	fx := testutil.New(testPool, ws, testUserID)
	member := dbfx.User(t, "Expired dashboard member", "expired-dashboard-member@example.test")
	fx.Member(t, ws, member, "member")
	project := fx.Project(t, "Expired dashboard project")
	issue := fx.Issue(t, "Expired dashboard task", testutil.Cols{"project_id": project})
	grant := fx.Insert(t, "projectauth_access_grants", testutil.Cols{
		"workspace_id": ws, "project_id": project, "issue_id": issue,
		"subject_type": "user", "subject_id": member, "role_key": "viewer", "source": "manual",
	})
	fx.InsertNoID(t, "projectauth_grant_constraints", testutil.Cols{
		"workspace_id": ws, "grant_id": grant, "expires_at": time.Now().Add(-time.Minute),
	}, "workspace_id=$1 AND grant_id=$2", ws, grant)

	result, err := (&projectAuthRepository{db: testPool}).ListPermissionReport(ctx, projectauth.PermissionReportFilter{
		WorkspaceID: ws, IssueID: issue, UserID: member, Scope: "issue", Limit: 1000,
	})
	if err != nil {
		t.Fatalf("ListPermissionReport: %v", err)
	}
	for _, row := range result.Rows {
		if row.GrantID == grant {
			t.Fatalf("expired grant was reported: %#v", row)
		}
	}
}
