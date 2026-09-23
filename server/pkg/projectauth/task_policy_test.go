package projectauth

import (
	"context"
	"errors"
	"testing"
)

// legacyGrantAdapter implements the unified grant contract but intentionally
// omits ResourceRepository. It is the red test for the enabled fail-closed
// task binding requirement.
type legacyGrantAdapter struct {
	workspace        WorkspaceRole
	project          ProjectRole
	projectWorkspace string
}

func (r *legacyGrantAdapter) WorkspaceRole(context.Context, string, string) (WorkspaceRole, error) {
	return r.workspace, nil
}
func (r *legacyGrantAdapter) ProjectRole(context.Context, string, string) (ProjectRole, error) {
	return r.project, nil
}
func (r *legacyGrantAdapter) ProjectWorkspace(context.Context, string) (string, error) {
	return r.projectWorkspace, nil
}
func (r *legacyGrantAdapter) VisibleProjectIDs(context.Context, string, string) ([]string, error) {
	return nil, nil
}
func (r *legacyGrantAdapter) ListAccessGrants(context.Context, string, string, string) ([]AccessGrant, error) {
	return nil, nil
}
func (r *legacyGrantAdapter) ListUserOrganizations(context.Context, string, string) ([]string, error) {
	return nil, nil
}
func (r *legacyGrantAdapter) UpsertAccessGrant(context.Context, AccessGrant) error { return nil }
func (r *legacyGrantAdapter) DeleteAccessGrant(context.Context, string, string, string, SubjectType, string, RoleKey, Permission) error {
	return nil
}

type fakeLegacyIssuePermissionRepo struct {
	fakeRepo
}

// sequencedGrantRepo lets the regression tests model a successful minimum
// project View check followed by a failing project permission lookup. A task
// direct grant is returned after that failure to prove it cannot mask the
// project-level error.
type sequencedGrantRepo struct {
	fakeGrantRepo
	responses []struct {
		grants []AccessGrant
		err    error
	}
	calls int
}

func (r *sequencedGrantRepo) ListAccessGrants(context.Context, string, string, string) ([]AccessGrant, error) {
	index := r.calls
	r.calls++
	if index >= len(r.responses) {
		return nil, nil
	}
	return r.responses[index].grants, r.responses[index].err
}

// 2026-08-27 coder(lq): Model an adapter that still exposes the historical
// issue grant lookup. CheckIssue must never call it after task permissions
// became fully inherited from the parent project.
func (f *fakeLegacyIssuePermissionRepo) IssuePermission(context.Context, string, string, string, Permission) (bool, error) {
	return true, nil
}

func TestCheckIssueInheritsProjectPermission(t *testing.T) {
	subject := Subject{UserID: "u-1", WorkspaceID: "ws-1"}
	service := New(&fakeRepo{
		workspace:        string(WorkspaceMember),
		project:          string(ProjectViewer),
		projectWorkspace: "ws-1",
		issueProject:     "project-1",
	}, true)

	if err := service.CheckIssue(context.Background(), subject, "issue-1", "project-1", View); err != nil {
		t.Fatalf("project viewer should view a bound task: %v", err)
	}
	if err := service.CheckIssue(context.Background(), subject, "issue-1", "project-1", Edit); !errors.Is(err, ErrForbidden) {
		t.Fatalf("project viewer editing a task got %v, want %v", err, ErrForbidden)
	}
}

// 2026-08-27 coder(lq): CheckIssue must preserve the exact project permission
// requested by the caller. This prevents a task endpoint from accidentally
// collapsing every operation to the project's View permission.
func TestCheckIssueDelegatesEveryPermissionToProject(t *testing.T) {
	subject := Subject{UserID: "u-1", WorkspaceID: "ws-1"}
	cases := []struct {
		name       string
		role       ProjectRole
		permission Permission
		want       bool
	}{
		{"viewer can view", ProjectViewer, View, true},
		{"viewer cannot edit", ProjectViewer, Edit, false},
		{"member cannot create issues through a task", ProjectMember, IssueCreate, false},
		{"member can comment on issues", ProjectMember, IssueComment, true},
		{"viewer cannot comment on issues", ProjectViewer, IssueComment, false},
		{"member cannot manage issues", ProjectMember, IssueManage, false},
		{"manager can manage issues", ProjectManager, IssueManage, true},
		{"manager can use agents", ProjectManager, AgentUse, true},
		{"manager cannot manage members", ProjectManager, MemberManage, false},
		{"owner cannot manage settings through a task", ProjectOwner, SettingsManage, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service := New(&fakeRepo{
				workspace:        string(WorkspaceMember),
				project:          string(tc.role),
				projectWorkspace: "ws-1",
				issueProject:     "project-1",
			}, true)
			err := service.CheckIssue(context.Background(), subject, "issue-1", "project-1", tc.permission)
			if (err == nil) != tc.want {
				t.Fatalf("CheckIssue(%s) got %v, want allowed=%v", tc.permission, err, tc.want)
			}
		})
	}
}

// 2026-09-05 coder(lq): Project roles still govern inherited task work, but
// project administration and task creation must never be reachable through a
// task URL, even for a project Owner.
func TestCheckIssueNeverEscalatesProjectAdministration(t *testing.T) {
	service := New(&fakeRepo{
		workspace:        string(WorkspaceMember),
		project:          string(ProjectOwner),
		projectWorkspace: "ws-1",
		issueProject:     "project-1",
	}, true)
	subject := Subject{UserID: "u-1", WorkspaceID: "ws-1"}

	for _, permission := range []Permission{IssueCreate, MemberManage, SettingsManage} {
		t.Run(string(permission), func(t *testing.T) {
			if err := service.CheckIssue(context.Background(), subject, "issue-1", "project-1", permission); !errors.Is(err, ErrForbidden) {
				t.Fatalf("CheckIssue(%s) = %v, want %v", permission, err, ErrForbidden)
			}
		})
	}
}

func TestCheckIssueRejectsUserWithoutProjectMembership(t *testing.T) {
	service := New(&fakeRepo{
		workspace:        string(WorkspaceMember),
		projectWorkspace: "ws-1",
		projectErr:       errors.New("project membership not found"),
		issueProject:     "project-1",
	}, true)
	subject := Subject{UserID: "u-1", WorkspaceID: "ws-1"}

	if err := service.CheckIssue(context.Background(), subject, "issue-1", "project-1", View); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member without project access got %v, want %v", err, ErrForbidden)
	}
}

// 2026-09-11 coder(lq): A task-level Member grant lets a workspace member
// work on that task without making the user a member of its parent project.
func TestCheckIssueAllowsDirectTaskMemberWithoutProjectMembership(t *testing.T) {
	repo := &fakeGrantRepo{
		fakeRepo: fakeRepo{
			workspace:        string(WorkspaceMember),
			projectWorkspace: "ws-1",
			issueProject:     "project-1",
		},
		grants: []AccessGrant{{
			ProjectID:   "project-1",
			IssueID:     "issue-1",
			SubjectType: SubjectUser,
			SubjectID:   "u-1",
			Role:        RoleKey(ProjectMember),
			Source:      GrantSourceSystem,
		}},
	}
	service := New(repo, true)
	subject := Subject{UserID: "u-1", WorkspaceID: "ws-1"}

	for _, permission := range []Permission{View, Edit, IssueComment, IssueChildCreate} {
		if err := service.CheckIssue(context.Background(), subject, "issue-1", "project-1", permission); err != nil {
			t.Fatalf("direct task Member should allow %s without project membership: %v", permission, err)
		}
	}
	if err := service.CheckIssue(context.Background(), subject, "issue-1", "project-1", MemberManage); !errors.Is(err, ErrForbidden) {
		t.Fatalf("task Member must not manage project members, got %v", err)
	}
}

func TestCheckIssueRequiresProjectBinding(t *testing.T) {
	service := New(&fakeRepo{
		workspace:        string(WorkspaceMember),
		project:          string(ProjectOwner),
		projectWorkspace: "ws-1",
	}, true)
	subject := Subject{UserID: "u-1", WorkspaceID: "ws-1"}

	for name, ids := range map[string][2]string{
		"missing issue":   {"", "project-1"},
		"missing project": {"issue-1", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if err := service.CheckIssue(context.Background(), subject, ids[0], ids[1], View); !errors.Is(err, ErrNoProjectAccess) {
				t.Fatalf("got %v, want %v", err, ErrNoProjectAccess)
			}
		})
	}
}

func TestCheckIssueDoesNotBypassProjectMembership(t *testing.T) {
	service := New(&fakeRepo{
		workspace:        string(WorkspaceMember),
		projectWorkspace: "ws-1",
		projectErr:       errors.New("project membership not found"),
		issueProject:     "project-1",
	}, true)
	subject := Subject{UserID: "u-1", WorkspaceID: "ws-1"}

	if err := service.CheckIssue(context.Background(), subject, "issue-1", "project-1", View); !errors.Is(err, ErrForbidden) {
		t.Fatalf("task access must inherit project membership, got %v", err)
	}
}

func TestCheckIssueIgnoresLegacyDirectGrant(t *testing.T) {
	repo := &fakeLegacyIssuePermissionRepo{fakeRepo: fakeRepo{
		workspace:        string(WorkspaceMember),
		projectWorkspace: "ws-1",
		projectErr:       errors.New("project membership not found"),
		issueProject:     "project-1",
	}}

	err := New(repo, true).CheckIssue(
		context.Background(),
		Subject{UserID: "u-1", WorkspaceID: "ws-1"},
		"issue-1",
		"project-1",
		View,
	)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("legacy task grant must not bypass project membership, got %v", err)
	}
}

func TestCheckIssueFailsClosedWithoutResourceRepository(t *testing.T) {
	repo := &legacyGrantAdapter{
		workspace:        WorkspaceMember,
		project:          ProjectViewer,
		projectWorkspace: "ws-1",
	}
	if err := New(repo, true).CheckIssue(context.Background(), Subject{UserID: "u-1", WorkspaceID: "ws-1"}, "issue-1", "project-1", View); !errors.Is(err, ErrMigrationRequired) {
		t.Fatalf("CheckIssue without resource repository = %v, want %v", err, ErrMigrationRequired)
	}
}

func TestCheckIssueDoesNotFallbackOnProjectGrantErrors(t *testing.T) {
	for _, projectErr := range []error{ErrStorageUnavailable, ErrNotWorkspaceMember, ErrNoProjectAccess} {
		t.Run(projectErr.Error(), func(t *testing.T) {
			repo := &sequencedGrantRepo{
				fakeGrantRepo: fakeGrantRepo{fakeRepo: fakeRepo{
					workspace:        string(WorkspaceMember),
					projectWorkspace: "ws-1",
					issueProject:     "project-1",
				}},
				responses: []struct {
					grants []AccessGrant
					err    error
				}{
					{grants: []AccessGrant{{ProjectID: "project-1", SubjectType: SubjectUser, SubjectID: "u-1", Permission: View}}},
					{err: projectErr},
					{grants: []AccessGrant{{ProjectID: "project-1", IssueID: "issue-1", SubjectType: SubjectUser, SubjectID: "u-1", Permission: Edit}}},
				},
			}

			err := New(repo, true).CheckIssue(
				context.Background(),
				Subject{UserID: "u-1", WorkspaceID: "ws-1"},
				"issue-1",
				"project-1",
				Edit,
			)
			if !errors.Is(err, projectErr) {
				t.Fatalf("CheckIssue error = %v, want project error %v", err, projectErr)
			}
			if repo.calls != 2 {
				t.Fatalf("task grant lookup ran after project error: %d calls, want 2", repo.calls)
			}
		})
	}
}
