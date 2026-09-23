package projectauth

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"
)

type fakeEffectiveAccessRepository struct {
	workspaceRole WorkspaceRole
	ownerBypass   bool
	resources     map[string]IssueAccessResource
	issueGrants   map[string][]AccessGrant
	projectGrants map[string][]AccessGrant
	organizations []string
	projectRoles  map[ProjectRole][]Permission
	taskRoles     map[TaskRole][]Permission
	errAt         string
}

func (f *fakeEffectiveAccessRepository) WorkspaceRole(context.Context, string, string) (WorkspaceRole, error) {
	if f.errAt == "workspace" {
		return "", errors.New("workspace unavailable")
	}
	return f.workspaceRole, nil
}
func (f *fakeEffectiveAccessRepository) WorkspaceOwnerBypassEnabled(context.Context, string) (bool, error) {
	if f.errAt == "owner" {
		return false, errors.New("switch unavailable")
	}
	return f.ownerBypass, nil
}
func (f *fakeEffectiveAccessRepository) IssueAccessResource(_ context.Context, _, issueID string) (IssueAccessResource, error) {
	if f.errAt == "resource" {
		return IssueAccessResource{}, errors.New("resource unavailable")
	}
	resource, ok := f.resources[issueID]
	if !ok {
		return IssueAccessResource{}, ErrNoProjectAccess
	}
	return resource, nil
}
func (f *fakeEffectiveAccessRepository) ListIssueAccessGrants(_ context.Context, _, issueID string) ([]AccessGrant, error) {
	if f.errAt == "issue-grants" {
		return nil, errors.New("grants unavailable")
	}
	return append([]AccessGrant(nil), f.issueGrants[issueID]...), nil
}
func (f *fakeEffectiveAccessRepository) ListProjectAccessGrants(_ context.Context, _, projectID string) ([]AccessGrant, error) {
	if f.errAt == "project-grants" {
		return nil, errors.New("grants unavailable")
	}
	return append([]AccessGrant(nil), f.projectGrants[projectID]...), nil
}
func (f *fakeEffectiveAccessRepository) ListUserOrganizations(context.Context, string, string) ([]string, error) {
	if f.errAt == "organizations" {
		return nil, errors.New("directory unavailable")
	}
	return append([]string(nil), f.organizations...), nil
}
func (f *fakeEffectiveAccessRepository) RolePermissions(_ context.Context, _ string, role ProjectRole) ([]Permission, bool, error) {
	if f.errAt == "project-role" {
		return nil, false, errors.New("role unavailable")
	}
	permissions, ok := f.projectRoles[role]
	return append([]Permission(nil), permissions...), ok, nil
}
func (f *fakeEffectiveAccessRepository) TaskRolePermissions(_ context.Context, _ string, role TaskRole) ([]Permission, bool, error) {
	if f.errAt == "task-role" {
		return nil, false, errors.New("role unavailable")
	}
	permissions, ok := f.taskRoles[role]
	return append([]Permission(nil), permissions...), ok, nil
}

func effectiveFixture() *fakeEffectiveAccessRepository {
	return &fakeEffectiveAccessRepository{
		workspaceRole: WorkspaceMember,
		resources: map[string]IssueAccessResource{
			"task": {WorkspaceID: "ws", IssueID: "task", ProjectID: "project", ProjectWorkspaceID: "ws", CreatorUserID: "creator", ProjectAccessMode: ProjectAccessInherit, PolicyVersion: 3},
		},
		issueGrants: map[string][]AccessGrant{}, projectGrants: map[string][]AccessGrant{},
		projectRoles: map[ProjectRole][]Permission{
			ProjectOwner:   {View, Edit, IssueCreate, IssueComment, IssueManage, IssueArchive, AgentUse, IssueChildCreate, MemberManage, SettingsManage},
			ProjectManager: {View, Edit, IssueCreate, IssueComment, IssueManage, AgentUse, IssueChildCreate},
			ProjectMember:  {View, IssueComment, AgentUse},
			ProjectViewer:  {View},
		},
		taskRoles: map[TaskRole][]Permission{
			TaskOwner:            allTaskPermissions(),
			TaskManager:          {View, Edit, IssueComment, IssueManage, IssueArchive, AgentUse, IssueChildCreate},
			TaskMember:           {View, Edit, IssueComment, IssueChildCreate},
			TaskViewer:           {View},
			TaskRole("reviewer"): {View, IssueComment},
		},
	}
}

func permissionsOf(access EffectiveIssueAccess) []Permission {
	result := append([]Permission(nil), access.Permissions...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func TestEffectiveAccessUsesIndependentTaskRoleCatalog(t *testing.T) {
	repo := effectiveFixture()
	repo.projectRoles[ProjectMember] = []Permission{View, MemberManage}
	repo.taskRoles[TaskMember] = []Permission{View, Edit, IssueComment}
	repo.issueGrants["task"] = []AccessGrant{{ID: "task-role", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Role: "member", Scope: RoleScopeTask}}
	repo.projectGrants["project"] = []AccessGrant{{ID: "project-role", WorkspaceID: "ws", ProjectID: "project", SubjectType: SubjectUser, SubjectID: "user", Role: "member", Scope: RoleScopeProject}}

	access, err := NewEffectiveAccessResolver(repo).ResolveIssue(context.Background(), Subject{UserID: "user", WorkspaceID: "ws"}, "task")
	if err != nil {
		t.Fatal(err)
	}
	want := []Permission{Edit, IssueComment, View}
	if got := permissionsOf(access); !reflect.DeepEqual(got, want) {
		t.Fatalf("permissions = %v, want %v", got, want)
	}
	for _, source := range access.Sources {
		if source.Role == "member" && source.Scope == "" {
			t.Fatal("role source omitted scope")
		}
		if source.Permission == MemberManage {
			t.Fatal("project administration leaked into task")
		}
	}
}

func TestEffectiveAccessSupportsSystemAndCustomTaskRoles(t *testing.T) {
	for role, want := range map[TaskRole][]Permission{
		TaskOwner: allTaskPermissions(), TaskManager: {View, Edit, IssueComment, IssueManage, IssueArchive, AgentUse, IssueChildCreate},
		TaskMember: {View, Edit, IssueComment, IssueChildCreate}, TaskViewer: {View},
		TaskRole("reviewer"): {View, IssueComment},
	} {
		t.Run(string(role), func(t *testing.T) {
			repo := effectiveFixture()
			repo.issueGrants["task"] = []AccessGrant{{ID: "g", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Role: RoleKey(role), Scope: RoleScopeTask}}
			access, err := NewEffectiveAccessResolver(repo).ResolveIssue(context.Background(), Subject{UserID: "user", WorkspaceID: "ws"}, "task")
			if err != nil {
				t.Fatal(err)
			}
			sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
			if got := permissionsOf(access); !reflect.DeepEqual(got, want) {
				t.Fatalf("permissions = %v, want %v", got, want)
			}
		})
	}
}

func TestEffectiveAccessMergesTaskIdentityAndGrantSources(t *testing.T) {
	repo := effectiveFixture()
	resource := repo.resources["task"]
	resource.CreatorUserID, resource.AssigneeUserID, resource.OriginatorUserID = "user", "user", "user"
	repo.resources["task"] = resource
	repo.organizations = []string{"department"}
	repo.issueGrants["task"] = []AccessGrant{
		{ID: "direct", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Permission: IssueManage},
		{ID: "org", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectOrganization, SubjectID: "department", Role: "viewer", Scope: RoleScopeTask},
		{ID: "everyone", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectEveryone, Role: "viewer", Scope: RoleScopeTask},
		{ID: "mention", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Role: "member", Scope: RoleScopeTask, Source: GrantSourceSystem},
	}
	access, err := NewEffectiveAccessResolver(repo).ResolveIssue(context.Background(), Subject{UserID: "user", WorkspaceID: "ws"}, "task")
	if err != nil {
		t.Fatal(err)
	}
	wantSources := map[AccessSourceKind]bool{AccessSourceCreator: false, AccessSourceAssignee: false, AccessSourceOriginator: false, AccessSourceIssueDirect: false, AccessSourceIssueOrg: false, AccessSourceIssueEveryone: false, AccessSourceMention: false}
	for _, source := range access.Sources {
		if _, ok := wantSources[source.Source]; ok {
			wantSources[source.Source] = true
		}
	}
	for source, found := range wantSources {
		if !found {
			t.Errorf("missing source %s", source)
		}
	}
}

func TestEffectiveAccessProjectModesAndProjectlessTasks(t *testing.T) {
	for _, mode := range []ProjectAccessMode{ProjectAccessInherit, ProjectAccessRestricted} {
		t.Run(string(mode), func(t *testing.T) {
			repo := effectiveFixture()
			resource := repo.resources["task"]
			resource.ProjectAccessMode = mode
			repo.resources["task"] = resource
			repo.projectGrants["project"] = []AccessGrant{{ID: "p", WorkspaceID: "ws", ProjectID: "project", SubjectType: SubjectUser, SubjectID: "user", Permission: Edit}}
			repo.issueGrants["task"] = []AccessGrant{{ID: "t", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Permission: View}}
			access, err := NewEffectiveAccessResolver(repo).ResolveIssue(context.Background(), Subject{UserID: "user", WorkspaceID: "ws"}, "task")
			if err != nil {
				t.Fatal(err)
			}
			want := []Permission{View}
			if mode == ProjectAccessInherit {
				want = []Permission{Edit, View}
			}
			if got := permissionsOf(access); !reflect.DeepEqual(got, want) {
				t.Fatalf("permissions = %v, want %v", got, want)
			}
		})
	}
	repo := effectiveFixture()
	repo.resources["task"] = IssueAccessResource{WorkspaceID: "ws", IssueID: "task", CreatorUserID: "creator", AssigneeUserID: "user", ProjectAccessMode: ProjectAccessInherit, PolicyVersion: 1}
	access, err := NewEffectiveAccessResolver(repo).ResolveIssue(context.Background(), Subject{UserID: "user", WorkspaceID: "ws"}, "task")
	if err != nil {
		t.Fatal(err)
	}
	if len(access.Permissions) == 0 {
		t.Fatal("projectless assignee lost task access")
	}
}

func TestEffectiveAccessInheritsOnlyDirectParentBase(t *testing.T) {
	repo := effectiveFixture()
	repo.resources["task"] = IssueAccessResource{WorkspaceID: "ws", IssueID: "task", ProjectID: "child-project", ProjectWorkspaceID: "ws", ParentIssueID: "parent", ParentWorkspaceID: "ws", CreatorUserID: "other", ProjectAccessMode: ProjectAccessRestricted, PolicyVersion: 2}
	repo.resources["parent"] = IssueAccessResource{WorkspaceID: "ws", IssueID: "parent", ProjectID: "parent-project", ProjectWorkspaceID: "ws", ParentIssueID: "grandparent", ParentWorkspaceID: "ws", CreatorUserID: "other", ProjectAccessMode: ProjectAccessInherit, PolicyVersion: 4}
	repo.resources["grandparent"] = IssueAccessResource{WorkspaceID: "ws", IssueID: "grandparent", CreatorUserID: "user", ProjectAccessMode: ProjectAccessInherit, PolicyVersion: 1}
	repo.projectGrants["parent-project"] = []AccessGrant{{ID: "parent-project", WorkspaceID: "ws", ProjectID: "parent-project", SubjectType: SubjectUser, SubjectID: "user", Permission: Edit}}
	repo.issueGrants["grandparent"] = []AccessGrant{{ID: "grandparent", WorkspaceID: "ws", IssueID: "grandparent", SubjectType: SubjectUser, SubjectID: "user", Permission: IssueManage}}

	access, err := NewEffectiveAccessResolver(repo).ResolveIssue(context.Background(), Subject{UserID: "user", WorkspaceID: "ws"}, "task")
	if err != nil {
		t.Fatal(err)
	}
	if got := permissionsOf(access); !reflect.DeepEqual(got, []Permission{Edit, View}) {
		t.Fatalf("permissions = %v, want direct parent's projected edit and implicit view", got)
	}
	for _, source := range access.Sources {
		if source.Source != AccessSourceParentIssue || source.SourceResource.ID != "parent" {
			t.Fatalf("unexpected parent explanation: %+v", source)
		}
	}
}

func TestEffectiveAccessDirectParentSupportsSameCrossAndNoProject(t *testing.T) {
	for _, test := range []struct {
		name          string
		childProject  string
		parentProject string
	}{
		{name: "same-project", childProject: "project", parentProject: "project"},
		{name: "cross-project", childProject: "child-project", parentProject: "parent-project"},
		{name: "projectless-parent", childProject: "child-project"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := effectiveFixture()
			repo.resources["task"] = IssueAccessResource{
				WorkspaceID: "ws", IssueID: "task", ProjectID: test.childProject, ProjectWorkspaceID: "ws",
				ParentIssueID: "parent", ParentWorkspaceID: "ws", CreatorUserID: "other",
				ProjectAccessMode: ProjectAccessRestricted, PolicyVersion: 2,
			}
			repo.resources["parent"] = IssueAccessResource{
				WorkspaceID: "ws", IssueID: "parent", ProjectID: test.parentProject, CreatorUserID: "other",
				ProjectAccessMode: ProjectAccessInherit, PolicyVersion: 4,
			}
			if test.parentProject != "" {
				repo.resources["parent"] = IssueAccessResource{
					WorkspaceID: "ws", IssueID: "parent", ProjectID: test.parentProject, ProjectWorkspaceID: "ws",
					CreatorUserID: "other", ProjectAccessMode: ProjectAccessInherit, PolicyVersion: 4,
				}
				repo.projectGrants[test.parentProject] = []AccessGrant{{
					ID: "parent-project", WorkspaceID: "ws", ProjectID: test.parentProject,
					SubjectType: SubjectUser, SubjectID: "user", Permission: IssueComment,
				}}
			} else {
				repo.issueGrants["parent"] = []AccessGrant{{
					ID: "parent-task", WorkspaceID: "ws", IssueID: "parent",
					SubjectType: SubjectUser, SubjectID: "user", Permission: IssueComment,
				}}
			}

			access, err := NewEffectiveAccessResolver(repo).ResolveIssue(context.Background(), Subject{UserID: "user", WorkspaceID: "ws"}, "task")
			if err != nil {
				t.Fatal(err)
			}
			if got := permissionsOf(access); !reflect.DeepEqual(got, []Permission{IssueComment, View}) {
				t.Fatalf("permissions = %v, want direct parent access", got)
			}
			for _, source := range access.Sources {
				if source.Source != AccessSourceParentIssue || source.SourceResource.ID != "parent" {
					t.Fatalf("unexpected parent explanation: %+v", source)
				}
			}
		})
	}
}

func TestEffectiveAccessExpiryRevocationOwnerBatchExplainAndPreview(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	repo := effectiveFixture()
	repo.resources["task-2"] = IssueAccessResource{WorkspaceID: "ws", IssueID: "task-2", CreatorUserID: "other", ProjectAccessMode: ProjectAccessInherit, PolicyVersion: 1}
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	repo.issueGrants["task"] = []AccessGrant{
		{ID: "expired", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Permission: Edit, ExpiresAt: &past},
		{ID: "expired-role", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Role: "member", Scope: RoleScopeTask, ExpiresAt: &past},
		{ID: "role-target", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectRole, SubjectID: "member", Permission: IssueManage},
		{ID: "one", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Permission: View, ExpiresAt: &future},
		{ID: "two", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectEveryone, Permission: View},
	}
	repo.projectGrants["project"] = []AccessGrant{{ID: "project", WorkspaceID: "ws", ProjectID: "project", SubjectType: SubjectUser, SubjectID: "user", Permission: IssueComment}}
	resolver := NewEffectiveAccessResolverWithClock(repo, func() time.Time { return now })
	subject := Subject{UserID: "user", WorkspaceID: "ws"}
	access, err := resolver.ResolveIssue(context.Background(), subject, "task")
	if err != nil {
		t.Fatal(err)
	}
	if got := permissionsOf(access); !reflect.DeepEqual(got, []Permission{IssueComment, View}) {
		t.Fatalf("permissions = %v", got)
	}
	delete(repo.issueGrants, "task")
	repo.issueGrants["task"] = []AccessGrant{{ID: "two", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectEveryone, Permission: View}}
	access, err = resolver.ResolveIssue(context.Background(), subject, "task")
	if err != nil || !reflect.DeepEqual(permissionsOf(access), []Permission{IssueComment, View}) {
		t.Fatalf("one source revoke removed another: %+v, %v", access, err)
	}

	explanation, err := resolver.ExplainIssue(context.Background(), subject, "task", IssueComment)
	if err != nil || !explanation.Allowed || len(explanation.Sources) == 0 || explanation.Sources[0].PolicyVersion != 3 {
		t.Fatalf("bad explanation: %+v, %v", explanation, err)
	}
	if err := resolver.CanIssue(context.Background(), subject, "task", IssueComment); err != nil {
		t.Fatalf("CanIssue disagrees with ResolveIssue: %v", err)
	}
	if err := resolver.CanIssue(context.Background(), subject, "task", IssueManage); !errors.Is(err, ErrForbidden) {
		t.Fatalf("CanIssue should deny missing permission: %v", err)
	}
	preview, err := resolver.PreviewIssuePolicyChange(context.Background(), subject, "task", ProjectAccessRestricted)
	if err != nil || !containsPermission(preview.Revoked, IssueComment) || containsPermission(preview.After.Permissions, IssueComment) {
		t.Fatalf("bad preview: %+v, %v", preview, err)
	}

	batch, err := resolver.ResolveIssues(context.Background(), subject, []string{"task", "task-2"})
	if err != nil || !reflect.DeepEqual(batch["task"].Permissions, access.Permissions) {
		t.Fatalf("batch differs from single: %+v, %v", batch, err)
	}
	repo.workspaceRole, repo.ownerBypass = WorkspaceOwner, true
	ownerAccess, err := resolver.ResolveIssue(context.Background(), subject, "task-2")
	if err != nil || len(ownerAccess.Permissions) != len(allTaskPermissions()) {
		t.Fatalf("owner bypass not live: %+v, %v", ownerAccess, err)
	}
	repo.ownerBypass = false
	ownerAccess, err = resolver.ResolveIssue(context.Background(), subject, "task-2")
	if err != nil || len(ownerAccess.Permissions) != 0 {
		t.Fatalf("disabled owner bypass still applied: %+v, %v", ownerAccess, err)
	}
}

func TestEffectiveAccessExplanationPreservesGrantMetadata(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	repo := effectiveFixture()
	repo.issueGrants["task"] = []AccessGrant{{
		ID: "requested", WorkspaceID: "ws", ProjectID: "project", IssueID: "task",
		SubjectType: SubjectUser, SubjectID: "user", Role: "reviewer", Scope: RoleScopeTask,
		Source: GrantSourceManual, GrantedBy: "owner", ExpiresAt: &expires,
		OriginKind: "access_request", OriginID: "request-1",
	}}
	resolver := NewEffectiveAccessResolverWithClock(repo, func() time.Time { return now })
	explanation, err := resolver.ExplainIssue(context.Background(), Subject{UserID: "user", WorkspaceID: "ws"}, "task", IssueComment)
	if err != nil {
		t.Fatal(err)
	}
	if !explanation.Allowed || len(explanation.Sources) != 1 {
		t.Fatalf("unexpected explanation: %+v", explanation)
	}
	source := explanation.Sources[0]
	if source.Source != AccessSourceAccessRequest || source.Role != "reviewer" || source.Scope != RoleScopeTask ||
		source.GrantID != "requested" || source.GrantSource != GrantSourceManual || source.GrantedBy != "owner" ||
		source.OriginKind != "access_request" || source.OriginID != "request-1" || source.ExpiresAt == nil || !source.ExpiresAt.Equal(expires) ||
		source.SourceResource != (AccessResourceRef{Scope: RoleScopeTask, ID: "task"}) ||
		source.TargetResource != (AccessResourceRef{Scope: RoleScopeTask, ID: "task"}) || source.PolicyVersion != 3 {
		t.Fatalf("grant metadata was not preserved: %+v", source)
	}
}

func TestEffectiveAccessMentionGrantIsIdempotentAndTaskLocal(t *testing.T) {
	repo := effectiveFixture()
	grant := AccessGrant{ID: "mention", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Role: "member", Scope: RoleScopeTask, Source: GrantSourceSystem}
	repo.issueGrants["task"] = []AccessGrant{grant, grant}
	repo.resources["sibling"] = IssueAccessResource{WorkspaceID: "ws", IssueID: "sibling", CreatorUserID: "other", ProjectAccessMode: ProjectAccessInherit, PolicyVersion: 1}
	resolver := NewEffectiveAccessResolver(repo)
	access, err := resolver.ResolveIssue(context.Background(), Subject{UserID: "user", WorkspaceID: "ws"}, "task")
	if err != nil {
		t.Fatal(err)
	}
	if got := permissionsOf(access); !reflect.DeepEqual(got, []Permission{Edit, IssueChildCreate, IssueComment, View}) {
		t.Fatalf("mention permissions = %v", got)
	}
	if len(access.Sources) != 4 {
		t.Fatalf("duplicate mention produced duplicate sources: %+v", access.Sources)
	}
	sibling, err := resolver.ResolveIssue(context.Background(), Subject{UserID: "user", WorkspaceID: "ws"}, "sibling")
	if err != nil || len(sibling.Permissions) != 0 {
		t.Fatalf("mention leaked to sibling task: %+v, %v", sibling, err)
	}
}

func TestEffectiveAccessGrantCombinationOrderIndependent(t *testing.T) {
	repo := effectiveFixture()
	repo.organizations = []string{"department"}
	grants := []AccessGrant{
		{ID: "user", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Permission: Edit},
		{ID: "org", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectOrganization, SubjectID: "department", Permission: IssueComment},
		{ID: "everyone", WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectEveryone, Permission: View},
	}
	repo.issueGrants["task"] = grants
	resolver := NewEffectiveAccessResolver(repo)
	first, err := resolver.ResolveIssue(context.Background(), Subject{UserID: "user", WorkspaceID: "ws"}, "task")
	if err != nil {
		t.Fatal(err)
	}
	repo.issueGrants["task"] = []AccessGrant{grants[2], grants[1], grants[0]}
	second, err := resolver.ResolveIssue(context.Background(), Subject{UserID: "user", WorkspaceID: "ws"}, "task")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("grant order changed effective access:\nfirst=%+v\nsecond=%+v", first, second)
	}
}

func TestEffectiveAccessFailsClosed(t *testing.T) {
	subject := Subject{UserID: "user", WorkspaceID: "ws"}
	for _, failure := range []string{"workspace", "owner", "resource", "issue-grants", "organizations", "project-grants", "project-role", "task-role"} {
		t.Run(failure, func(t *testing.T) {
			repo := effectiveFixture()
			repo.errAt = failure
			repo.issueGrants["task"] = []AccessGrant{{WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Role: "member", Scope: RoleScopeTask}}
			repo.projectGrants["project"] = []AccessGrant{{WorkspaceID: "ws", ProjectID: "project", SubjectType: SubjectUser, SubjectID: "user", Role: "member", Scope: RoleScopeProject}}
			if _, err := NewEffectiveAccessResolver(repo).ResolveIssue(context.Background(), subject, "task"); err == nil {
				t.Fatal("storage failure allowed access")
			}
		})
	}
	for name, mutate := range map[string]func(*fakeEffectiveAccessRepository){
		"cross-workspace": func(repo *fakeEffectiveAccessRepository) {
			r := repo.resources["task"]
			r.ProjectWorkspaceID = "other"
			repo.resources["task"] = r
		},
		"resource-binding": func(repo *fakeEffectiveAccessRepository) {
			repo.issueGrants["task"] = []AccessGrant{{WorkspaceID: "ws", ProjectID: "other", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Permission: View}}
		},
		"wrong-role-scope": func(repo *fakeEffectiveAccessRepository) {
			repo.issueGrants["task"] = []AccessGrant{{WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Role: "member", Scope: RoleScopeProject}}
		},
		"unknown-permission": func(repo *fakeEffectiveAccessRepository) {
			repo.issueGrants["task"] = []AccessGrant{{WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Permission: Permission("project.unknown")}}
		},
		"unknown-subject": func(repo *fakeEffectiveAccessRepository) {
			repo.issueGrants["task"] = []AccessGrant{{WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectType("unknown"), SubjectID: "user", Permission: View}}
		},
		"ambiguous-grant-kind": func(repo *fakeEffectiveAccessRepository) {
			repo.issueGrants["task"] = []AccessGrant{{WorkspaceID: "ws", ProjectID: "project", IssueID: "task", SubjectType: SubjectUser, SubjectID: "user", Role: "member", Permission: View, Scope: RoleScopeTask}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			repo := effectiveFixture()
			mutate(repo)
			if _, err := NewEffectiveAccessResolver(repo).ResolveIssue(context.Background(), subject, "task"); err == nil {
				t.Fatal("invalid data allowed access")
			}
		})
	}
	if _, err := NewEffectiveAccessResolver(effectiveFixture()).ExplainIssue(context.Background(), subject, "task", Permission("project.unknown")); err == nil {
		t.Fatal("unknown requested permission allowed")
	}
}
