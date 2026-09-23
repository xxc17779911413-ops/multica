package projectauth

import (
	"reflect"
	"sort"
	"testing"
)

func TestDefaultTaskPolicyMatchesDocumentedSystemRoles(t *testing.T) {
	policy := DefaultTaskPolicy()
	want := map[TaskRole][]Permission{
		TaskOwner:   {View, Edit, IssueComment, IssueManage, IssueArchive, AgentUse, IssueChildCreate},
		TaskManager: {View, Edit, IssueComment, IssueManage, IssueArchive, AgentUse, IssueChildCreate},
		TaskMember:  {View, Edit, IssueComment, IssueChildCreate},
		TaskViewer:  {View},
	}

	for role, wantPermissions := range want {
		got := make([]Permission, 0, len(TaskPermissionSet()))
		for _, permission := range TaskPermissionSet() {
			if policy.Allows(role, permission) {
				got = append(got, permission)
			}
		}
		sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
		sort.Slice(wantPermissions, func(i, j int) bool { return wantPermissions[i] < wantPermissions[j] })
		if !reflect.DeepEqual(got, wantPermissions) {
			t.Fatalf("task role %s permissions = %v, want %v", role, got, wantPermissions)
		}
	}
}

func TestTaskPermissionSetExcludesProjectAdministration(t *testing.T) {
	policy := DefaultTaskPolicy()
	for _, role := range []TaskRole{TaskOwner, TaskManager, TaskMember, TaskViewer} {
		for _, permission := range []Permission{IssueCreate, MemberManage, SettingsManage} {
			if policy.Allows(role, permission) {
				t.Fatalf("task role %s unexpectedly allows project permission %s", role, permission)
			}
		}
	}
}

func TestTaskSystemRoleDefinitionsAreScopedAndIndependent(t *testing.T) {
	definitions := TaskSystemRoleDefinitions()
	if len(definitions) != 4 {
		t.Fatalf("task system role count = %d, want 4", len(definitions))
	}
	for _, definition := range definitions {
		if definition.Scope != RoleScopeTask {
			t.Fatalf("task role %s scope = %q, want %q", definition.Key, definition.Scope, RoleScopeTask)
		}
		if !definition.IsSystem {
			t.Fatalf("task role %s must be a system role", definition.Key)
		}
	}

	projectMember := DefaultPolicy()
	taskMember := DefaultTaskPolicy()
	if projectMember.Allows(ProjectMember, Edit) {
		t.Fatal("test precondition failed: project Member unexpectedly allows Edit")
	}
	if !taskMember.Allows(TaskMember, Edit) {
		t.Fatal("task Member must allow Edit independently of project Member")
	}
	if projectMember.Allows(ProjectMember, IssueChildCreate) {
		t.Fatal("project Member role must not gain task ChildCreate through a shared matrix")
	}
}
