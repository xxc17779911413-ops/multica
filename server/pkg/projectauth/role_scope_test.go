package projectauth

import "testing"

func TestAccessGrantRoleScopeIsExplicit(t *testing.T) {
	projectGrant := AccessGrant{ProjectID: "project-1", Role: "member", Scope: RoleScopeProject}
	taskGrant := AccessGrant{ProjectID: "project-1", IssueID: "issue-1", Role: "member", Scope: RoleScopeTask}

	if err := projectGrant.ValidateRoleScope(); err != nil {
		t.Fatalf("project role scope rejected: %v", err)
	}
	if err := taskGrant.ValidateRoleScope(); err != nil {
		t.Fatalf("task role scope rejected: %v", err)
	}
	projectGrant.Scope = RoleScopeTask
	if err := projectGrant.ValidateRoleScope(); err == nil {
		t.Fatal("project grant accepted task role scope")
	}
	taskGrant.Scope = RoleScopeProject
	if err := taskGrant.ValidateRoleScope(); err == nil {
		t.Fatal("task grant accepted project role scope")
	}
}

func TestSystemRoleCatalogsReturnIndependentScopes(t *testing.T) {
	for _, role := range SystemRoleDefinitions() {
		if role.Scope != RoleScopeProject {
			t.Fatalf("project role %s scope = %q", role.Key, role.Scope)
		}
	}
	for _, role := range TaskSystemRoleDefinitions() {
		if role.Scope != RoleScopeTask {
			t.Fatalf("task role %s scope = %q", role.Key, role.Scope)
		}
	}
}

func TestProjectPermissionProjectionIsExplicitAndTaskCapped(t *testing.T) {
	tests := []struct {
		permission Permission
		want       Permission
		projected  bool
	}{
		{View, View, true},
		{Edit, Edit, true},
		{IssueComment, IssueComment, true},
		{IssueManage, IssueManage, true},
		{IssueArchive, IssueArchive, true},
		{AgentUse, AgentUse, true},
		{IssueChildCreate, IssueChildCreate, true},
		{IssueCreate, "", false},
		{MemberManage, "", false},
		{SettingsManage, "", false},
	}
	for _, tt := range tests {
		got, ok := ProjectPermissionToTask(tt.permission)
		if got != tt.want || ok != tt.projected {
			t.Errorf("projection(%s) = (%s,%t), want (%s,%t)", tt.permission, got, ok, tt.want, tt.projected)
		}
	}

	if capped, err := TaskPermissionCap([]Permission{Edit, MemberManage}); err != nil {
		t.Fatalf("cap should filter known non-task permissions: %v", err)
	} else if len(capped) != 2 || capped[0] != Edit || capped[1] != View {
		t.Fatalf("cap should retain edit, add implicit view, and filter project-only permission: %v", capped)
	}
	if _, err := TaskPermissionCap([]Permission{Permission("project.unknown")}); err == nil {
		t.Fatal("cap accepted unknown permission")
	}
	projected, err := ProjectPermissionsToTask([]Permission{Edit, IssueCreate, MemberManage})
	if err != nil || len(projected) != 2 || projected[0] != Edit || projected[1] != View {
		t.Fatalf("central projection = %v, %v; want edit + implicit view", projected, err)
	}
}
