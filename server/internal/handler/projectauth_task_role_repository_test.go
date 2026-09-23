package handler

import (
	"context"
	"testing"

	"github.com/multica-ai/multica/server/pkg/projectauth"
)

var _ projectauth.TaskRolePermissionRepository = (*projectAuthRepository)(nil)

func TestTaskRolePermissionsUseIndependentPersistentMatrix(t *testing.T) {
	if testPool == nil {
		t.Skip("database not available")
	}

	repo := &projectAuthRepository{db: testPool}
	permissions, found, err := repo.TaskRolePermissions(context.Background(), testWorkspaceID, projectauth.TaskMember)
	if err != nil {
		t.Fatalf("TaskRolePermissions: %v", err)
	}
	if !found {
		t.Fatal("task Member role was not seeded")
	}

	want := map[projectauth.Permission]bool{
		projectauth.View:             true,
		projectauth.Edit:             true,
		projectauth.IssueComment:     true,
		projectauth.IssueChildCreate: true,
	}
	if len(permissions) != len(want) {
		t.Fatalf("task Member permissions = %v, want %v", permissions, want)
	}
	for _, permission := range permissions {
		if !want[permission] {
			t.Fatalf("task Member unexpectedly allows %s", permission)
		}
	}
}
