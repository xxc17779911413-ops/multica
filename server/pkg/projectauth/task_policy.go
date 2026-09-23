package projectauth

import (
	"context"
	"errors"
	"fmt"
)

// 2026-09-03 coder(lq): A task inherits every task-applicable permission from
// its project, while a direct task grant can supplement access only for that
// one task. Project administration and task creation remain project-scoped.
func (s *Service) CheckIssue(ctx context.Context, subject Subject, issueID, projectID string, permission Permission) error {
	return s.CheckIssueWithWorkspaceScope(ctx, subject, issueID, projectID, permission, true)
}

// 2026-09-01 coder(lq): Keep direct issue checks aligned with list visibility
// so a restricted workspace-owner request cannot open a hidden task by URL.
func (s *Service) CheckIssueWithWorkspaceScope(ctx context.Context, subject Subject, issueID, projectID string, permission Permission, includeWorkspaceOwned bool) error {
	if s == nil || !s.Enabled() {
		return nil
	}
	if issueID == "" || projectID == "" {
		return ErrNoProjectAccess
	}
	// 2026-09-01 coder(lq): Resolve the canonical task binding before any
	// permission lookup. Callers must not pair an issue from one project or
	// workspace with another project ID supplied in the request.
	resourceRepo, ok := s.repo.(ResourceRepository)
	if !ok {
		// 2026-09-01 coder(lq): An enabled task ACL must resolve the canonical
		// issue binding before checking grants; otherwise a caller could pair a
		// valid project grant with an unrelated issue ID.
		return ErrMigrationRequired
	}
	workspaceID, boundProjectID, err := resourceRepo.IssueProject(ctx, issueID)
	if err != nil {
		if errors.Is(err, ErrNoProjectAccess) || errors.Is(err, ErrCrossWorkspace) {
			return err
		}
		return authorizationStorageError(err)
	}
	if workspaceID != subject.WorkspaceID || boundProjectID != projectID {
		return ErrNoProjectAccess
	}
	// 2026-09-05 coder(lq): The creator invariant preserves ownership for an
	// active workspace member only; removed members must not regain access from
	// a historical creator reference.
	if _, memberErr := s.requireWorkspaceMember(ctx, subject); memberErr != nil {
		return memberErr
	}
	// 2026-09-05 coder(lq): Keep project administration and task creation at
	// project scope. This guard must run before inherited project checks;
	// otherwise a project Owner could satisfy MemberManage, SettingsManage, or
	// IssueCreate through a task endpoint.
	if !taskGrantPermissionAllowed(permission) {
		return fmt.Errorf("%w: permission=%s", ErrForbidden, permission)
	}
	// 2026-09-05 coder(lq): A task creator is an immutable task Owner even when
	// the project grant was removed or the owner grant row is missing. Restrict
	// this hard bypass to task-scoped permissions so it cannot grant project
	// administration through a task URL.
	if creatorRepo, ok := s.repo.(IssueCreatorRepository); ok {
		creator, creatorErr := creatorRepo.IssueCreator(ctx, issueID)
		if creatorErr != nil {
			return authorizationStorageError(creatorErr)
		}
		if creator != "" && creator == subject.UserID && taskGrantPermissionAllowed(permission) {
			return nil
		}
	}
	// 2026-09-03 coder(lq): Check inherited project permission first. This also
	// validates current workspace membership and fails closed on storage or
	// migration errors. Only an ordinary authorization denial may fall through
	// to a task-scoped grant.
	if err := s.CheckWithWorkspaceScope(ctx, subject, projectID, permission, includeWorkspaceOwned); err == nil {
		return nil
	} else if !errors.Is(err, ErrForbidden) {
		return err
	}
	if grants, ok := s.repo.(GrantRepository); ok {
		allowed, _, grantErr := s.checkGrants(ctx, grants, subject, projectID, issueID, permission)
		if grantErr != nil {
			return grantErr
		}
		if allowed {
			return nil
		}
	} else {
		return ErrMigrationRequired
	}
	return fmt.Errorf("%w: permission=%s", ErrForbidden, permission)
}
