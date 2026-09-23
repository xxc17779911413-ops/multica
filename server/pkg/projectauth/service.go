package projectauth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Service struct {
	repo       Repository
	policy     Policy
	taskPolicy TaskPolicy
	rollout    RolloutPhase
}

func New(repo Repository, enabled bool) *Service {
	return NewWithRollout(repo, LegacyRolloutPhase(enabled))
}

func NewWithRollout(repo Repository, rollout RolloutPhase) *Service {
	return &Service{repo: repo, policy: DefaultPolicy(), taskPolicy: DefaultTaskPolicy(), rollout: rollout}
}

func (s *Service) RolloutPhase() RolloutPhase {
	if s == nil {
		return RolloutOff
	}
	return s.rollout
}

func (s *Service) Enabled() bool       { return s != nil && s.rollout.ReaderEnabled() }
func (s *Service) ShadowEnabled() bool { return s != nil && s.rollout.ShadowEnabled() }

// WorkspaceOwnerBypassEnabledFromEnvironment is the single parser for the
// deployment-level owner override. 2026-09-18 coder(lq): Accept surrounding
// whitespace and case differences so an operationally valid false value
// cannot silently fall back to the permissive default.
func WorkspaceOwnerBypassEnabledFromEnvironment() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("PROJECT_OWNER_BYPASS_ENABLED")), "false")
}

// WorkspaceOwnerBypassEnabled resolves the workspace-level owner override.
// The switch is deployment-scoped and now comes from the process environment
// rather than workspace.settings, so operators can flip it without touching
// page state.
func (s *Service) WorkspaceOwnerBypassEnabled(ctx context.Context, workspaceID string) (bool, error) {
	_ = ctx
	_ = workspaceID
	return WorkspaceOwnerBypassEnabledFromEnvironment(), nil
}

// CurrentProjectRoles returns the caller's effective role for visible projects
// when the persistence adapter supports the optional batch read. A missing
// adapter is treated as an empty result so older adapters remain compatible.
// 2026-08-28 coder(lq): Expose list metadata without coupling handlers to SQL.
func (s *Service) CurrentProjectRoles(ctx context.Context, workspaceID, userID string) (map[string]ProjectRole, error) {
	if s == nil || !s.Enabled() || s.repo == nil {
		return map[string]ProjectRole{}, nil
	}
	reader, ok := s.repo.(ProjectRoleReader)
	if !ok {
		return map[string]ProjectRole{}, nil
	}
	return reader.CurrentProjectRoles(ctx, workspaceID, userID)
}

// ListOrganizations returns the latest local directory snapshot for a
// workspace. The authorization package deliberately has no provider client;
// an adapter must synchronize organizations before this endpoint can serve
// them. 2026-09-01 coder(lq): Add provider-neutral organization picker seam.
func (s *Service) ListOrganizations(ctx context.Context, subject Subject) ([]Organization, error) {
	if s == nil || !s.Enabled() {
		return nil, nil
	}
	directory, ok := s.repo.(OrganizationDirectoryRepository)
	if !ok {
		return nil, ErrMigrationRequired
	}
	if _, err := s.requireWorkspaceMember(ctx, subject); err != nil {
		return nil, err
	}
	organizations, err := directory.ListOrganizations(ctx, subject.WorkspaceID)
	if err != nil {
		return nil, authorizationStorageError(err)
	}
	return organizations, nil
}

// ListOrganizationMembers returns employees from the local synchronized
// directory. A missing optional adapter produces an empty list so organization
// pickers from older deployments remain usable during rolling upgrades.
// 2026-09-03 coder(lq): Add a read-only employee directory boundary.
func (s *Service) ListOrganizationMembers(ctx context.Context, subject Subject) ([]OrganizationMember, error) {
	if s == nil || !s.Enabled() {
		return nil, nil
	}
	if _, err := s.requireWorkspaceMember(ctx, subject); err != nil {
		return nil, err
	}
	directory, ok := s.repo.(OrganizationMemberDirectoryRepository)
	if !ok {
		return []OrganizationMember{}, nil
	}
	members, err := directory.ListOrganizationMembers(ctx, subject.WorkspaceID)
	if err != nil {
		return nil, authorizationStorageError(err)
	}
	return members, nil
}

// 2026-08-24 coder(lq): Return nil only when the subject may perform the
// permission; disabled deployments preserve legacy behavior during rollout.
func (s *Service) Check(ctx context.Context, subject Subject, projectID string, permission Permission) error {
	return s.checkWithWorkspaceScope(ctx, subject, projectID, permission, true)
}

// 2026-09-01 coder(lq): The workspace-owner visibility switch is a read
// scope, not a new role. Callers can therefore request a restricted check
// while preserving explicit project grants for workspace owners.
func (s *Service) CheckWithWorkspaceScope(ctx context.Context, subject Subject, projectID string, permission Permission, includeWorkspaceOwned bool) error {
	return s.checkWithWorkspaceScope(ctx, subject, projectID, permission, includeWorkspaceOwned)
}

func (s *Service) checkWithWorkspaceScope(ctx context.Context, subject Subject, projectID string, permission Permission, includeWorkspaceOwned bool) error {
	if s == nil || !s.Enabled() {
		return nil
	}
	// 2026-08-24 coder(lq): Fail closed when the rollout flag is enabled but
	// the persistence adapter was not wired, instead of panicking in a request.
	if s.repo == nil {
		return ErrDisabled
	}
	// 2026-09-01 coder(lq): Once the feature flag is enabled, the unified
	// grant repository is mandatory. Refusing legacy-only adapters prevents a
	// stale project_members row from becoming an authorization bypass.
	grants, ok := s.repo.(GrantRepository)
	if !ok {
		return ErrMigrationRequired
	}
	if subject.UserID == "" || subject.WorkspaceID == "" || projectID == "" {
		return ErrNoProjectAccess
	}
	workspaceID, err := s.repo.ProjectWorkspace(ctx, projectID)
	if err != nil {
		if errors.Is(err, ErrNoProjectAccess) || errors.Is(err, ErrCrossWorkspace) {
			return err
		}
		return authorizationStorageError(err)
	}
	if workspaceID != subject.WorkspaceID {
		return ErrNoProjectAccess
	}
	role, err := s.repo.WorkspaceRole(ctx, subject.WorkspaceID, subject.UserID)
	if err != nil {
		if errors.Is(err, ErrNotWorkspaceMember) {
			return ErrNotWorkspaceMember
		}
		return authorizationStorageError(err)
	}
	// 2026-09-04 coder(lq): The project creator is an immutable Owner even
	// when an older database is missing the seeded grant row. Resolve this
	// identity after workspace membership, then short-circuit every permission
	// check so ACL edits cannot strand the creator or silently reduce Owner
	// capabilities.
	if creatorRepo, creatorRepoOK := s.repo.(ProjectCreatorRepository); creatorRepoOK {
		creator, creatorErr := creatorRepo.ProjectCreator(ctx, projectID)
		if creatorErr != nil {
			if errors.Is(creatorErr, ErrNoProjectAccess) {
				return creatorErr
			}
			return authorizationStorageError(creatorErr)
		}
		if creator != "" && creator == subject.UserID {
			return nil
		}
	}
	if role == WorkspaceOwner {
		bypassEnabled, bypassErr := s.WorkspaceOwnerBypassEnabled(ctx, subject.WorkspaceID)
		if bypassErr != nil {
			return ErrForbidden
		}
		if bypassEnabled && includeWorkspaceOwned {
			return nil
		}
	}
	allowed, _, grantErr := s.checkGrants(ctx, grants, subject, projectID, "", permission)
	if grantErr != nil {
		return grantErr
	}
	if allowed {
		return nil
	}
	// 2026-09-01 coder(lq): The project row and workspace membership were
	// already validated above. A caller with no matching grant is therefore a
	// forbidden operation on an existing resource (HTTP 403), not a missing
	// project (HTTP 404). Keep ErrNoProjectAccess reserved for resource lookup
	// failures and cross-workspace boundaries.
	return fmt.Errorf("%w: permission=%s", ErrForbidden, permission)
}

// 2026-08-31 coder(lq): Resolve every grant source on each request so role or
// organization changes become effective immediately and do not depend on JWT
// refresh timing.
func (s *Service) checkGrants(ctx context.Context, repo GrantRepository, subject Subject, projectID, issueID string, permission Permission) (allowed bool, matched bool, err error) {
	grants, err := repo.ListAccessGrants(ctx, subject.WorkspaceID, projectID, issueID)
	if err != nil {
		return false, false, authorizationStorageError(err)
	}
	organizations, err := repo.ListUserOrganizations(ctx, subject.WorkspaceID, subject.UserID)
	if err != nil {
		return false, false, authorizationStorageError(err)
	}
	orgSet := make(map[string]struct{}, len(organizations))
	for _, organization := range organizations {
		orgSet[organization] = struct{}{}
	}
	// A role subject is matched against roles granted to this user (including
	// organization/everyone role grants). Only canonical *project* grants may
	// contribute to the project role set. A task role assignment is scoped to
	// that task and must never make a project-level role grant match, otherwise
	// granting a role on task A could escalate the caller to project settings
	// or member management (and could leak into task B).
	// 2026-09-01 coder(lq): Keep task role assignments out of project role
	// resolution; direct task grants remain evaluated in the second pass.
	projectRoleSet := make(map[ProjectRole]struct{})
	taskRoleSet := make(map[TaskRole]struct{})
	for index := range grants {
		grant := &grants[index]
		if err := grant.NormalizeRoleScope(); err != nil {
			return false, false, err
		}
		if grant.IssueID != "" && grant.IssueID != issueID {
			continue
		}
		matchesSubject := grant.SubjectType == SubjectUser && grant.SubjectID == subject.UserID
		if grant.SubjectType == SubjectOrganization {
			_, matchesSubject = orgSet[grant.SubjectID]
		}
		if grant.SubjectType == SubjectEveryone && (grant.SubjectID == "" || grant.SubjectID == subject.WorkspaceID) {
			matchesSubject = true
		}
		if matchesSubject && grant.Role != "" {
			if grant.IssueID == "" {
				projectRoleSet[ProjectRole(grant.Role)] = struct{}{}
			} else {
				taskRoleSet[TaskRole(grant.Role)] = struct{}{}
			}
		}
	}
	for _, grant := range grants {
		if grant.IssueID != "" && grant.IssueID != issueID {
			continue
		}
		matches := false
		switch grant.SubjectType {
		case SubjectUser:
			matches = grant.SubjectID == subject.UserID
		case SubjectEveryone:
			matches = grant.SubjectID == "" || grant.SubjectID == subject.WorkspaceID
		case SubjectOrganization:
			_, matches = orgSet[grant.SubjectID]
		case SubjectRole:
			// A role subject resolves only within the grant's declared catalog.
			// Equal project/task role keys are intentionally unrelated.
			if grant.Scope == RoleScopeTask {
				_, matches = taskRoleSet[TaskRole(grant.SubjectID)]
			} else {
				_, matches = projectRoleSet[ProjectRole(grant.SubjectID)]
			}
			if !matches && grant.SubjectID == "" && grant.Role != "" {
				if grant.Scope == RoleScopeTask {
					_, matches = taskRoleSet[TaskRole(grant.Role)]
				} else {
					_, matches = projectRoleSet[ProjectRole(grant.Role)]
				}
			}
		}
		if !matches {
			continue
		}
		// A matching grant establishes project/task visibility even when its
		// role or permission does not allow the requested operation.
		matched = true
		// Task-level grants are intentionally narrower than project grants. A
		// task can be directly shared for task work, but it cannot confer project
		// membership/settings administration or a role's project-wide power.
		if grant.IssueID != "" && issueID != "" && grant.Permission != "" && !taskGrantPermissionAllowed(grant.Permission) {
			continue
		}
		if grant.Permission != "" {
			if grant.IssueID == "" && issueID != "" {
				projected, projectionErr := ProjectPermissionsToTask([]Permission{grant.Permission})
				if projectionErr != nil {
					return false, matched, projectionErr
				}
				if containsPermission(projected, permission) {
					return true, true, nil
				}
			} else if grant.Permission == permission {
				return true, true, nil
			}
		}
		if grant.Role != "" {
			var allowed bool
			var roleErr error
			if grant.IssueID != "" {
				allowed, roleErr = s.taskRoleAllows(ctx, subject.WorkspaceID, TaskRole(grant.Role), permission)
			} else if issueID != "" {
				allowed, roleErr = s.projectRoleAllowsTask(ctx, subject.WorkspaceID, ProjectRole(grant.Role), permission)
			} else {
				allowed, roleErr = s.roleAllows(ctx, subject.WorkspaceID, ProjectRole(grant.Role), permission)
			}
			if roleErr != nil {
				return false, matched, roleErr
			}
			if allowed && (grant.IssueID == "" || taskGrantPermissionAllowed(permission)) {
				return true, true, nil
			}
		}
	}
	return false, matched, nil
}

// 2026-09-01 coder(lq): Keep task resource validation in the service layer,
// not only in HTTP handlers. Every task grant operation must resolve the
// canonical issue binding so background jobs or future adapters cannot attach
// an ACL to a missing task, a projectless task, or a task from another project.
func (s *Service) resolveIssueBinding(ctx context.Context, subject Subject, issueID, projectID string) error {
	if issueID == "" || projectID == "" || subject.WorkspaceID == "" {
		return ErrNoProjectAccess
	}
	resourceRepo, ok := s.repo.(ResourceRepository)
	if !ok {
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
		return ErrCrossWorkspace
	}
	return nil
}

func taskGrantPermissionAllowed(permission Permission) bool {
	switch permission {
	// 2026-09-03 coder(lq): Task grants may cover every task-scoped action,
	// including comments and archive. Project administration remains scoped to
	// the project and can never be delegated through one task.
	case View, Edit, IssueComment, IssueManage, IssueArchive, AgentUse, IssueChildCreate:
		return true
	default:
		return false
	}
}

func (s *Service) taskRoleAllows(ctx context.Context, workspaceID string, role TaskRole, permission Permission) (bool, error) {
	if resolver, ok := s.repo.(TaskRolePermissionRepository); ok {
		permissions, found, err := resolver.TaskRolePermissions(ctx, workspaceID, role)
		if err != nil {
			return false, authorizationStorageError(err)
		}
		if found {
			capped, capErr := TaskPermissionCap(permissions)
			if capErr != nil {
				return false, capErr
			}
			for _, candidate := range capped {
				if candidate == permission {
					return true, nil
				}
			}
			return false, nil
		}
	}
	return s.taskPolicy.Allows(role, permission), nil
}

func (s *Service) projectRoleAllowsTask(ctx context.Context, workspaceID string, role ProjectRole, permission Permission) (bool, error) {
	permissions, _, err := s.rolePermissions(ctx, workspaceID, role)
	if err != nil {
		return false, err
	}
	projected, err := ProjectPermissionsToTask(permissions)
	if err != nil {
		return false, err
	}
	return containsPermission(projected, permission), nil
}

func (s *Service) roleAllows(ctx context.Context, workspaceID string, role ProjectRole, permission Permission) (bool, error) {
	if resolver, ok := s.repo.(RolePermissionRepository); ok {
		permissions, found, err := resolver.RolePermissions(ctx, workspaceID, role)
		if err != nil {
			return false, authorizationStorageError(err)
		}
		if found {
			for _, candidate := range permissions {
				if candidate == permission {
					return true, nil
				}
			}
			return false, nil
		}
	}
	return s.policy.Allows(role, permission), nil
}

func (s *Service) ListRoles(ctx context.Context, subject Subject) ([]RoleDefinition, error) {
	rr, ok := s.repo.(RoleRepository)
	if !ok {
		return nil, ErrDisabled
	}
	// 2026-08-28 coder(lq): Project owners need to read the workspace role
	// catalog when granting project access; only the workspace owner may mutate it.
	if _, err := s.requireWorkspaceMember(ctx, subject); err != nil {
		return nil, err
	}
	roles, err := rr.ListRoleDefinitions(ctx, subject.WorkspaceID)
	if err != nil {
		return nil, authorizationStorageError(err)
	}
	for index := range roles {
		if err := normalizeProjectRoleDefinition(&roles[index]); err != nil {
			return nil, err
		}
	}
	return roles, nil
}

func normalizeProjectRoleDefinition(role *RoleDefinition) error {
	if role.Scope == "" {
		role.Scope = RoleScopeProject
	}
	if role.Scope != RoleScopeProject {
		return ErrInvalidRoleScope
	}
	return nil
}

func (s *Service) CreateRole(ctx context.Context, subject Subject, role RoleDefinition) (RoleDefinition, error) {
	enabled, err := s.mutationEnabled()
	if err != nil {
		return RoleDefinition{}, err
	}
	if !enabled {
		return RoleDefinition{}, nil
	}
	rr, ok := s.repo.(RoleRepository)
	if !ok {
		return RoleDefinition{}, ErrDisabled
	}
	if err := s.requireRoleOwner(ctx, subject); err != nil {
		return RoleDefinition{}, err
	}
	if err := normalizeProjectRoleDefinition(&role); err != nil {
		return RoleDefinition{}, err
	}
	if role.IsSystem || !validCustomRoleKey(role.Key) {
		return RoleDefinition{}, ErrInvalidRole
	}
	if err := validatePermissions(role.Permissions); err != nil {
		return RoleDefinition{}, err
	}
	created, err := rr.CreateRoleDefinition(ctx, subject.WorkspaceID, subject.UserID, role)
	if err != nil {
		return RoleDefinition{}, authorizationStorageError(err)
	}
	if err := s.recordAudit(ctx, AuthorizationAuditEvent{
		WorkspaceID: subject.WorkspaceID,
		ActorUserID: subject.UserID,
		Action:      "project_permission_role_created",
		Details: map[string]any{
			"role_key":    string(created.Key),
			"name":        created.Name,
			"permissions": created.Permissions,
		},
	}); err != nil {
		return RoleDefinition{}, err
	}
	return created, nil
}

func (s *Service) UpdateRole(ctx context.Context, subject Subject, key string, role RoleDefinition) (RoleDefinition, error) {
	enabled, err := s.mutationEnabled()
	if err != nil {
		return RoleDefinition{}, err
	}
	if !enabled {
		return RoleDefinition{}, nil
	}
	rr, ok := s.repo.(RoleRepository)
	if !ok {
		return RoleDefinition{}, ErrDisabled
	}
	if err := s.requireRoleOwner(ctx, subject); err != nil {
		return RoleDefinition{}, err
	}
	if key == "" {
		return RoleDefinition{}, ErrInvalidRole
	}
	current, err := rr.GetRoleDefinition(ctx, subject.WorkspaceID, key)
	if err != nil {
		return RoleDefinition{}, ErrInvalidRole
	}
	if err := normalizeProjectRoleDefinition(&current); err != nil {
		return RoleDefinition{}, err
	}
	if err := normalizeProjectRoleDefinition(&role); err != nil {
		return RoleDefinition{}, err
	}
	// The key and system marker are immutable identity fields. System roles
	// are editable, but remain undeletable after their permissions change.
	if role.Key != "" && string(role.Key) != key {
		return RoleDefinition{}, ErrInvalidRole
	}
	role.Key = current.Key
	role.Scope = current.Scope
	role.IsSystem = current.IsSystem
	if err := validatePermissions(role.Permissions); err != nil {
		return RoleDefinition{}, err
	}
	updated, err := rr.UpdateRoleDefinition(ctx, subject.WorkspaceID, key, role)
	if err != nil {
		return RoleDefinition{}, authorizationStorageError(err)
	}
	if err := s.recordAudit(ctx, AuthorizationAuditEvent{
		WorkspaceID: subject.WorkspaceID,
		ActorUserID: subject.UserID,
		Action:      "project_permission_role_updated",
		Details: map[string]any{
			"role_key":    key,
			"name":        updated.Name,
			"permissions": updated.Permissions,
		},
	}); err != nil {
		return RoleDefinition{}, err
	}
	return updated, nil
}

func (s *Service) DeleteRole(ctx context.Context, subject Subject, key string) error {
	enabled, err := s.mutationEnabled()
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	rr, ok := s.repo.(RoleRepository)
	if !ok {
		return ErrDisabled
	}
	if err := s.requireRoleOwner(ctx, subject); err != nil {
		return err
	}
	if key == "" {
		return ErrInvalidRole
	}
	definition, err := rr.GetRoleDefinition(ctx, subject.WorkspaceID, key)
	if err != nil || definition.IsSystem {
		return ErrInvalidRole
	}
	if err := rr.DeleteRoleDefinition(ctx, subject.WorkspaceID, key); err != nil {
		return authorizationStorageError(err)
	}
	return s.recordAudit(ctx, AuthorizationAuditEvent{
		WorkspaceID: subject.WorkspaceID,
		ActorUserID: subject.UserID,
		Action:      "project_permission_role_deleted",
		Details: map[string]any{
			"role_key": key,
		},
	})
}

func (s *Service) requireRoleOwner(ctx context.Context, subject Subject) error {
	role, err := s.requireWorkspaceMember(ctx, subject)
	if err != nil {
		return err
	}
	// 2026-08-28 coder(lq): Role definitions affect authorization across the
	// whole workspace, so workspace admins and project owners may only consume
	// the catalog; only the workspace owner may mutate it.
	if role != WorkspaceOwner {
		return ErrForbidden
	}
	return nil
}

func (s *Service) requireWorkspaceMember(ctx context.Context, subject Subject) (WorkspaceRole, error) {
	if subject.UserID == "" || subject.WorkspaceID == "" || s == nil || s.repo == nil {
		return "", ErrNotWorkspaceMember
	}
	role, err := s.repo.WorkspaceRole(ctx, subject.WorkspaceID, subject.UserID)
	if err != nil {
		if errors.Is(err, ErrNotWorkspaceMember) {
			return "", ErrNotWorkspaceMember
		}
		return "", authorizationStorageError(err)
	}
	return role, nil
}

func validatePermissions(permissions []Permission) error {
	for _, permission := range permissions {
		if !validReportPermission(permission) {
			return fmt.Errorf("%w: permission=%s", ErrInvalidRole, permission)
		}
	}
	return nil
}

func validCustomRoleKey(role ProjectRole) bool {
	value := strings.TrimSpace(string(role))
	if value == "" || len(value) > 64 || IsSystemRole(ProjectRole(value)) {
		return false
	}
	for index, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || (char == '-' && index > 0 && index < len(value)-1) {
			continue
		}
		return false
	}
	return true
}

// 2026-08-24 coder(lq): Keep the HTTP adapter on one authorization entry point.
func (s *Service) Require(ctx context.Context, subject Subject, projectID string, permission Permission) error {
	return s.Check(ctx, subject, projectID, permission)
}

// RequireWithWorkspaceScope is the HTTP-facing equivalent of CheckWithWorkspaceScope.
// The restricted form is used by read paths when a workspace owner disabled
// the global task visibility switch.
func (s *Service) RequireWithWorkspaceScope(ctx context.Context, subject Subject, projectID string, permission Permission, includeWorkspaceOwned bool) error {
	return s.CheckWithWorkspaceScope(ctx, subject, projectID, permission, includeWorkspaceOwned)
}

// 2026-08-31 coder(lq): GrantAccess/RevokeAccess are the single write seam for
// project and task authorization. Handlers can expose different UI flows
// without duplicating validation or bypassing the project-management guard.
func (s *Service) GrantAccess(ctx context.Context, actor Subject, grant AccessGrant) error {
	enabled, err := s.mutationEnabled()
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	repo, ok := s.repo.(GrantRepository)
	if !ok {
		return ErrDisabled
	}
	if grant.WorkspaceID == "" {
		grant.WorkspaceID = actor.WorkspaceID
	}
	if grant.WorkspaceID != actor.WorkspaceID || grant.ProjectID == "" {
		return ErrCrossWorkspace
	}
	if issueID := strings.TrimSpace(grant.IssueID); issueID != "" {
		if err := s.resolveIssueBinding(ctx, actor, issueID, grant.ProjectID); err != nil {
			return err
		}
	}
	if grant.IssueID == "" {
		if err := s.Require(ctx, actor, grant.ProjectID, MemberManage); err != nil {
			return err
		}
	} else if err := s.CheckIssue(ctx, actor, grant.IssueID, grant.ProjectID, IssueManage); err != nil {
		return err
	}
	if grant.SubjectType == SubjectEveryone {
		grant.SubjectID = ""
	}
	if err := grant.NormalizeRoleScope(); err != nil {
		return err
	}
	if err := validateGrantShape(grant); err != nil {
		return err
	}
	if err := s.validateGrantSubject(ctx, actor.WorkspaceID, grant.Scope, grant.SubjectType, grant.SubjectID); err != nil {
		return err
	}
	if grant.Role != "" {
		if err := s.validateScopedRoleReference(ctx, actor.WorkspaceID, grant.Scope, grant.Role); err != nil {
			return err
		}
	}
	// 2026-09-05 coder(lq): A resource creator's Owner role is immutable. A
	// second, weaker role grant would otherwise coexist in the role-key unique
	// index and make the creator appear downgraded in permission reports. Keep
	// direct permission grants additive; only role grants can downgrade an
	// Owner and therefore need this guard.
	if err := s.protectCreatorOwnerGrant(ctx, grant); err != nil {
		return err
	}
	if grant.IssueID != "" {
		if grant.Permission != "" && !taskGrantPermissionAllowed(grant.Permission) {
			return ErrInvalidIssuePermission
		}
		// An Owner role is valid at task scope too. checkGrants still caps a
		// task-scoped role at task permissions, so project member/settings
		// administration cannot leak through a task Owner grant.
		if grant.Role != "" && TaskRole(grant.Role) != TaskOwner {
			permissions, _, err := s.taskRolePermissions(ctx, actor.WorkspaceID, TaskRole(grant.Role))
			if err != nil {
				return err
			}
			for _, permission := range permissions {
				if !taskGrantPermissionAllowed(permission) {
					return ErrInvalidIssuePermission
				}
			}
		}
	}
	grant.Source = GrantSourceManual
	grant.GrantedBy = actor.UserID
	if err := repo.UpsertAccessGrant(ctx, grant); err != nil {
		return authorizationStorageError(err)
	}
	return s.recordAudit(ctx, AuthorizationAuditEvent{
		WorkspaceID: actor.WorkspaceID,
		ProjectID:   grant.ProjectID,
		IssueID:     grant.IssueID,
		ActorUserID: actor.UserID,
		Action:      "project_permission_granted",
		Details:     grantAuditDetails(grant),
	})
}

// protectCreatorOwnerGrant prevents a project or task creator from receiving
// a weaker role through the mutable grants table. The creator remains an
// Owner even when the historical Owner row is absent; adapters that expose
// creator identities opt into this invariant while older dry-run adapters
// remain source-compatible.
// 2026-09-05 coder(lq): Enforce creator Owner protection on the grant path,
// complementing the read and revoke guards.
func (s *Service) protectCreatorOwnerGrant(ctx context.Context, grant AccessGrant) error {
	if grant.SubjectType != SubjectUser || grant.Role == "" || (grant.Scope == RoleScopeProject && ProjectRole(grant.Role) == ProjectOwner) || (grant.Scope == RoleScopeTask && TaskRole(grant.Role) == TaskOwner) {
		return nil
	}
	if grant.IssueID != "" {
		creatorRepo, ok := s.repo.(IssueCreatorRepository)
		if !ok {
			return nil
		}
		creator, err := creatorRepo.IssueCreator(ctx, grant.IssueID)
		if err != nil {
			return authorizationStorageError(err)
		}
		if creator != "" && creator == grant.SubjectID {
			return ErrLastOwner
		}
		return nil
	}
	creatorRepo, ok := s.repo.(ProjectCreatorRepository)
	if !ok {
		return nil
	}
	creator, err := creatorRepo.ProjectCreator(ctx, grant.ProjectID)
	if err != nil {
		return authorizationStorageError(err)
	}
	if creator != "" && creator == grant.SubjectID {
		return ErrLastOwner
	}
	return nil
}

// 2026-09-01 coder(lq): Keep subject existence checks at the authorization
// seam. A provider adapter may be unavailable during an OA sync; that is a
// service failure (503), while a missing directory row is a bad request.
func (s *Service) validateGrantSubject(ctx context.Context, workspaceID string, scope RoleScope, subjectType SubjectType, subjectID string) error {
	switch subjectType {
	case SubjectEveryone:
		return nil
	case SubjectRole:
		if err := s.validateScopedRoleReference(ctx, workspaceID, scope, RoleKey(subjectID)); err != nil {
			if errors.Is(err, ErrMigrationRequired) {
				return err
			}
			return ErrInvalidSubject
		}
	case SubjectUser, SubjectOrganization:
		directory, ok := s.repo.(SubjectRepository)
		if !ok {
			// 2026-09-01 coder(lq): Never persist a user/org grant without a
			// workspace-scoped directory lookup; missing adapters are a rollout
			// failure, not evidence that the subject is valid.
			return ErrMigrationRequired
		}
		var valid bool
		var err error
		if subjectType == SubjectUser {
			valid, err = directory.UserInWorkspace(ctx, workspaceID, subjectID)
		} else {
			valid, err = directory.ActiveOrganizationInWorkspace(ctx, workspaceID, subjectID)
		}
		if err != nil {
			return authorizationStorageError(err)
		}
		if !valid {
			return ErrInvalidSubject
		}
	default:
		return ErrInvalidSubject
	}
	return nil
}

// 2026-09-04 coder(lq): Keep grant-shape validation shared by grant and
// revoke paths. Revoke must reject malformed payloads before issuing a
// delete, otherwise an invalid role/permission is silently reported as a
// successful no-op and leaves callers with an unsafe API contract.
func validateGrantShape(grant AccessGrant) error {
	if err := grant.ValidateRoleScope(); err != nil {
		return err
	}
	if grant.SubjectType != SubjectUser && grant.SubjectType != SubjectRole && grant.SubjectType != SubjectOrganization && grant.SubjectType != SubjectEveryone {
		return ErrInvalidRole
	}
	if grant.SubjectType != SubjectEveryone && strings.TrimSpace(grant.SubjectID) == "" {
		return ErrInvalidSubject
	}
	// The unified table stores exactly one grant kind.
	if (grant.Role == "") == (grant.Permission == "") {
		return ErrInvalidRole
	}
	// A role subject selects members who already hold that project role; it
	// cannot receive another role and create an ambiguous role-to-role chain.
	if grant.SubjectType == SubjectRole && grant.Role != "" {
		return ErrInvalidRole
	}
	if grant.Permission != "" && !validReportPermission(grant.Permission) {
		return ErrInvalidIssuePermission
	}
	if grant.IssueID != "" && grant.Permission != "" && !taskGrantPermissionAllowed(grant.Permission) {
		return ErrInvalidIssuePermission
	}
	return nil
}

func (s *Service) validateRoleReference(ctx context.Context, workspaceID string, role ProjectRole) error {
	if validProjectRole(role) {
		return nil
	}
	rr, ok := s.repo.(RoleRepository)
	if !ok {
		return ErrInvalidRole
	}
	definition, err := rr.GetRoleDefinition(ctx, workspaceID, string(role))
	if err != nil || definition.Key == "" {
		if err != nil && errors.Is(err, ErrMigrationRequired) {
			return err
		}
		return ErrInvalidRole
	}
	return nil
}

func (s *Service) validateScopedRoleReference(ctx context.Context, workspaceID string, scope RoleScope, role RoleKey) error {
	switch scope {
	case RoleScopeProject:
		return s.validateRoleReference(ctx, workspaceID, ProjectRole(role))
	case RoleScopeTask:
		_, found, err := s.taskRolePermissions(ctx, workspaceID, TaskRole(role))
		if err != nil {
			return err
		}
		if !found {
			return ErrInvalidRole
		}
		return nil
	default:
		return ErrInvalidRoleScope
	}
}

// 2026-09-01 coder(lq): Authorization reads must distinguish a missing ACL
// migration from a denied request. Keeping this mapping in the provider-neutral
// service lets every HTTP adapter return a retryable 503 without inspecting
// database-driver errors or accidentally falling back to legacy ACL tables.
func authorizationStorageError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrMigrationRequired) || errors.Is(err, ErrStorageUnavailable) {
		return err
	}
	for _, domainErr := range []error{
		ErrDisabled, ErrNotWorkspaceMember, ErrNoProjectAccess, ErrForbidden,
		ErrInvalidRole, ErrInvalidIssuePermission, ErrCrossWorkspace,
		ErrLastOwner, ErrInvalidReportFilter, ErrRoleInUse, ErrInvalidSubject,
		ErrInvalidRoleScope,
	} {
		if errors.Is(err, domainErr) {
			return err
		}
	}
	return ErrStorageUnavailable
}

func (s *Service) rolePermissions(ctx context.Context, workspaceID string, role ProjectRole) ([]Permission, bool, error) {
	if resolver, ok := s.repo.(RolePermissionRepository); ok {
		permissions, found, err := resolver.RolePermissions(ctx, workspaceID, role)
		if err != nil {
			return nil, false, authorizationStorageError(err)
		}
		if found {
			return permissions, true, nil
		}
	}
	permissions := make([]Permission, 0)
	for permission, allowed := range s.policy.roles[role] {
		if allowed {
			permissions = append(permissions, permission)
		}
	}
	return permissions, false, nil
}

func (s *Service) taskRolePermissions(ctx context.Context, workspaceID string, role TaskRole) ([]Permission, bool, error) {
	if resolver, ok := s.repo.(TaskRolePermissionRepository); ok {
		permissions, found, err := resolver.TaskRolePermissions(ctx, workspaceID, role)
		if err != nil {
			return nil, false, authorizationStorageError(err)
		}
		if found {
			return permissions, true, nil
		}
	}
	permissions := make([]Permission, 0)
	for permission, allowed := range s.taskPolicy.roles[role] {
		if allowed {
			permissions = append(permissions, permission)
		}
	}
	return permissions, IsSystemTaskRole(role), nil
}

func (s *Service) RevokeAccess(ctx context.Context, actor Subject, grant AccessGrant) error {
	enabled, err := s.mutationEnabled()
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	repo, ok := s.repo.(GrantRepository)
	if !ok {
		return ErrDisabled
	}
	if grant.WorkspaceID != "" && grant.WorkspaceID != actor.WorkspaceID {
		return ErrCrossWorkspace
	}
	if grant.ProjectID == "" {
		return ErrNoProjectAccess
	}
	if grant.SubjectType == SubjectEveryone {
		grant.SubjectID = ""
	}
	if err := grant.NormalizeRoleScope(); err != nil {
		return err
	}
	if grant.IssueID == "" {
		if err := s.Require(ctx, actor, grant.ProjectID, MemberManage); err != nil {
			return err
		}
	} else {
		if err := s.resolveIssueBinding(ctx, actor, grant.IssueID, grant.ProjectID); err != nil {
			return err
		}
		if err := s.CheckIssue(ctx, actor, grant.IssueID, grant.ProjectID, IssueManage); err != nil {
			return err
		}
	}
	if err := validateGrantShape(grant); err != nil {
		return err
	}
	if grant.Role != "" {
		if err := s.validateScopedRoleReference(ctx, actor.WorkspaceID, grant.Scope, grant.Role); err != nil {
			return err
		}
	}
	if grant.SubjectType == SubjectRole {
		if err := s.validateScopedRoleReference(ctx, actor.WorkspaceID, grant.Scope, RoleKey(grant.SubjectID)); err != nil {
			if errors.Is(err, ErrMigrationRequired) {
				return err
			}
			return ErrInvalidSubject
		}
	}
	if grant.IssueID == "" && ProjectRole(grant.Role) == ProjectOwner {
		if err := s.protectProjectOwnerRevoke(ctx, repo, actor.WorkspaceID, grant); err != nil {
			return err
		}
	}
	if grant.IssueID != "" && TaskRole(grant.Role) == TaskOwner {
		if err := s.protectIssueOwnerRevoke(ctx, actor.WorkspaceID, grant); err != nil {
			return err
		}
	}
	if err := repo.DeleteAccessGrant(ctx, actor.WorkspaceID, grant.ProjectID, grant.IssueID, grant.SubjectType, grant.SubjectID, grant.Role, grant.Permission); err != nil {
		return authorizationStorageError(err)
	}
	return s.recordAudit(ctx, AuthorizationAuditEvent{
		WorkspaceID: actor.WorkspaceID,
		ProjectID:   grant.ProjectID,
		IssueID:     grant.IssueID,
		ActorUserID: actor.UserID,
		Action:      "project_permission_revoked",
		Details:     grantAuditDetails(grant),
	})
}

// protectIssueOwnerRevoke keeps task ownership anchored to the effective task
// creator. Unlike project ownership there is no "last task owner" rule: only
// the creator's immutable Owner grant is protected, while other task Owner
// grants remain revocable.
// 2026-09-05 coder(lq): Enforce task creator ownership in the service layer;
// the PostgreSQL adapter repeats the same predicate for direct SQL safety.
func (s *Service) protectIssueOwnerRevoke(ctx context.Context, workspaceID string, grant AccessGrant) error {
	creatorRepo, ok := s.repo.(IssueCreatorRepository)
	if !ok {
		return ErrMigrationRequired
	}
	creator, err := creatorRepo.IssueCreator(ctx, grant.IssueID)
	if err != nil {
		return authorizationStorageError(err)
	}
	if grant.SubjectType == SubjectUser && creator != "" && grant.SubjectID == creator {
		return ErrLastOwner
	}
	return nil
}

// protectProjectOwnerRevoke keeps project ownership anchored to the creator
// and prevents a project from becoming ownerless. The database adapter also
// repeats the owner-count check atomically so concurrent revoke requests
// cannot both observe the same final owner and delete it.
// 2026-09-04 coder(lq): Restore creator Owner as a hard authorization invariant.
func (s *Service) protectProjectOwnerRevoke(ctx context.Context, repo GrantRepository, workspaceID string, grant AccessGrant) error {
	creatorRepo, ok := s.repo.(ProjectCreatorRepository)
	if !ok {
		return ErrMigrationRequired
	}
	creator, err := creatorRepo.ProjectCreator(ctx, grant.ProjectID)
	if err != nil {
		return authorizationStorageError(err)
	}
	if grant.SubjectType == SubjectUser && creator != "" && grant.SubjectID == creator {
		return ErrLastOwner
	}
	grants, err := repo.ListAccessGrants(ctx, workspaceID, grant.ProjectID, "")
	if err != nil {
		return authorizationStorageError(err)
	}
	ownerCount := 0
	for _, candidate := range grants {
		if candidate.IssueID == "" && ProjectRole(candidate.Role) == ProjectOwner {
			ownerCount++
		}
	}
	if ownerCount <= 1 {
		return ErrLastOwner
	}
	return nil
}

func grantAuditDetails(grant AccessGrant) map[string]any {
	return map[string]any{
		"project_id":   grant.ProjectID,
		"issue_id":     grant.IssueID,
		"subject_type": string(grant.SubjectType),
		"subject_id":   grant.SubjectID,
		"role":         string(grant.Role),
		"permission":   string(grant.Permission),
		"source":       string(grant.Source),
	}
}

func (s *Service) recordAudit(ctx context.Context, event AuthorizationAuditEvent) error {
	if audit, ok := s.repo.(AuditRepository); ok {
		return audit.RecordAuthorizationAudit(ctx, event)
	}
	// 2026-08-31 coder(lq): Keep older in-memory/legacy adapters source
	// compatible while production adapters opt into durable audit writes.
	return nil
}

// ListAccessGrants returns the raw, auditable grants for a project or one of
// its tasks. Reading the list requires project visibility; mutation remains
// guarded by MemberManage/IssueManage in GrantAccess and RevokeAccess.
// 2026-08-31 coder(lq): Expose one read seam for project and task permission
// dialogs without coupling HTTP handlers to SQL.
func (s *Service) ListAccessGrants(ctx context.Context, subject Subject, projectID, issueID string) ([]AccessGrant, error) {
	if s == nil || !s.Enabled() {
		return nil, nil
	}
	repo, ok := s.repo.(GrantRepository)
	if !ok {
		return nil, ErrDisabled
	}
	if projectID == "" {
		return nil, ErrNoProjectAccess
	}
	if issueID == "" {
		if err := s.Check(ctx, subject, projectID, View); err != nil {
			return nil, err
		}
	} else {
		if err := s.resolveIssueBinding(ctx, subject, issueID, projectID); err != nil {
			return nil, err
		}
		if err := s.CheckIssue(ctx, subject, issueID, projectID, View); err != nil {
			return nil, err
		}
	}
	return repo.ListAccessGrants(ctx, subject.WorkspaceID, projectID, issueID)
}

// 2026-08-24 coder(lq): Scope project lists to native admins or project_members.
func (s *Service) Scope(ctx context.Context, subject Subject) ([]string, error) {
	return s.ScopeWithWorkspaceOwned(ctx, subject, true)
}

// 2026-08-28 coder(lq): ScopeWithWorkspaceOwned omits workspace-owner-only
// visibility when requested while preserving explicit project grants.
func (s *Service) ScopeWithWorkspaceOwned(ctx context.Context, subject Subject, includeWorkspaceOwned bool) ([]string, error) {
	if s == nil || !s.Enabled() {
		return nil, nil
	}
	if s.repo == nil {
		return nil, ErrDisabled
	}
	if subject.UserID == "" || subject.WorkspaceID == "" {
		return nil, ErrNotWorkspaceMember
	}
	_, err := s.repo.WorkspaceRole(ctx, subject.WorkspaceID, subject.UserID)
	if err != nil {
		if errors.Is(err, ErrNotWorkspaceMember) {
			return nil, ErrNotWorkspaceMember
		}
		return nil, authorizationStorageError(err)
	}
	if scoped, ok := s.repo.(ScopedProjectRepository); ok {
		ids, err := scoped.VisibleProjectIDsWithWorkspaceScope(ctx, subject.WorkspaceID, subject.UserID, includeWorkspaceOwned)
		if err != nil {
			return nil, authorizationStorageError(err)
		}
		return ids, nil
	}
	ids, err := s.repo.VisibleProjectIDs(ctx, subject.WorkspaceID, subject.UserID)
	if err != nil {
		return nil, authorizationStorageError(err)
	}
	return ids, nil
}

func ValidateProjectRole(role ProjectRole) error {
	if !validProjectRole(role) {
		return fmt.Errorf("%w: %s", ErrInvalidRole, role)
	}
	return nil
}
