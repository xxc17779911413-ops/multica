package projectauth

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type ProjectAccessMode string

const (
	ProjectAccessInherit    ProjectAccessMode = "inherit"
	ProjectAccessRestricted ProjectAccessMode = "restricted"
)

type AccessSourceKind string

const (
	AccessSourceWorkspaceOwner  AccessSourceKind = "workspace_owner_bypass"
	AccessSourceCreator         AccessSourceKind = "creator"
	AccessSourceAssignee        AccessSourceKind = "assignee"
	AccessSourceOriginator      AccessSourceKind = "delegated_originator"
	AccessSourceMention         AccessSourceKind = "mention"
	AccessSourceIssueDirect     AccessSourceKind = "issue_direct"
	AccessSourceIssueOrg        AccessSourceKind = "issue_organization"
	AccessSourceIssueEveryone   AccessSourceKind = "issue_everyone"
	AccessSourceProjectDirect   AccessSourceKind = "project_direct"
	AccessSourceProjectOrg      AccessSourceKind = "project_organization"
	AccessSourceProjectEveryone AccessSourceKind = "project_everyone"
	AccessSourceParentIssue     AccessSourceKind = "parent_issue"
	AccessSourceAccessRequest   AccessSourceKind = "access_request"
)

type AccessResourceRef struct {
	Scope RoleScope `json:"scope"`
	ID    string    `json:"id"`
}

// IssueAccessResource is the authorization snapshot loaded by the storage
// adapter. Workspace columns for related resources make cross-workspace
// corruption detectable instead of silently treating it as a permission.
type IssueAccessResource struct {
	WorkspaceID        string
	IssueID            string
	ProjectID          string
	ProjectWorkspaceID string
	ParentIssueID      string
	ParentWorkspaceID  string
	CreatorUserID      string
	AssigneeUserID     string
	OriginatorUserID   string
	ProjectAccessMode  ProjectAccessMode
	PolicyVersion      int64
}

type PermissionSource struct {
	Permission         Permission         `json:"permission"`
	Source             AccessSourceKind   `json:"source"`
	UnderlyingSource   AccessSourceKind   `json:"underlying_source,omitempty"`
	SubjectType        SubjectType        `json:"subject_type,omitempty"`
	SubjectID          string             `json:"subject_id,omitempty"`
	Role               RoleKey            `json:"role,omitempty"`
	Scope              RoleScope          `json:"scope,omitempty"`
	GrantID            string             `json:"grant_id,omitempty"`
	GrantSource        GrantSource        `json:"grant_source,omitempty"`
	GrantedBy          string             `json:"granted_by,omitempty"`
	OriginKind         string             `json:"origin_kind,omitempty"`
	OriginID           string             `json:"origin_id,omitempty"`
	ExpiresAt          *time.Time         `json:"expires_at,omitempty"`
	SourceResource     AccessResourceRef  `json:"source_resource"`
	UnderlyingResource *AccessResourceRef `json:"underlying_resource,omitempty"`
	TargetResource     AccessResourceRef  `json:"target_resource"`
	PolicyVersion      int64              `json:"policy_version"`
}

type EffectiveIssueAccess struct {
	WorkspaceID       string             `json:"workspace_id"`
	IssueID           string             `json:"issue_id"`
	ProjectID         string             `json:"project_id,omitempty"`
	ProjectAccessMode ProjectAccessMode  `json:"project_access_mode"`
	PolicyVersion     int64              `json:"policy_version"`
	Permissions       []Permission       `json:"permissions"`
	Sources           []PermissionSource `json:"sources"`
}

type PermissionExplanation struct {
	Allowed    bool                 `json:"allowed"`
	Permission Permission           `json:"permission"`
	Access     EffectiveIssueAccess `json:"access"`
	Sources    []PermissionSource   `json:"sources"`
}

type PolicyImpact struct {
	Before   EffectiveIssueAccess `json:"before"`
	After    EffectiveIssueAccess `json:"after"`
	Granted  []Permission         `json:"granted"`
	Revoked  []Permission         `json:"revoked"`
	Retained []Permission         `json:"retained"`
}

// EffectiveAccessRepository is deliberately additive and provider-neutral.
// The resolver never reads external directories or SQL directly.
type EffectiveAccessRepository interface {
	WorkspaceRole(ctx context.Context, workspaceID, userID string) (WorkspaceRole, error)
	WorkspaceOwnerBypassEnabled(ctx context.Context, workspaceID string) (bool, error)
	IssueAccessResource(ctx context.Context, workspaceID, issueID string) (IssueAccessResource, error)
	ListIssueAccessGrants(ctx context.Context, workspaceID, issueID string) ([]AccessGrant, error)
	ListProjectAccessGrants(ctx context.Context, workspaceID, projectID string) ([]AccessGrant, error)
	ListUserOrganizations(ctx context.Context, workspaceID, userID string) ([]string, error)
	RolePermissions(ctx context.Context, workspaceID string, role ProjectRole) ([]Permission, bool, error)
	TaskRolePermissions(ctx context.Context, workspaceID string, role TaskRole) ([]Permission, bool, error)
}

// EffectiveAccessResolver exposes one core decision algorithm through single,
// batch, explanation, and policy-preview views.
type EffectiveAccessResolver interface {
	ResolveIssue(ctx context.Context, subject Subject, issueID string) (EffectiveIssueAccess, error)
	ResolveIssues(ctx context.Context, subject Subject, issueIDs []string) (map[string]EffectiveIssueAccess, error)
	CanIssue(ctx context.Context, subject Subject, issueID string, permission Permission) error
	ExplainIssue(ctx context.Context, subject Subject, issueID string, permission Permission) (PermissionExplanation, error)
	PreviewIssuePolicyChange(ctx context.Context, subject Subject, issueID string, mode ProjectAccessMode) (PolicyImpact, error)
}

type effectiveAccessResolver struct {
	repo EffectiveAccessRepository
	now  func() time.Time
}

func NewEffectiveAccessResolver(repo EffectiveAccessRepository) EffectiveAccessResolver {
	return NewEffectiveAccessResolverWithClock(repo, time.Now)
}

func NewEffectiveAccessResolverWithClock(repo EffectiveAccessRepository, now func() time.Time) EffectiveAccessResolver {
	return &effectiveAccessResolver{repo: repo, now: now}
}

type effectiveEvaluation struct {
	resolver      *effectiveAccessResolver
	subject       Subject
	workspaceRole WorkspaceRole
	ownerBypass   bool
	organizations map[string]struct{}
	resources     map[string]IssueAccessResource
	issueGrants   map[string][]AccessGrant
	projectGrants map[string][]AccessGrant
	projectRoles  map[ProjectRole][]Permission
	taskRoles     map[TaskRole][]Permission
}

func (r *effectiveAccessResolver) newEvaluation(ctx context.Context, subject Subject) (*effectiveEvaluation, error) {
	if r == nil || r.repo == nil || subject.UserID == "" || subject.WorkspaceID == "" {
		return nil, ErrNotWorkspaceMember
	}
	role, err := r.repo.WorkspaceRole(ctx, subject.WorkspaceID, subject.UserID)
	if err != nil {
		return nil, authorizationStorageError(err)
	}
	if role != WorkspaceOwner && role != WorkspaceAdmin && role != WorkspaceMember {
		return nil, ErrNotWorkspaceMember
	}
	bypass, err := r.repo.WorkspaceOwnerBypassEnabled(ctx, subject.WorkspaceID)
	if err != nil {
		return nil, authorizationStorageError(err)
	}
	organizations, err := r.repo.ListUserOrganizations(ctx, subject.WorkspaceID, subject.UserID)
	if err != nil {
		return nil, authorizationStorageError(err)
	}
	orgSet := make(map[string]struct{}, len(organizations))
	for _, organization := range organizations {
		orgSet[organization] = struct{}{}
	}
	return &effectiveEvaluation{resolver: r, subject: subject, workspaceRole: role, ownerBypass: bypass, organizations: orgSet,
		resources: map[string]IssueAccessResource{}, issueGrants: map[string][]AccessGrant{}, projectGrants: map[string][]AccessGrant{},
		projectRoles: map[ProjectRole][]Permission{}, taskRoles: map[TaskRole][]Permission{}}, nil
}

func (r *effectiveAccessResolver) ResolveIssue(ctx context.Context, subject Subject, issueID string) (EffectiveIssueAccess, error) {
	evaluation, err := r.newEvaluation(ctx, subject)
	if err != nil {
		return EffectiveIssueAccess{}, err
	}
	return evaluation.resolve(ctx, issueID, nil)
}

func (r *effectiveAccessResolver) ResolveIssues(ctx context.Context, subject Subject, issueIDs []string) (map[string]EffectiveIssueAccess, error) {
	evaluation, err := r.newEvaluation(ctx, subject)
	if err != nil {
		return nil, err
	}
	result := make(map[string]EffectiveIssueAccess, len(issueIDs))
	for _, issueID := range issueIDs {
		if _, duplicate := result[issueID]; duplicate {
			continue
		}
		access, resolveErr := evaluation.resolve(ctx, issueID, nil)
		if resolveErr != nil {
			return nil, resolveErr
		}
		result[issueID] = access
	}
	return result, nil
}

func (r *effectiveAccessResolver) CanIssue(ctx context.Context, subject Subject, issueID string, permission Permission) error {
	if !IsKnownPermission(permission) || !IsTaskPermission(permission) {
		return ErrInvalidIssuePermission
	}
	access, err := r.ResolveIssue(ctx, subject, issueID)
	if err != nil {
		return err
	}
	if !containsPermission(access.Permissions, permission) {
		return ErrForbidden
	}
	return nil
}

func (r *effectiveAccessResolver) ExplainIssue(ctx context.Context, subject Subject, issueID string, permission Permission) (PermissionExplanation, error) {
	if !IsKnownPermission(permission) || !IsTaskPermission(permission) {
		return PermissionExplanation{}, ErrInvalidIssuePermission
	}
	access, err := r.ResolveIssue(ctx, subject, issueID)
	if err != nil {
		return PermissionExplanation{}, err
	}
	explanation := PermissionExplanation{Permission: permission, Access: access}
	for _, source := range access.Sources {
		if source.Permission == permission {
			explanation.Allowed = true
			explanation.Sources = append(explanation.Sources, source)
		}
	}
	return explanation, nil
}

func (r *effectiveAccessResolver) PreviewIssuePolicyChange(ctx context.Context, subject Subject, issueID string, mode ProjectAccessMode) (PolicyImpact, error) {
	if mode != ProjectAccessInherit && mode != ProjectAccessRestricted {
		return PolicyImpact{}, ErrInvalidIssuePermission
	}
	evaluation, err := r.newEvaluation(ctx, subject)
	if err != nil {
		return PolicyImpact{}, err
	}
	before, err := evaluation.resolve(ctx, issueID, nil)
	if err != nil {
		return PolicyImpact{}, err
	}
	after, err := evaluation.resolve(ctx, issueID, &mode)
	if err != nil {
		return PolicyImpact{}, err
	}
	impact := PolicyImpact{Before: before, After: after}
	beforeSet, afterSet := permissionSet(before.Permissions), permissionSet(after.Permissions)
	for _, permission := range allTaskPermissions() {
		_, had := beforeSet[permission]
		_, has := afterSet[permission]
		switch {
		case had && has:
			impact.Retained = append(impact.Retained, permission)
		case had:
			impact.Revoked = append(impact.Revoked, permission)
		case has:
			impact.Granted = append(impact.Granted, permission)
		}
	}
	return impact, nil
}

func permissionSet(permissions []Permission) map[Permission]struct{} {
	result := make(map[Permission]struct{}, len(permissions))
	for _, permission := range permissions {
		result[permission] = struct{}{}
	}
	return result
}

func containsPermission(permissions []Permission, permission Permission) bool {
	_, ok := permissionSet(permissions)[permission]
	return ok
}

func (e *effectiveEvaluation) resolve(ctx context.Context, issueID string, override *ProjectAccessMode) (EffectiveIssueAccess, error) {
	resource, err := e.resource(ctx, issueID)
	if err != nil {
		return EffectiveIssueAccess{}, err
	}
	mode := resource.ProjectAccessMode
	if override != nil {
		mode = *override
	}
	base, err := e.base(ctx, resource, mode)
	if err != nil {
		return EffectiveIssueAccess{}, err
	}
	sources := base
	if resource.ParentIssueID != "" {
		parent, parentErr := e.resource(ctx, resource.ParentIssueID)
		if parentErr != nil {
			return EffectiveIssueAccess{}, parentErr
		}
		if parent.IssueID != resource.ParentIssueID || parent.WorkspaceID != resource.WorkspaceID {
			return EffectiveIssueAccess{}, ErrCrossWorkspace
		}
		parentBase, parentErr := e.base(ctx, parent, parent.ProjectAccessMode)
		if parentErr != nil {
			return EffectiveIssueAccess{}, parentErr
		}
		for _, source := range parentBase {
			source.UnderlyingSource = source.Source
			underlyingResource := source.SourceResource
			source.UnderlyingResource = &underlyingResource
			source.Source = AccessSourceParentIssue
			source.SourceResource = AccessResourceRef{Scope: RoleScopeTask, ID: parent.IssueID}
			source.TargetResource = AccessResourceRef{Scope: RoleScopeTask, ID: resource.IssueID}
			source.PolicyVersion = resource.PolicyVersion
			sources = append(sources, source)
		}
	}
	if e.ownerBypass && e.workspaceRole == WorkspaceOwner {
		for _, permission := range allTaskPermissions() {
			sources = append(sources, PermissionSource{Permission: permission, Source: AccessSourceWorkspaceOwner, Role: RoleKey(WorkspaceOwner), Scope: RoleScopeWorkspace,
				SubjectType: SubjectUser, SubjectID: e.subject.UserID, SourceResource: AccessResourceRef{Scope: RoleScopeWorkspace, ID: resource.WorkspaceID},
				TargetResource: AccessResourceRef{Scope: RoleScopeTask, ID: resource.IssueID}, PolicyVersion: resource.PolicyVersion})
		}
	}
	sources = deduplicateSources(sources)
	permissions := make([]Permission, 0)
	seen := map[Permission]struct{}{}
	for _, source := range sources {
		if _, ok := seen[source.Permission]; !ok {
			seen[source.Permission] = struct{}{}
			permissions = append(permissions, source.Permission)
		}
	}
	sort.Slice(permissions, func(i, j int) bool { return permissions[i] < permissions[j] })
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Permission != sources[j].Permission {
			return sources[i].Permission < sources[j].Permission
		}
		if sources[i].Source != sources[j].Source {
			return sources[i].Source < sources[j].Source
		}
		return sources[i].GrantID < sources[j].GrantID
	})
	return EffectiveIssueAccess{WorkspaceID: resource.WorkspaceID, IssueID: resource.IssueID, ProjectID: resource.ProjectID,
		ProjectAccessMode: mode, PolicyVersion: resource.PolicyVersion, Permissions: permissions, Sources: sources}, nil
}

func (e *effectiveEvaluation) resource(ctx context.Context, issueID string) (IssueAccessResource, error) {
	if resource, ok := e.resources[issueID]; ok {
		return resource, nil
	}
	resource, err := e.resolver.repo.IssueAccessResource(ctx, e.subject.WorkspaceID, issueID)
	if err != nil {
		return IssueAccessResource{}, authorizationStorageError(err)
	}
	if resource.WorkspaceID != e.subject.WorkspaceID || resource.IssueID != issueID {
		return IssueAccessResource{}, ErrCrossWorkspace
	}
	if resource.ProjectID != "" && resource.ProjectWorkspaceID != resource.WorkspaceID {
		return IssueAccessResource{}, ErrCrossWorkspace
	}
	if resource.ParentIssueID != "" && resource.ParentWorkspaceID != resource.WorkspaceID {
		return IssueAccessResource{}, ErrCrossWorkspace
	}
	if resource.ProjectAccessMode == "" {
		resource.ProjectAccessMode = ProjectAccessInherit
	}
	if resource.ProjectAccessMode != ProjectAccessInherit && resource.ProjectAccessMode != ProjectAccessRestricted {
		return IssueAccessResource{}, ErrInvalidIssuePermission
	}
	if resource.PolicyVersion <= 0 {
		resource.PolicyVersion = 1
	}
	e.resources[issueID] = resource
	return resource, nil
}

func (e *effectiveEvaluation) base(ctx context.Context, resource IssueAccessResource, mode ProjectAccessMode) ([]PermissionSource, error) {
	result := make([]PermissionSource, 0)
	for _, dynamic := range []struct {
		user   string
		role   TaskRole
		source AccessSourceKind
	}{
		{resource.CreatorUserID, TaskOwner, AccessSourceCreator}, {resource.AssigneeUserID, TaskMember, AccessSourceAssignee}, {resource.OriginatorUserID, TaskMember, AccessSourceOriginator},
	} {
		if dynamic.user != e.subject.UserID {
			continue
		}
		permissions, err := e.taskRolePermissions(ctx, dynamic.role)
		if err != nil {
			return nil, err
		}
		result = append(result, e.roleSources(resource, permissions, RoleKey(dynamic.role), RoleScopeTask, dynamic.source, AccessGrant{
			SubjectType: SubjectUser, SubjectID: dynamic.user, Source: GrantSourceSystem,
		})...)
	}
	grants, err := e.issueAccessGrants(ctx, resource)
	if err != nil {
		return nil, err
	}
	taskRoles := roleSetForSubject(grants, e.subject, e.organizations, RoleScopeTask, e.resolver.now())
	for _, grant := range grants {
		matches, matchErr := grantMatches(grant, e.subject, e.organizations, taskRoles, RoleScopeTask)
		if matchErr != nil {
			return nil, matchErr
		}
		if !matches || isExpired(grant, e.resolver.now()) {
			continue
		}
		permissionSources, sourceErr := e.grantSources(ctx, resource, grant, RoleScopeTask, false)
		if sourceErr != nil {
			return nil, sourceErr
		}
		result = append(result, permissionSources...)
	}
	if mode == ProjectAccessInherit && resource.ProjectID != "" {
		projectGrants, grantErr := e.projectAccessGrants(ctx, resource)
		if grantErr != nil {
			return nil, grantErr
		}
		projectRoles := roleSetForSubject(projectGrants, e.subject, e.organizations, RoleScopeProject, e.resolver.now())
		for _, grant := range projectGrants {
			matches, matchErr := grantMatches(grant, e.subject, e.organizations, projectRoles, RoleScopeProject)
			if matchErr != nil {
				return nil, matchErr
			}
			if !matches || isExpired(grant, e.resolver.now()) {
				continue
			}
			permissionSources, sourceErr := e.grantSources(ctx, resource, grant, RoleScopeProject, true)
			if sourceErr != nil {
				return nil, sourceErr
			}
			result = append(result, permissionSources...)
		}
	}
	return result, nil
}

func (e *effectiveEvaluation) issueAccessGrants(ctx context.Context, resource IssueAccessResource) ([]AccessGrant, error) {
	if grants, ok := e.issueGrants[resource.IssueID]; ok {
		return grants, nil
	}
	grants, err := e.resolver.repo.ListIssueAccessGrants(ctx, resource.WorkspaceID, resource.IssueID)
	if err != nil {
		return nil, authorizationStorageError(err)
	}
	for index := range grants {
		grant := &grants[index]
		if grant.WorkspaceID != resource.WorkspaceID || grant.IssueID != resource.IssueID || grant.ProjectID != resource.ProjectID {
			return nil, ErrCrossWorkspace
		}
		if err := grant.NormalizeRoleScope(); err != nil {
			return nil, err
		}
		if err := validateGrantShape(*grant); err != nil {
			return nil, err
		}
	}
	e.issueGrants[resource.IssueID] = grants
	return grants, nil
}

func (e *effectiveEvaluation) projectAccessGrants(ctx context.Context, resource IssueAccessResource) ([]AccessGrant, error) {
	if grants, ok := e.projectGrants[resource.ProjectID]; ok {
		return grants, nil
	}
	grants, err := e.resolver.repo.ListProjectAccessGrants(ctx, resource.WorkspaceID, resource.ProjectID)
	if err != nil {
		return nil, authorizationStorageError(err)
	}
	for index := range grants {
		grant := &grants[index]
		if grant.WorkspaceID != resource.WorkspaceID || grant.ProjectID != resource.ProjectID || grant.IssueID != "" {
			return nil, ErrCrossWorkspace
		}
		if err := grant.NormalizeRoleScope(); err != nil {
			return nil, err
		}
		if err := validateGrantShape(*grant); err != nil {
			return nil, err
		}
	}
	e.projectGrants[resource.ProjectID] = grants
	return grants, nil
}

func roleSetForSubject(grants []AccessGrant, subject Subject, organizations map[string]struct{}, scope RoleScope, now time.Time) map[RoleKey]struct{} {
	roles := map[RoleKey]struct{}{}
	for _, grant := range grants {
		if grant.Scope != scope || grant.Role == "" || grant.SubjectType == SubjectRole || isExpired(grant, now) {
			continue
		}
		if directSubjectMatch(grant, subject, organizations) {
			roles[grant.Role] = struct{}{}
		}
	}
	return roles
}

func grantMatches(grant AccessGrant, subject Subject, organizations map[string]struct{}, roles map[RoleKey]struct{}, scope RoleScope) (bool, error) {
	if grant.Role != "" && grant.Scope != scope {
		return false, ErrInvalidRoleScope
	}
	if grant.Permission != "" && !IsKnownPermission(grant.Permission) {
		return false, ErrInvalidIssuePermission
	}
	if grant.SubjectType == SubjectRole {
		_, ok := roles[RoleKey(grant.SubjectID)]
		return ok, nil
	}
	return directSubjectMatch(grant, subject, organizations), nil
}

func directSubjectMatch(grant AccessGrant, subject Subject, organizations map[string]struct{}) bool {
	switch grant.SubjectType {
	case SubjectUser:
		return grant.SubjectID == subject.UserID
	case SubjectOrganization:
		_, ok := organizations[grant.SubjectID]
		return ok
	case SubjectEveryone:
		return grant.SubjectID == "" || grant.SubjectID == subject.WorkspaceID
	default:
		return false
	}
}

func isExpired(grant AccessGrant, now time.Time) bool {
	return grant.ExpiresAt != nil && !grant.ExpiresAt.After(now)
}

func (e *effectiveEvaluation) grantSources(ctx context.Context, resource IssueAccessResource, grant AccessGrant, scope RoleScope, project bool) ([]PermissionSource, error) {
	permissions := []Permission{grant.Permission}
	if grant.Role != "" {
		var err error
		if scope == RoleScopeTask {
			permissions, err = e.taskRolePermissions(ctx, TaskRole(grant.Role))
		} else {
			permissions, err = e.projectRolePermissions(ctx, ProjectRole(grant.Role))
		}
		if err != nil {
			return nil, err
		}
	}
	if grant.Role == "" && grant.Permission == "" {
		return nil, ErrInvalidRole
	}
	if project {
		capped, capErr := ProjectPermissionsToTask(permissions)
		if capErr != nil {
			return nil, capErr
		}
		permissions = capped
	} else {
		var err error
		permissions, err = TaskPermissionCap(permissions)
		if err != nil {
			return nil, err
		}
	}
	source := accessSourceForGrant(grant, project)
	return e.roleSources(resource, permissions, grant.Role, scope, source, grant), nil
}

func accessSourceForGrant(grant AccessGrant, project bool) AccessSourceKind {
	if grant.OriginKind == "access_request" {
		return AccessSourceAccessRequest
	}
	if project {
		switch grant.SubjectType {
		case SubjectOrganization:
			return AccessSourceProjectOrg
		case SubjectEveryone:
			return AccessSourceProjectEveryone
		default:
			return AccessSourceProjectDirect
		}
	}
	if grant.Source == GrantSourceSystem && grant.SubjectType == SubjectUser {
		return AccessSourceMention
	}
	switch grant.SubjectType {
	case SubjectOrganization:
		return AccessSourceIssueOrg
	case SubjectEveryone:
		return AccessSourceIssueEveryone
	default:
		return AccessSourceIssueDirect
	}
}

func (e *effectiveEvaluation) roleSources(resource IssueAccessResource, permissions []Permission, role RoleKey, scope RoleScope, source AccessSourceKind, grant AccessGrant) []PermissionSource {
	result := make([]PermissionSource, 0, len(permissions))
	sourceID := resource.IssueID
	if scope == RoleScopeProject {
		sourceID = resource.ProjectID
	}
	for _, permission := range permissions {
		result = append(result, PermissionSource{Permission: permission, Source: source, SubjectType: grant.SubjectType, SubjectID: grant.SubjectID,
			Role: role, Scope: scope, GrantID: grant.ID, GrantSource: grant.Source, GrantedBy: grant.GrantedBy, OriginKind: grant.OriginKind, OriginID: grant.OriginID, ExpiresAt: grant.ExpiresAt,
			SourceResource: AccessResourceRef{Scope: scope, ID: sourceID}, TargetResource: AccessResourceRef{Scope: RoleScopeTask, ID: resource.IssueID}, PolicyVersion: resource.PolicyVersion})
	}
	return result
}

func (e *effectiveEvaluation) taskRolePermissions(ctx context.Context, role TaskRole) ([]Permission, error) {
	if permissions, ok := e.taskRoles[role]; ok {
		return permissions, nil
	}
	permissions, found, err := e.resolver.repo.TaskRolePermissions(ctx, e.subject.WorkspaceID, role)
	if err != nil {
		return nil, authorizationStorageError(err)
	}
	if !found {
		return nil, ErrInvalidRole
	}
	capped, err := TaskPermissionCap(permissions)
	if err != nil {
		return nil, err
	}
	e.taskRoles[role] = capped
	return capped, nil
}

func (e *effectiveEvaluation) projectRolePermissions(ctx context.Context, role ProjectRole) ([]Permission, error) {
	if permissions, ok := e.projectRoles[role]; ok {
		return permissions, nil
	}
	permissions, found, err := e.resolver.repo.RolePermissions(ctx, e.subject.WorkspaceID, role)
	if err != nil {
		return nil, authorizationStorageError(err)
	}
	if !found {
		return nil, ErrInvalidRole
	}
	for _, permission := range permissions {
		if !IsKnownPermission(permission) {
			return nil, fmt.Errorf("%w: %s", ErrInvalidIssuePermission, permission)
		}
	}
	e.projectRoles[role] = permissions
	return permissions, nil
}

func deduplicateSources(sources []PermissionSource) []PermissionSource {
	result := make([]PermissionSource, 0, len(sources))
	seen := map[string]struct{}{}
	for _, source := range sources {
		key := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", source.Permission, source.Source, source.GrantID, source.SubjectID, source.Role, source.SourceResource.ID, source.UnderlyingSource)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, source)
	}
	return result
}
