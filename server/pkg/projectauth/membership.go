package projectauth

import "context"

type ProjectMemberRecord struct {
	ProjectID string      `json:"project_id"`
	UserID    string      `json:"user_id"`
	Role      ProjectRole `json:"role"`
}

type MemberRepository interface {
	Repository
	AddProjectMember(ctx context.Context, projectID, userID string, role ProjectRole) error
	PromoteProjectMember(ctx context.Context, projectID, userID string, minimumRole ProjectRole) error
	RemoveProjectMember(ctx context.Context, projectID, userID string) error
	ListProjectMembers(ctx context.Context, projectID string) ([]ProjectMemberRecord, error)
}

// 2026-08-24 coder(lq): Seed the creator as project owner so enabling the
// overlay cannot strand projects created by ordinary workspace members.
func (s *Service) EnsureOwner(ctx context.Context, projectID, userID string) error {
	enabled, err := s.mutationEnabled()
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	mr, ok := s.repo.(MemberRepository)
	if !ok {
		return ErrDisabled
	}
	workspaceID, err := mr.ProjectWorkspace(ctx, projectID)
	if err != nil {
		// 2026-09-04 coder(lq): Keep migration/storage failures intact. The
		// project-create handler needs to distinguish an unavailable permission
		// schema from a genuinely missing project.
		return authorizationStorageError(err)
	}
	if _, err = mr.WorkspaceRole(ctx, workspaceID, userID); err != nil {
		return authorizationStorageError(err)
	}
	return mr.PromoteProjectMember(ctx, projectID, userID, ProjectOwner)
}

// 2026-08-27 coder(lq): Automatic grants are monotonic. Business events may
// raise a member's minimum project role, but must never overwrite a stronger
// explicit grant made by a project owner.
func (s *Service) PromoteMember(ctx context.Context, projectID, userID string, minimumRole ProjectRole) error {
	enabled, err := s.mutationEnabled()
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	if !validProjectRole(minimumRole) {
		return ErrInvalidRole
	}
	mr, ok := s.repo.(MemberRepository)
	if !ok {
		return ErrDisabled
	}
	workspaceID, err := mr.ProjectWorkspace(ctx, projectID)
	if err != nil {
		return authorizationStorageError(err)
	}
	if _, err = mr.WorkspaceRole(ctx, workspaceID, userID); err != nil {
		return authorizationStorageError(err)
	}
	return mr.PromoteProjectMember(ctx, projectID, userID, minimumRole)
}

// 2026-08-24 coder(lq): Perform the two tenant checks that cannot be represented by a
// simple project_members foreign key: the project exists and the user belongs
// to the same native workspace.
func (s *Service) AddMember(ctx context.Context, actor Subject, projectID, userID string, role ProjectRole) error {
	enabled, err := s.mutationEnabled()
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	if err := s.Require(ctx, actor, projectID, MemberManage); err != nil {
		return err
	}
	mr, ok := s.repo.(MemberRepository)
	if !ok {
		return ErrDisabled
	}
	workspaceID, err := mr.ProjectWorkspace(ctx, projectID)
	if err != nil {
		return ErrNoProjectAccess
	}
	if !validProjectRole(role) {
		rr, roleRepoOK := s.repo.(RoleRepository)
		if !roleRepoOK {
			return ErrInvalidRole
		}
		definition, roleErr := rr.GetRoleDefinition(ctx, workspaceID, string(role))
		if roleErr != nil || definition.IsSystem {
			return ErrInvalidRole
		}
	}
	if _, err = mr.WorkspaceRole(ctx, workspaceID, userID); err != nil {
		return ErrCrossWorkspace
	}
	if role != ProjectOwner {
		// 2026-08-27 coder(lq): AddMember also updates existing grants. Protect
		// the final owner from role changes, not only from member removal.
		members, listErr := mr.ListProjectMembers(ctx, projectID)
		if listErr != nil {
			return listErr
		}
		ownerCount := 0
		targetIsOwner := false
		for _, member := range members {
			if member.Role == ProjectOwner {
				ownerCount++
				targetIsOwner = targetIsOwner || member.UserID == userID
			}
		}
		if targetIsOwner && ownerCount <= 1 {
			return ErrLastOwner
		}
		if targetIsOwner {
			creator, creatorErr := s.projectCreator(ctx, projectID)
			if creatorErr != nil {
				return creatorErr
			}
			if creator == userID {
				return ErrLastOwner
			}
		}
	}
	return mr.AddProjectMember(ctx, projectID, userID, role)
}

func (s *Service) ListMembers(ctx context.Context, actor Subject, projectID string) ([]ProjectMemberRecord, error) {
	if s == nil || !s.Enabled() {
		return nil, nil
	}
	// 2026-08-28 coder(lq): The settings matrix is read-only for ordinary
	// project members, so membership rows must be visible with project.view;
	// can_manage remains a separate capability returned by the HTTP handler.
	if err := s.Require(ctx, actor, projectID, View); err != nil {
		return nil, err
	}
	mr, ok := s.repo.(MemberRepository)
	if !ok {
		return nil, ErrDisabled
	}
	return mr.ListProjectMembers(ctx, projectID)
}

func (s *Service) RemoveMember(ctx context.Context, actor Subject, projectID, userID string) error {
	enabled, gateErr := s.mutationEnabled()
	if gateErr != nil {
		return gateErr
	}
	if !enabled {
		return nil
	}
	if err := s.Require(ctx, actor, projectID, MemberManage); err != nil {
		return err
	}
	mr, ok := s.repo.(MemberRepository)
	if !ok {
		return ErrDisabled
	}
	// 2026-08-27 coder(lq): Never leave a project without an owner. The
	// workspace owner can recover access, but project managers must never be
	// able to leave the project without an owner.
	members, err := mr.ListProjectMembers(ctx, projectID)
	if err != nil {
		return err
	}
	ownerCount := 0
	targetIsOwner := false
	for _, member := range members {
		if member.Role == ProjectOwner {
			ownerCount++
			if member.UserID == userID {
				targetIsOwner = true
			}
		}
	}
	if targetIsOwner && ownerCount <= 1 {
		return ErrLastOwner
	}
	if targetIsOwner {
		creator, creatorErr := s.projectCreator(ctx, projectID)
		if creatorErr != nil {
			return creatorErr
		}
		if creator == userID {
			return ErrLastOwner
		}
	}
	return mr.RemoveProjectMember(ctx, projectID, userID)
}

// projectCreator returns the immutable creator identity when the persistence
// adapter exposes it. Older compatibility adapters may omit this optional
// lookup; their existing last-owner protection remains unchanged.
// 2026-09-04 coder(lq): Keep creator ownership intact on legacy member APIs.
func (s *Service) projectCreator(ctx context.Context, projectID string) (string, error) {
	creatorRepo, ok := s.repo.(ProjectCreatorRepository)
	if !ok {
		return "", nil
	}
	creator, err := creatorRepo.ProjectCreator(ctx, projectID)
	if err != nil {
		return "", authorizationStorageError(err)
	}
	return creator, nil
}
