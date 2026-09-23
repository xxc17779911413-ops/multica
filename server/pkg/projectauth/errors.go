package projectauth

import "errors"

var (
	ErrDisabled               = errors.New("project permissions are disabled")
	ErrNotWorkspaceMember     = errors.New("user is not a workspace member")
	ErrNoProjectAccess        = errors.New("user is not a project member")
	ErrForbidden              = errors.New("project permission denied")
	ErrInvalidRole            = errors.New("invalid project role")
	ErrInvalidRoleScope       = errors.New("role scope does not match resource")
	ErrInvalidIssuePermission = errors.New("invalid issue permission")
	ErrCrossWorkspace         = errors.New("project member is outside the project workspace")
	ErrLastOwner              = errors.New("project must retain at least one owner")
	ErrInvalidReportFilter    = errors.New("invalid permission report filter")
	ErrRoleInUse              = errors.New("project permission role is in use")
	ErrInvalidSubject         = errors.New("invalid project permission subject")
	ErrMigrationRequired      = errors.New("project permission migration is required")
	ErrStorageUnavailable     = errors.New("project permission storage unavailable")
)
