package projectauth

import (
	"context"
	"errors"
	"testing"
)

type organizationDirectoryRepo struct {
	fakeRepo
	members    []OrganizationMember
	membersErr error
}

func (f *organizationDirectoryRepo) ListOrganizationMembers(context.Context, string) ([]OrganizationMember, error) {
	return f.members, f.membersErr
}

func memberDirectorySubject() Subject {
	return Subject{UserID: "u-1", WorkspaceID: "ws-1"}
}

func TestListOrganizationMembersDisabledReturnsEmpty(t *testing.T) {
	members, err := New(nil, false).ListOrganizationMembers(context.Background(), memberDirectorySubject())
	if err != nil {
		t.Fatalf("disabled directory returned error: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("disabled directory returned members: %#v", members)
	}
}

func TestListOrganizationMembersRequiresWorkspaceMembership(t *testing.T) {
	repo := &organizationDirectoryRepo{fakeRepo: fakeRepo{workspaceErr: ErrNotWorkspaceMember}}
	_, err := New(repo, true).ListOrganizationMembers(context.Background(), memberDirectorySubject())
	if !errors.Is(err, ErrNotWorkspaceMember) {
		t.Fatalf("got %v, want %v", err, ErrNotWorkspaceMember)
	}
}

func TestListOrganizationMembersReturnsDirectorySnapshot(t *testing.T) {
	repo := &organizationDirectoryRepo{
		fakeRepo: fakeRepo{workspace: string(WorkspaceMember)},
		members: []OrganizationMember{{
			OrganizationID: "org-a",
			UserID:         "u-2",
			Name:           "Alice",
			Email:          "alice@example.com",
			WorkspaceRole:  WorkspaceMember,
			HasLoggedIn:    true,
		}},
	}
	members, err := New(repo, true).ListOrganizationMembers(context.Background(), memberDirectorySubject())
	if err != nil {
		t.Fatalf("ListOrganizationMembers returned %v", err)
	}
	if len(members) != 1 || members[0].UserID != "u-2" || members[0].OrganizationID != "org-a" || !members[0].HasLoggedIn {
		t.Fatalf("unexpected directory snapshot: %#v", members)
	}
}

func TestListOrganizationMembersPreservesNotLoggedInDirectoryMembers(t *testing.T) {
	repo := &organizationDirectoryRepo{
		fakeRepo: fakeRepo{workspace: string(WorkspaceMember)},
		members: []OrganizationMember{{
			OrganizationID: "org-a",
			UserID:         "u-3",
			Name:           "Bob",
			Email:          "bob@example.com",
			WorkspaceRole:  WorkspaceMember,
			HasLoggedIn:    false,
		}},
	}
	members, err := New(repo, true).ListOrganizationMembers(context.Background(), memberDirectorySubject())
	if err != nil {
		t.Fatalf("ListOrganizationMembers returned %v", err)
	}
	if len(members) != 1 || members[0].UserID != "u-3" || members[0].HasLoggedIn {
		t.Fatalf("expected imported member without login: %#v", members)
	}
}

func TestListOrganizationMembersKeepsOlderAdaptersCompatible(t *testing.T) {
	members, err := New(fakeRepo{workspace: string(WorkspaceMember)}, true).ListOrganizationMembers(context.Background(), memberDirectorySubject())
	if err != nil {
		t.Fatalf("missing optional adapter returned %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("missing optional adapter returned members: %#v", members)
	}
}

func TestListOrganizationMembersMapsStorageErrors(t *testing.T) {
	repo := &organizationDirectoryRepo{
		fakeRepo:   fakeRepo{workspace: string(WorkspaceMember)},
		membersErr: errors.New("database unavailable"),
	}
	_, err := New(repo, true).ListOrganizationMembers(context.Background(), memberDirectorySubject())
	if !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("got %v, want %v", err, ErrStorageUnavailable)
	}
}
