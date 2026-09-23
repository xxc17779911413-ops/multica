import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderWithI18n } from "../../test/i18n";
import { configStore } from "@multica/core/config";

const {
  listProjectMembers,
  listMembers,
  addProjectMember,
  removeProjectMember,
  listProjectAccessGrants,
  listProjectAuthorizationOrganizations,
  listProjectPermissionRoles,
  createProjectAccessGrant,
  revokeProjectAccessGrant,
  toastSuccess,
  toastError,
} = vi.hoisted(() => ({
  listProjectMembers: vi.fn(),
  listMembers: vi.fn(),
  addProjectMember: vi.fn(),
  removeProjectMember: vi.fn(),
  listProjectAccessGrants: vi.fn(),
  listProjectAuthorizationOrganizations: vi.fn(),
  listProjectPermissionRoles: vi.fn(),
  createProjectAccessGrant: vi.fn(),
  revokeProjectAccessGrant: vi.fn(),
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
}));

vi.mock("@multica/core/api", () => ({
  api: {
    listProjectMembers,
    listMembers,
    addProjectMember,
    removeProjectMember,
    listProjectAccessGrants,
    listProjectAuthorizationOrganizations,
    listProjectPermissionRoles,
    createProjectAccessGrant,
    revokeProjectAccessGrant,
  },
}));

vi.mock("@multica/core/hooks", () => ({
  useWorkspaceId: () => "workspace-1",
}));

vi.mock("sonner", () => ({
  toast: {
    success: toastSuccess,
    error: toastError,
  },
}));

import { ProjectPermissionsDialog } from "./project-permissions-dialog";

const workspaceMembers = [
  {
    id: "membership-alice",
    workspace_id: "workspace-1",
    user_id: "alice",
    role: "member",
    created_at: "2026-08-27T00:00:00Z",
    name: "Alice Owner",
    email: "alice@example.com",
    avatar_url: null,
    has_logged_in: true,
  },
  {
    id: "membership-bob",
    workspace_id: "workspace-1",
    user_id: "bob",
    role: "member",
    created_at: "2026-08-27T00:00:00Z",
    name: "Bob Builder",
    email: "bob@example.com",
    avatar_url: null,
    has_logged_in: true,
  },
  {
    id: "membership-carol",
    workspace_id: "workspace-1",
    user_id: "carol",
    role: "member",
    created_at: "2026-08-27T00:00:00Z",
    name: "Carol Reviewer",
    email: "carol@example.com",
    avatar_url: null,
    has_logged_in: true,
  },
  {
    id: "membership-dave",
    workspace_id: "workspace-1",
    user_id: "dave",
    role: "member",
    created_at: "2026-08-27T00:00:00Z",
    name: "Dave Designer",
    email: "dave@example.com",
    avatar_url: null,
    has_logged_in: true,
  },
];

// The projects list mounts this dialog open with its own trigger button, which is
// how a reader without manage rights reaches it.
function renderOpenDialog() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return renderWithI18n(
    <QueryClientProvider client={queryClient}>
      <ProjectPermissionsDialog projectId="project-1" open hideTrigger />
    </QueryClientProvider>,
  );
}

function renderDialog() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return renderWithI18n(
    <QueryClientProvider client={queryClient}>
      <ProjectPermissionsDialog projectId="project-1" />
    </QueryClientProvider>,
  );
}

describe("ProjectPermissionsDialog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listProjectMembers.mockResolvedValue({
      members: [
        { project_id: "project-1", user_id: "alice", role: "owner" },
        { project_id: "project-1", user_id: "bob", role: "member" },
      ],
      total: 2,
      can_manage: true,
    });
    listMembers.mockResolvedValue(workspaceMembers);
    addProjectMember.mockResolvedValue(undefined);
    removeProjectMember.mockResolvedValue(undefined);
    listProjectAccessGrants.mockResolvedValue({ grants: [], total: 0, project_id: "project-1" });
    listProjectAuthorizationOrganizations.mockResolvedValue({ organizations: [], members: [], total: 0, member_total: 0 });
    listProjectPermissionRoles.mockResolvedValue({ roles: [
      { id: "role-owner", workspace_id: "workspace-1", key: "owner", name: "Owner", description: "", permissions: [], is_system: true },
      { id: "role-manager", workspace_id: "workspace-1", key: "manager", name: "Manager", description: "", permissions: [], is_system: true },
      { id: "role-member", workspace_id: "workspace-1", key: "member", name: "Member", description: "", permissions: [], is_system: true },
      { id: "role-viewer", workspace_id: "workspace-1", key: "viewer", name: "Viewer", description: "", permissions: [], is_system: true },
    ] });
    createProjectAccessGrant.mockImplementation(async (projectId: string, data: Record<string, unknown>) => ({
      id: `${data.subject_type}-${data.subject_id ?? "everyone"}`,
      workspace_id: "workspace-1",
      project_id: projectId,
      source: "manual",
      ...data,
    }));
    revokeProjectAccessGrant.mockResolvedValue(undefined);
    configStore.getState().setAuthConfig({ allowSignup: true, projectPermissionsEnabled: false });
  });

  it("only shows the authorization action to project member managers", async () => {
    listProjectMembers.mockResolvedValue({ members: [], total: 0, can_manage: false });

    renderDialog();

    await waitFor(() => expect(listProjectMembers).toHaveBeenCalledWith("project-1"));
    expect(screen.queryByRole("button", { name: "Access" })).not.toBeInTheDocument();
  });

  it("explains the permission boundary instead of rendering an empty dialog", async () => {
    // Every section is manage-only, so this reader used to get a dialog with a
    // title, a description and a close button, which reads as a broken screen.
    listProjectMembers.mockResolvedValue({ members: [], total: 0, can_manage: false });

    renderOpenDialog();

    expect(await screen.findByRole("dialog", { name: "Project access" })).toBeInTheDocument();
    expect(
      await screen.findByText(/do not have permission to manage this project/),
    ).toBeInTheDocument();
  });

  it("shows all current grants separately from ungranted workspace members", async () => {
    const user = userEvent.setup();
    renderDialog();

    await user.click(await screen.findByRole("button", { name: "Access" }));
    expect(await screen.findByRole("dialog", { name: "Project access" })).toBeInTheDocument();

    await user.click(await screen.findByRole("button", { name: "Already granted 2" }));
    const currentAccess = await screen.findByRole("region", { name: "Current project access" });
    expect(within(currentAccess).getByText("Alice Owner")).toBeInTheDocument();
    expect(within(currentAccess).getByText("Bob Builder")).toBeInTheDocument();
    expect(within(currentAccess).queryByText("Carol Reviewer")).not.toBeInTheDocument();
    await user.click(screen.getAllByRole("button", { name: "Close" }).at(-1)!);

    const addMembers = screen.getByRole("region", { name: "Grant access" });
    expect(within(addMembers).queryByText("Alice Owner")).not.toBeInTheDocument();
    expect(within(addMembers).queryByText("Bob Builder")).not.toBeInTheDocument();
    await user.click(within(addMembers).getByRole("button", { name: "Search by name or email" }));
    expect(await screen.findByRole("option", { name: /Carol Reviewer/ })).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText("Search by name or email"), "carol@example");

    expect(screen.getByRole("option", { name: /Carol Reviewer/ })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /Dave Designer/ })).not.toBeInTheDocument();
  });

  it("changes one existing project member role directly", async () => {
    const user = userEvent.setup();
    renderDialog();

    await user.click(await screen.findByRole("button", { name: "Access" }));
    await user.click(await screen.findByRole("button", { name: "Already granted 2" }));
    await user.click(await screen.findByRole("combobox", { name: "Change role for Bob Builder" }));
    await user.click(await screen.findByRole("option", { name: "Manager" }));

    await waitFor(() => {
      expect(addProjectMember).toHaveBeenCalledWith("project-1", { user_id: "bob", role: "manager" });
    });
    expect(toastSuccess).toHaveBeenCalledWith("Project access updated");
  });

  it("grants one selected role to multiple workspace members", async () => {
    const user = userEvent.setup();
    renderDialog();

    await user.click(await screen.findByRole("button", { name: "Access" }));
    const addMembers = screen.getByRole("region", { name: "Grant access" });
    await user.click(within(addMembers).getByRole("button", { name: "Search by name or email" }));
    await screen.findByRole("option", { name: /Carol Reviewer/ });
    await user.click(screen.getByRole("checkbox", { name: "Carol Reviewer" }));
    await user.click(screen.getByRole("checkbox", { name: "Dave Designer" }));
    expect(screen.getByRole("checkbox", { name: "Carol Reviewer" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Dave Designer" })).toBeChecked();

    const rolePicker = screen.getByRole("combobox", { name: "Project role to grant" });
    await user.click(rolePicker);
    const viewerOption = await screen.findByRole("option", { name: "Viewer" });
    expect(viewerOption.closest('[data-slot="select-content"]')).toHaveAttribute("data-align-trigger", "false");
    await user.click(viewerOption);
    await user.click(screen.getByRole("button", { name: "Grant access" }));

    await waitFor(() => expect(addProjectMember).toHaveBeenCalledTimes(2));
    expect(addProjectMember).toHaveBeenCalledWith("project-1", { user_id: "carol", role: "viewer" });
    expect(addProjectMember).toHaveBeenCalledWith("project-1", { user_id: "dave", role: "viewer" });
    expect(toastSuccess).toHaveBeenCalledWith("Project access updated");
  });

  it("keeps only failed members selected after a partial bulk failure", async () => {
    addProjectMember
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("grant failed"));
    const user = userEvent.setup();
    renderDialog();

    await user.click(await screen.findByRole("button", { name: "Access" }));
    const addMembers = screen.getByRole("region", { name: "Grant access" });
    await user.click(within(addMembers).getByRole("button", { name: "Search by name or email" }));
    await screen.findByRole("option", { name: /Carol Reviewer/ });
    await user.click(screen.getByRole("checkbox", { name: "Carol Reviewer" }));
    await user.click(screen.getByRole("checkbox", { name: "Dave Designer" }));
    expect(screen.getByRole("checkbox", { name: "Carol Reviewer" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Dave Designer" })).toBeChecked();
    await user.click(screen.getByRole("button", { name: "Grant access" }));

    await waitFor(() => expect(toastError).toHaveBeenCalledWith("Some members could not be updated. Try again."));
    await user.click(screen.getByRole("button", { name: "Search by name or email" }));
    expect(screen.getByRole("checkbox", { name: "Carol Reviewer" })).not.toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Dave Designer" })).toBeChecked();
  });

  it("removes an existing project member", async () => {
    const user = userEvent.setup();
    renderDialog();

    await user.click(await screen.findByRole("button", { name: "Access" }));
    await user.click(await screen.findByRole("button", { name: "Already granted 2" }));
    await user.click(await screen.findByRole("button", { name: "Remove project access for Alice Owner" }));

    await waitFor(() => expect(removeProjectMember).toHaveBeenCalledWith("project-1", "alice"));
    expect(toastSuccess).toHaveBeenCalledWith("Project member removed");
  });

  it("grants a project role to a department without expanding it into users", async () => {
    configStore.getState().setAuthConfig({ allowSignup: true, projectPermissionsEnabled: true });
    listProjectAuthorizationOrganizations.mockResolvedValue({
      organizations: [{ id: "org-a", workspace_id: "workspace-1", provider: "manual", external_id: "dept-a", name: "Department A", status: "active" }],
      members: [], total: 1, member_total: 0,
    });
    const user = userEvent.setup();
    renderDialog();

    await user.click(await screen.findByRole("button", { name: "Access" }));
    const addMembers = screen.getByRole("region", { name: "Grant access" });
    await user.click(within(addMembers).getByRole("button", { name: "Select organization" }));
    await user.click(await screen.findByRole("checkbox", { name: "Department A" }));
    await user.click(within(addMembers).getByRole("combobox", { name: "Project role to grant" }));
    await user.click(await screen.findByRole("option", { name: "Member" }));
    await user.click(screen.getByRole("button", { name: "Grant access" }));

    await waitFor(() => expect(createProjectAccessGrant).toHaveBeenCalledWith("project-1", {
      subject_type: "organization", subject_id: "org-a", role: "member",
    }));
    expect(addProjectMember).not.toHaveBeenCalled();
  });

  it("grants a project role to a person through the unified authorization table", async () => {
    configStore.getState().setAuthConfig({ allowSignup: true, projectPermissionsEnabled: true });
    const user = userEvent.setup();
    renderDialog();

    await user.click(await screen.findByRole("button", { name: "Access" }));
    const addMembers = screen.getByRole("region", { name: "Grant access" });
    await user.click(within(addMembers).getByRole("button", { name: "Search by name or email" }));
    await user.click(await screen.findByRole("checkbox", { name: "Carol Reviewer" }));
    await user.click(within(addMembers).getByRole("combobox", { name: "Project role to grant" }));
    await user.click(await screen.findByRole("option", { name: "Member" }));
    await user.click(screen.getByRole("button", { name: "Grant access" }));

    await waitFor(() => expect(createProjectAccessGrant).toHaveBeenCalledWith("project-1", {
      subject_type: "user", subject_id: "carol", role: "member",
    }));
    expect(addProjectMember).not.toHaveBeenCalled();
  });

  it("uses unified user grants, rather than legacy members, for the addable list", async () => {
    configStore.getState().setAuthConfig({ allowSignup: true, projectPermissionsEnabled: true });
    listProjectAccessGrants.mockResolvedValue({
      grants: [{ id: "grant-carol", workspace_id: "workspace-1", project_id: "project-1", subject_type: "user", subject_id: "carol", role: "member", source: "manual" }],
      total: 1,
      project_id: "project-1",
    });
    const user = userEvent.setup();
    renderDialog();

    await user.click(await screen.findByRole("button", { name: "Access" }));
    const addMembers = screen.getByRole("region", { name: "Grant access" });
    await user.click(within(addMembers).getByRole("button", { name: "Search by name or email" }));
    expect(await screen.findByRole("option", { name: /Alice Owner/ })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /Bob Builder/ })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /Carol Reviewer/ })).not.toBeInTheDocument();
  });

  it("updates a unified grant by creating the replacement before revoking the old one", async () => {
    configStore.getState().setAuthConfig({ allowSignup: true, projectPermissionsEnabled: true });
    listProjectAccessGrants.mockResolvedValue({
      grants: [{ id: "grant-1", workspace_id: "workspace-1", project_id: "project-1", subject_type: "organization", subject_id: "org-a", role: "viewer", source: "manual" }],
      total: 1, project_id: "project-1",
    });
    listProjectAuthorizationOrganizations.mockResolvedValue({
      organizations: [{ id: "org-a", workspace_id: "workspace-1", provider: "manual", external_id: "dept-a", name: "Department A", status: "active" }],
      members: [], total: 1, member_total: 0,
    });
    const user = userEvent.setup();
    renderDialog();
    await user.click(await screen.findByRole("button", { name: "Access" }));
    await user.click(await screen.findByRole("button", { name: "Already granted 1" }));
    const currentAccess = await screen.findByRole("region", { name: "Current project access" });
    await user.click(within(currentAccess).getByRole("combobox", { name: /Change role for Organization: Department A/ }));
    await user.click(await screen.findByRole("option", { name: "Member" }));

    await waitFor(() => expect(createProjectAccessGrant).toHaveBeenCalledWith("project-1", {
      subject_type: "organization", subject_id: "org-a", role: "member",
    }));
    expect(revokeProjectAccessGrant).toHaveBeenCalledWith("project-1", {
      subject_type: "organization", subject_id: "org-a", role: "viewer", permission: undefined,
    });
    expect(createProjectAccessGrant.mock.invocationCallOrder[0]!).toBeLessThan(revokeProjectAccessGrant.mock.invocationCallOrder[0]!);
  });

  it("allows an everyone grant without selecting a user or department", async () => {
    configStore.getState().setAuthConfig({ allowSignup: true, projectPermissionsEnabled: true });
    const user = userEvent.setup();
    renderDialog();
    await user.click(await screen.findByRole("button", { name: "Access" }));
    const addMembers = screen.getByRole("region", { name: "Grant access" });
    await user.click(within(addMembers).getByRole("checkbox", { name: /Everyone/ }));
    await user.click(screen.getByRole("button", { name: "Grant access" }));

    await waitFor(() => expect(createProjectAccessGrant).toHaveBeenCalledWith("project-1", {
      subject_type: "everyone", subject_id: undefined, role: "member",
    }));
  });

  it("keeps people and departments selected together and lets everyone override without clearing them", async () => {
    configStore.getState().setAuthConfig({ allowSignup: true, projectPermissionsEnabled: true });
    listProjectAuthorizationOrganizations.mockResolvedValue({
      organizations: [{ id: "org-a", workspace_id: "workspace-1", provider: "manual", external_id: "dept-a", name: "Department A", status: "active" }],
      members: [], total: 1, member_total: 0,
    });
    const user = userEvent.setup();
    renderDialog();

    await user.click(await screen.findByRole("button", { name: "Access" }));
    const addMembers = screen.getByRole("region", { name: "Grant access" });
    const peoplePicker = within(addMembers).getByRole("button", { name: "Search by name or email" });
    const organizationPicker = within(addMembers).getByRole("button", { name: "Select organization" });
    await user.click(peoplePicker);
    await user.click(await screen.findByRole("checkbox", { name: "Carol Reviewer" }));
    await user.click(organizationPicker);
    await user.click(await screen.findByRole("checkbox", { name: "Department A" }));

    await user.click(within(addMembers).getByRole("checkbox", { name: /Everyone/ }));
    expect(peoplePicker).toHaveAttribute("aria-disabled", "true");
    expect(organizationPicker).toHaveAttribute("aria-disabled", "true");
    await user.click(screen.getByRole("button", { name: "Grant access" }));

    await waitFor(() => expect(createProjectAccessGrant).toHaveBeenCalledWith("project-1", {
      subject_type: "everyone", subject_id: undefined, role: "member",
    }));
    expect(createProjectAccessGrant).not.toHaveBeenCalledWith("project-1", expect.objectContaining({ subject_type: "user" }));
    expect(createProjectAccessGrant).not.toHaveBeenCalledWith("project-1", expect.objectContaining({ subject_type: "organization" }));
  });
});
