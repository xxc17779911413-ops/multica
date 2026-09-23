import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { configStore } from "@multica/core/config";
import { I18nProvider } from "@multica/core/i18n/react";
import enCommon from "../../locales/en/common.json";
import enSettings from "../../locales/en/settings.json";

type WorkspaceRole = "owner" | "admin" | "member";

const access = vi.hoisted(() => ({ role: "owner" as WorkspaceRole }));
const mockInvalidateQueries = vi.hoisted(() => vi.fn());

vi.mock("@tanstack/react-query", () => ({
  useQuery: (options: { queryKey?: readonly unknown[] }) =>
    options.queryKey?.[0] === "project-permission-roles"
      ? { data: { roles: [] }, isLoading: false }
      : { data: [{ user_id: "user-1", role: access.role }], isLoading: false },
  useQueryClient: () => ({ invalidateQueries: mockInvalidateQueries }),
}));

vi.mock("@multica/core/hooks", () => ({
  useWorkspaceId: () => "workspace-1",
}));

vi.mock("@multica/core/workspace/queries", () => ({
  memberListOptions: () => ({ queryKey: ["members"], queryFn: vi.fn() }),
  workspaceListOptions: () => ({ queryKey: ["workspaces"], queryFn: vi.fn() }),
  workspaceKeys: { list: () => ["workspaces"] },
}));

vi.mock("@multica/core/paths", () => ({
  useCurrentWorkspace: () => ({
    id: "workspace-1",
    slug: "workspace-1",
    name: "Test workspace",
    settings: {},
  }),
}));

vi.mock("@multica/core/auth", () => ({
  useAuthStore: (selector: (state: { user: { id: string } }) => unknown) =>
    selector({ user: { id: "user-1" } }),
}));

vi.mock("@multica/core/api", () => ({
  api: {
    listProjectPermissionRoles: vi.fn(),
    createProjectPermissionRole: vi.fn(),
    updateProjectPermissionRole: vi.fn(),
    deleteProjectPermissionRole: vi.fn(),
    updateWorkspace: vi.fn(),
  },
}));

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { ProjectPermissionRolesTab } from "./project-permission-roles-tab";

const TEST_RESOURCES = { en: { common: enCommon, settings: enSettings } };

function Wrapper({ children }: { children: ReactNode }) {
  return <I18nProvider locale="en" resources={TEST_RESOURCES}>{children}</I18nProvider>;
}

describe("ProjectPermissionRolesTab", () => {
  beforeEach(() => {
    access.role = "owner";
    vi.clearAllMocks();
    configStore.getState().setAuthConfig({
      allowSignup: true,
      projectPermissionsEnabled: true,
      projectPermissionRolloutPhase: "restricted",
    });
  });

  it("shows role management controls to the workspace owner", () => {
    render(<ProjectPermissionRolesTab />, { wrapper: Wrapper });

    expect(screen.getByRole("button", { name: "Add role" })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Edit" })).toHaveLength(4);
  });

  it.each(["admin", "member"] as const)(
    "keeps the role catalog read-only for a workspace %s",
    (role) => {
      access.role = role;
      render(<ProjectPermissionRolesTab />, { wrapper: Wrapper });

      expect(screen.getByText("Owner")).toBeInTheDocument();
      expect(screen.getByText("Manager")).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Add role" })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Delete role" })).not.toBeInTheDocument();
    },
  );

  it("allows the workspace owner to manage roles in any active rollout phase", () => {
    configStore.getState().setAuthConfig({
      allowSignup: true,
      projectPermissionsEnabled: true,
      projectPermissionRolloutPhase: "reader",
    });

    render(<ProjectPermissionRolesTab />, { wrapper: Wrapper });

    expect(screen.getByText("Owner")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add role" })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Edit" })).toHaveLength(4);
  });
});
