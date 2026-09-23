import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  useQuery: vi.fn(),
  getIssueAccessRequestTarget: vi.fn(),
}));

vi.mock("@tanstack/react-query", () => ({
  useQuery: mocks.useQuery,
}));
vi.mock("@multica/core/api", () => ({
  api: {
    listTaskPermissionRoles: vi.fn(),
    listIssueAccessRequests: vi.fn(),
    createIssueAccessRequest: vi.fn(),
    cancelIssueAccessRequest: vi.fn(),
    getIssueAccessRequestTarget: mocks.getIssueAccessRequestTarget,
  },
  // Mirrors the real client: only `status` participates in the 404 branch.
  ApiError: class ApiError extends Error {
    status: number;
    constructor(message: string, status: number) {
      super(message);
      this.name = "ApiError";
      this.status = status;
    }
  },
}));
vi.mock("@multica/core/config", () => ({
  useConfigStore: () => true,
}));
vi.mock("@multica/core/hooks", () => ({ useWorkspaceId: () => "workspace-1" }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("../../i18n", async () => {
  const issues = (await import("../../locales/en/issues.json")).default;
  return {
    useT: () => ({ t: (select: (bundle: typeof issues) => string) => select(issues) }),
  };
});

import { ApiError } from "@multica/core/api";
import { RestrictedIssueAccess, RestrictedIssueAccessFallback } from "./restricted-issue-access";

describe("RestrictedIssueAccess", () => {
  beforeEach(() => {
    mocks.useQuery.mockReset();
    mocks.getIssueAccessRequestTarget.mockReset();
  });

  it("isolates role and request caches by workspace", () => {
    mocks.useQuery
      .mockReturnValueOnce({ data: { scope: "task", roles: [] } })
      .mockReturnValueOnce({
        data: { items: [{ id: "request-1", requested_role: "viewer", status: "pending" }] },
        refetch: vi.fn(),
      });

    render(<RestrictedIssueAccess issueId="issue-1" identifier="LC-797" />);

    expect(screen.getByText("LC-797")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "You don't have access" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Request access" })).toBeInTheDocument();
    expect(screen.getByText("Can view · Pending approval")).toBeInTheDocument();
    expect(screen.queryByText(/task:viewer|pending/)).not.toBeInTheDocument();
    expect(mocks.useQuery).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        queryKey: ["task-permission-roles", "workspace-1", "restricted"],
      }),
    );
    expect(mocks.useQuery).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        queryKey: ["issue-access-requests", "workspace-1", "issue-1", "mine"],
      }),
    );
  });
});

// The shared fallback is what keeps a denial from being reported as a deletion —
// in the issue route and in the inbox alike.
describe("RestrictedIssueAccessFallback", () => {
  beforeEach(() => {
    mocks.useQuery.mockReset();
    mocks.getIssueAccessRequestTarget.mockReset();
  });

  it("resolves the reference and hands the canonical pair to the restricted page", () => {
    mocks.useQuery.mockImplementation((options: { queryKey: readonly unknown[] }) => {
      const [key] = options.queryKey;
      if (key === "issue-access-request-target") {
        return { isLoading: false, data: { id: "issue-1", identifier: "LC-797" } };
      }
      if (key === "task-permission-roles") return { data: { scope: "task", roles: [] } };
      return { data: { items: [] }, refetch: vi.fn() };
    });

    render(
      <RestrictedIssueAccessFallback
        targetId="issue-1"
        notFound={<p>Task deleted</p>}
        leading={<button type="button">Back</button>}
      />,
    );

    expect(screen.getByText("LC-797")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Back" })).toBeInTheDocument();
    expect(screen.queryByText("Task deleted")).not.toBeInTheDocument();
    expect(mocks.useQuery).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        queryKey: ["issue-access-request-target", "workspace-1", "issue-1"],
        // One denial must not turn into a retry loop while the host keeps rendering.
        retry: false,
      }),
    );
  });

  it("reports the task as gone only when the probe answers 404", () => {
    mocks.useQuery.mockReturnValue({
      isLoading: false,
      isError: true,
      error: new ApiError("not found", 404, "Not Found"),
    });

    render(<RestrictedIssueAccessFallback targetId="issue-1" notFound={<p>Task deleted</p>} />);

    expect(screen.getByText("Task deleted")).toBeInTheDocument();
  });

  it("never reports a failed access check as a deleted task", () => {
    mocks.useQuery.mockReturnValue({
      isLoading: false,
      isError: true,
      error: new ApiError("unavailable", 503, "Service Unavailable"),
      refetch: vi.fn(),
    });

    render(<RestrictedIssueAccessFallback targetId="issue-1" notFound={<p>Task deleted</p>} />);

    expect(screen.getByText("Could not check task access.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    expect(screen.queryByText("Task deleted")).not.toBeInTheDocument();
  });

  it("holds the host's loading frame until the reference resolves", () => {
    mocks.useQuery.mockReturnValue({ isLoading: true });

    render(
      <RestrictedIssueAccessFallback
        targetId="issue-1"
        loading={<p>Loading task</p>}
        notFound={<p>Task deleted</p>}
      />,
    );

    expect(screen.getByText("Loading task")).toBeInTheDocument();
    expect(screen.queryByText("Task deleted")).not.toBeInTheDocument();
  });
});
