import { describe, expect, it } from "vitest";

import { projectPermissionCellValue } from "./project-permissions-tab";

describe("projectPermissionCellValue", () => {
  it("does not turn a workspace owner into an implicit project owner", () => {
    expect(projectPermissionCellValue(undefined)).toBe("__no_project_access__");
  });

  it("keeps an explicitly assigned project role", () => {
    expect(projectPermissionCellValue(" owner ")).toBe("owner");
  });

  it("treats empty project roles as no explicit project authorization", () => {
    expect(projectPermissionCellValue("  ")).toBe("__no_project_access__");
  });
});
