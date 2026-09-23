import { describe, expect, it } from "vitest";
import type { ProjectPermissionReportRow } from "@multica/core/types";
import { permissionReportCSV, permissionRisk } from "./effective-access-dashboard";

function reportRow(overrides: Partial<ProjectPermissionReportRow> = {}): ProjectPermissionReportRow {
  return {
    scope: "issue",
    project_id: "project-1",
    project_title: "Project",
    issue_id: "issue-1",
    issue_title: "Task",
    user_id: "user-1",
    user_name: "Member",
    user_email: "member@example.test",
    workspace_role: "member",
    project_role: "viewer",
    permission: "project.view",
    source: "manual",
    subject_type: "user",
    inherited_from_project: false,
    ...overrides,
  };
}

describe("effective access dashboard", () => {
  it("classifies broad and elevated access as high risk", () => {
    expect(permissionRisk(reportRow({ subject_type: "everyone" }))).toBe("high");
    expect(permissionRisk(reportRow({ permission: "project.settings.manage" }))).toBe("high");
  });

  it("classifies grants expiring within seven days as medium risk", () => {
    const now = Date.parse("2026-09-14T00:00:00Z");
    expect(permissionRisk(reportRow({ expires_at: "2026-09-20T00:00:00Z" }), now)).toBe("medium");
  });

  it("neutralizes spreadsheet formulas in exported CSV", () => {
    const csv = permissionReportCSV([reportRow({ user_name: "=WEBSERVICE(\"https://example.test\")" })]);
    expect(csv).toContain("'=WEBSERVICE");
    expect(csv).not.toContain('\n"=WEBSERVICE');
  });
});
