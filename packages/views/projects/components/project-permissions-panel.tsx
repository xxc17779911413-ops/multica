"use client";

import { ProjectPermissionsDialog } from "./project-permissions-dialog";

// 2026-08-27 coder(lq): Keep the historical project-detail import stable while
// routing it through the complete project authorization experience. The dialog
// reads can_manage from the server, so workspace admins without project access
// cannot mutate permissions through a stale client-side role check.
export function ProjectPermissionsPanel({ projectId }: { projectId: string }) {
  return <ProjectPermissionsDialog projectId={projectId} />;
}
