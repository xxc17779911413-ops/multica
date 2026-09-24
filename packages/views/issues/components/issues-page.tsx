"use client";

import { ListTodo } from "lucide-react";
import { useIssuesScope } from "@multica/core/issues/stores/issues-scope-store";
import { RefreshablePageIcon } from "../../layout/refreshable-page-icon";
import { useT } from "../../i18n";
import { IssueSurface } from "../surface/issue-surface";
import { IssuesSurfaceHeader } from "./issues-surface-header";

export function IssuesPage() {
  const { t } = useT("issues");
  const scope = useIssuesScope("issues");

  return (
    <div className="flex flex-1 min-h-0 flex-col">
      <IssueSurface
        scope={{ type: "workspace", actorKind: scope }}
        modes={["board", "list", "table", "swimlane"]}
        batchToolbar="list"
        renderHeader={({ controller }) => (
          <IssuesSurfaceHeader
            leading={
              <>
                <RefreshablePageIcon refreshing={controller.isRefreshing}>
                  <ListTodo className="size-4" />
                </RefreshablePageIcon>
                <h1 className="text-body font-medium">{t(($) => $.page.breadcrumb_title)}</h1>
              </>
            }
            issues={controller.surfaceIssues}
            workingAgents={controller.workingAgents}
            facetCountsExact={controller.facetCountsExact}
            tableFacetCounts={controller.tableFacetCounts}
            onTableFacetChange={controller.setActiveTableFacet}
          />
        )}
        renderEmpty={() => (
          <div className="flex flex-1 min-h-0 flex-col items-center justify-center gap-2 text-muted-foreground">
            <ListTodo className="h-10 w-10 text-faint-foreground" />
            <p className="text-body">{t(($) => $.page.empty_title)}</p>
          </div>
        )}
      />
    </div>
  );
}
