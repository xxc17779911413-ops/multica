"use client";

import type { ReactNode } from "react";
import type {
  Issue,
  IssueTableFacetSpec,
  IssueTableFacetsResponse,
  WorkingAgentSummary,
} from "@multica/core/types";
import { useViewStore } from "@multica/core/issues/stores/view-store-context";
import { PageHeader } from "../../layout/page-header";
import { QuickViewsBar } from "./quick-views-bar";
import { IssuesHeader } from "./issues-header";

/**
 * Shared header for every issue surface (workspace issues, project tasks):
 * quick views with their range picker, the filter/display toolbar, and — when
 * a leading node is supplied — the page title row. Extracted so the project
 * surface cannot drift from the issues page again.
 */
export function IssuesSurfaceHeader({
  leading,
  issues,
  workingAgents,
  facetCountsExact,
  tableFacetCounts,
  onTableFacetChange,
}: {
  /** Page-title row content; omit on surfaces that render their own header. */
  leading?: ReactNode;
  issues: Issue[];
  workingAgents: WorkingAgentSummary[] | undefined;
  facetCountsExact: boolean;
  tableFacetCounts?: IssueTableFacetsResponse;
  onTableFacetChange: (facet: IssueTableFacetSpec | null) => void;
}) {
  const dateFilter = useViewStore((s) => s.dateFilter);
  const setDateFilter = useViewStore((s) => s.setDateFilter);

  return (
    <>
      {leading !== undefined ? <PageHeader>{leading}</PageHeader> : null}
      <QuickViewsBar />
      <IssuesHeader
        scopedIssues={issues}
        workingAgents={workingAgents}
        dateFilter={dateFilter}
        onDateFilterChange={setDateFilter}
        facetCountsExact={facetCountsExact}
        tableFacetCounts={tableFacetCounts}
        onTableFacetChange={onTableFacetChange}
      />
    </>
  );
}
