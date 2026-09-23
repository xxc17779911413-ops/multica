"use client";

import { useEffect } from "react";
import { Activity, Clock, History } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@multica/core/api";
import { useWorkspaceId } from "@multica/core/hooks";
import type { QuickViewKey } from "@multica/core/issues/stores/view-store";
import {
  useViewStore,
  useViewStoreApi,
} from "@multica/core/issues/stores/view-store-context";
import { Button } from "@multica/ui/components/ui/button";
import { cn } from "@multica/ui/lib/utils";
import { useT } from "../../i18n";

const QUICK_VIEWS: {
  key: QuickViewKey;
  labelKey: "quick_recent_created" | "quick_recent_viewed" | "quick_recent_active";
  icon: typeof Clock;
}[] = [
  { key: "recent_created", labelKey: "quick_recent_created", icon: Clock },
  { key: "recent_viewed", labelKey: "quick_recent_viewed", icon: History },
  { key: "recent_active", labelKey: "quick_recent_active", icon: Activity },
];

/**
 * One-click board presets pinned above the issue surface. Activating a preset
 * only seeds the view (layout, grouping, sort, and — for "recently viewed" —
 * the id window bounded by the server-side view history); every filter chip
 * the user adds afterwards layers on top through the ordinary filter bar.
 */
export function QuickViewsBar() {
  const { t } = useT("issues");
  const workspaceId = useWorkspaceId();
  const quickView = useViewStore((s) => s.quickView);
  const viewApi = useViewStoreApi();

  const recents = useQuery({
    queryKey: ["recent-issue-views", workspaceId],
    queryFn: () =>
      api.listRecentIssueViews({ workspace_id: workspaceId, limit: 50 }),
    enabled: quickView === "recent_viewed",
    staleTime: 15_000,
  });

  // The id window is server state; mirror each fetch into the view store so
  // the surface query can consume it.
  useEffect(() => {
    if (quickView !== "recent_viewed" || !recents.data) return;
    viewApi
      .getState()
      .setRecentViewedIds(recents.data.views.map((v) => v.issue_id));
  }, [quickView, recents.data, viewApi]);

  const activate = (key: QuickViewKey) => {
    const act = viewApi.getState();
    if (act.quickView === key) {
      act.setQuickView(null);
      return;
    }
    act.setQuickView(key);
    // Every preset opens as a status board; grouping/sort stay user-editable.
    act.setViewMode("board");
    act.setGrouping("status");
    if (key === "recent_active") {
      act.setSortBy("last_activity");
      act.setSortDirection("desc");
      return;
    }
    act.setSortBy("created_at");
    act.setSortDirection("desc");
    if (key === "recent_viewed") {
      act.setRecentViewedIds(
        recents.data?.views.map((v) => v.issue_id) ?? [],
      );
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-1.5 border-b px-4 py-1.5">
      <span className="mr-1 text-caption text-muted-foreground">
        {t(($) => $.display.quick_views_title)}
      </span>
      {QUICK_VIEWS.map(({ key, labelKey, icon: Icon }) => (
        <Button
          key={key}
          variant={quickView === key ? "secondary" : "ghost"}
          size="sm"
          className={cn(
            "h-6 gap-1.5 px-2 text-caption",
            quickView === key && "ring-1 ring-border",
          )}
          onClick={() => activate(key)}
        >
          <Icon className="size-3.5" />
          {t(($) => $.display[labelKey])}
        </Button>
      ))}
    </div>
  );
}
