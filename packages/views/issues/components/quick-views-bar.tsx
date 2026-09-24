"use client";

import { useEffect, useMemo } from "react";
import {
  Activity,
  CalendarRange,
  Check,
  ChevronDown,
  Clock,
  History,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@multica/core/api";
import { useWorkspaceId } from "@multica/core/hooks";
import {
  quickViewRangeBounds,
  type QuickViewKey,
  type QuickViewRange,
} from "@multica/core/issues/stores/view-store";
import {
  useViewStore,
  useViewStoreApi,
} from "@multica/core/issues/stores/view-store-context";
import { Button } from "@multica/ui/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@multica/ui/components/ui/dropdown-menu";
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

const QUICK_VIEW_RANGES: {
  key: QuickViewRange;
  labelKey:
    | "quick_range_today"
    | "quick_range_yesterday"
    | "quick_range_last3d"
    | "quick_range_this_week"
    | "quick_range_last7d"
    | "quick_range_this_month"
    | "quick_range_last30d";
}[] = [
  { key: "today", labelKey: "quick_range_today" },
  { key: "yesterday", labelKey: "quick_range_yesterday" },
  { key: "last3d", labelKey: "quick_range_last3d" },
  { key: "this_week", labelKey: "quick_range_this_week" },
  { key: "last7d", labelKey: "quick_range_last7d" },
  { key: "this_month", labelKey: "quick_range_this_month" },
  { key: "last30d", labelKey: "quick_range_last30d" },
];

/** Presets that own a visible time window; only they show the range picker. */
const RANGE_VIEWS: QuickViewKey[] = ["recent_created", "recent_active"];

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
  const quickViewRange = useViewStore((s) => s.quickViewRange);
  const setQuickViewRange = useViewStore((s) => s.setQuickViewRange);
  const viewApi = useViewStoreApi();

  const recents = useQuery({
    queryKey: ["recent-issue-views", workspaceId],
    queryFn: () =>
      api.listRecentIssueViews({ workspace_id: workspaceId, limit: 50 }),
    enabled: quickView === "recent_viewed",
    staleTime: 15_000,
  });

  // The id window is server state; mirror each fetch into the view store so
  // the surface query can consume it. The range picker owns what "recent"
  // means here too: only views inside the selected window count.
  const viewedIdsWithinRange = useMemo(() => {
    if (!recents.data) return [];
    const bounds = quickViewRangeBounds(quickViewRange);
    return recents.data.views
      .filter((v) => {
        const t = Date.parse(v.viewed_at);
        return Number.isFinite(t) && t >= bounds.start.getTime() && t < bounds.end.getTime();
      })
      .map((v) => v.issue_id);
  }, [recents.data, quickViewRange]);

  useEffect(() => {
    if (quickView !== "recent_viewed") return;
    viewApi.getState().setRecentViewedIds(viewedIdsWithinRange);
  }, [quickView, viewedIdsWithinRange, viewApi]);

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
      act.setRecentViewedIds(viewedIdsWithinRange);
    }
  };

  const showRangePicker = quickView != null && RANGE_VIEWS.includes(quickView);
  const rangeLabelKey =
    QUICK_VIEW_RANGES.find((range) => range.key === quickViewRange)?.labelKey ??
    "quick_range_today";

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
      {showRangePicker && (
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button
                variant="ghost"
                size="sm"
                aria-label={t(($) => $.display.quick_view_range)}
                className="h-6 gap-1 px-2 text-caption text-muted-foreground"
              >
                <CalendarRange className="size-3.5" />
                {t(($) => $.display[rangeLabelKey])}
                <ChevronDown className="size-3" />
              </Button>
            }
          />
          <DropdownMenuContent>
            {QUICK_VIEW_RANGES.map(({ key, labelKey }) => (
              <DropdownMenuItem key={key} onClick={() => setQuickViewRange(key)}>
                <Check
                  className={cn(
                    "size-3.5",
                    quickViewRange !== key && "opacity-0",
                  )}
                />
                {t(($) => $.display[labelKey])}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      )}
    </div>
  );
}
