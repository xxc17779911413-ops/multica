"use client";

import { createContext, useContext, type ReactNode } from "react";
import {
  QueryClient,
  QueryClientContext,
  useQuery,
} from "@tanstack/react-query";
import { useWorkspaceSlug } from "@multica/core/paths";
import { api } from "@multica/core/api";
import type { MemberWithUser, Workspace } from "@multica/core/types";

// 2026-09-04 coder(lq): Shared surfaces can render before the platform
// providers are mounted. A stable fallback client keeps the hook callable in
// those embedded contexts without issuing any network requests.
const fallbackQueryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
});

/**
 * Task-surface visibility scope shared by row decorations and the canonical
 * issue queries. Keeping this in the surface layer avoids coupling the core
 * Agent query helpers to a particular page preference.
 *
 * 2026-09-04 coder(lq): Keep the request inclusive after workspace readiness;
 * the backend deployment policy, not a page preference, decides whether a
 * workspace owner may bypass project grants.
 */
interface IssueSurfaceVisibility {
  includeWorkspaceOwned: boolean;
  ready: boolean;
}

const IssueSurfaceVisibilityContext =
  createContext<IssueSurfaceVisibility | null>(null);

export function IssueSurfaceVisibilityProvider({
  includeWorkspaceOwned,
  ready = true,
  children,
}: {
  includeWorkspaceOwned: boolean;
  /** Whether the current user's workspace membership has been resolved. */
  ready?: boolean;
  children: ReactNode;
}) {
  return (
    <IssueSurfaceVisibilityContext.Provider
      value={{ includeWorkspaceOwned, ready }}
    >
      {children}
    </IssueSurfaceVisibilityContext.Provider>
  );
}

export function useIssueSurfaceIncludeWorkspaceOwned(): boolean {
  return useContext(IssueSurfaceVisibilityContext)?.includeWorkspaceOwned ?? true;
}

export function useIssueSurfaceVisibilityReady(): boolean {
  return useContext(IssueSurfaceVisibilityContext)?.ready ?? true;
}

/**
 * Workspace-wide visibility state for surfaces that are not descendants of an
 * IssueSurface provider (Inbox and Chat). These surfaces use the same
 * fail-closed readiness gate; once ready, the backend remains authoritative
 * for workspace-owner visibility.
 */
export function useWorkspaceTaskVisibility(): IssueSurfaceVisibility {
  const context = useContext(IssueSurfaceVisibilityContext);
  const queryClient = useContext(QueryClientContext);
  const effectiveQueryClient = queryClient ?? fallbackQueryClient;
  const slug = useWorkspaceSlug();
  const workspaceQuery = useQuery<Workspace[]>(
    {
      queryKey: ["visibility-workspaces"],
      queryFn: () => api.listWorkspaces(),
      enabled: !!queryClient && !!slug,
    },
    effectiveQueryClient,
  );
  const wsId =
    (workspaceQuery.data ?? []).find((workspace) => workspace.slug === slug)
      ?.id ?? "";
  // 2026-09-01 coder(lq): Desktop chrome mounts before a workspace route is
  // resolved; keep this shared hook fail-closed without calling a workspace
  // endpoint with an empty id.
  const membersQuery = useQuery<MemberWithUser[]>(
    {
      queryKey: ["visibility-members", wsId],
      queryFn: () => api.listMembers(wsId),
      enabled: !!queryClient && !!wsId,
    },
    effectiveQueryClient,
  );
  if (context) return context;
  const ready = !!wsId && membersQuery.isSuccess;
  return {
    ready,
    includeWorkspaceOwned: ready,
  };
}
