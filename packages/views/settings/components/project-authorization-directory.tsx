"use client";

import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Search, Users } from "lucide-react";
import { api } from "@multica/core/api";
import type {
  ProjectAuthorizationOrganization,
  ProjectAuthorizationOrganizationMember,
} from "@multica/core/types";
import { Button } from "@multica/ui/components/ui/button";
import { Input } from "@multica/ui/components/ui/input";
import { cn } from "@multica/ui/lib/utils";
import { useT } from "../../i18n";
import { compareMemberRegistration } from "../../common/member-sorting";
import { SettingsCard, SettingsSection } from "./settings-layout";

const ALL_PEOPLE = "__all_people__";

type OrganizationNode = ProjectAuthorizationOrganization & {
  children: OrganizationNode[];
};

function buildTree(organizations: ProjectAuthorizationOrganization[]): OrganizationNode[] {
  const nodes = new Map<string, OrganizationNode>();
  organizations.forEach((organization) => nodes.set(organization.id, { ...organization, children: [] }));
  const roots: OrganizationNode[] = [];
  nodes.forEach((node) => {
    const parent = node.parent_id ? nodes.get(node.parent_id) : undefined;
    if (parent && parent.id !== node.id) parent.children.push(node);
    else roots.push(node);
  });
  const sortNodes = (items: OrganizationNode[]) => {
    items.sort((left, right) => left.name.localeCompare(right.name));
    items.forEach((item) => sortNodes(item.children));
  };
  sortNodes(roots);
  return roots;
}

function collectDescendantIds(rootId: string, organizations: ProjectAuthorizationOrganization[]): Set<string> {
  const childrenByParent = new Map<string, string[]>();
  organizations.forEach((organization) => {
    if (!organization.parent_id) return;
    const children = childrenByParent.get(organization.parent_id) ?? [];
    children.push(organization.id);
    childrenByParent.set(organization.parent_id, children);
  });
  const result = new Set<string>();
  const pending = [rootId];
  while (pending.length > 0) {
    const id = pending.pop();
    if (!id || result.has(id)) continue;
    result.add(id);
    pending.push(...(childrenByParent.get(id) ?? []));
  }
  return result;
}

// 2026-09-03 coder(lq): Keep directory browsing separate from import controls
// so future OA adapters can reuse the same normalized department tree.
export function ProjectAuthorizationDirectory({
  workspaceId,
  workspaceName,
}: {
  workspaceId: string;
  /** The workspace name is the local, provider-neutral company label. */
  workspaceName?: string | null;
}) {
  const { t } = useT("settings");
  const [selectedId, setSelectedId] = useState(ALL_PEOPLE);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const query = useQuery({
    queryKey: ["project-permission-organizations", workspaceId],
    queryFn: () => api.listProjectAuthorizationOrganizations(workspaceId),
    enabled: !!workspaceId,
    staleTime: 60_000,
  });
  const organizations = query.data?.organizations ?? [];
  const members = query.data?.members ?? [];
  const tree = useMemo(() => buildTree(organizations), [organizations]);

  useEffect(() => {
    if (tree.length === 0) return;
    setExpandedIds((current) => current.size > 0 ? current : new Set(tree.map((node) => node.id)));
  }, [tree]);

  const selectedOrganizationIds = useMemo(
    () => selectedId === ALL_PEOPLE ? null : collectDescendantIds(selectedId, organizations),
    [organizations, selectedId],
  );
  const visibleMembers = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase();
    const byUser = new Map<string, ProjectAuthorizationOrganizationMember>();
    members.forEach((member) => {
      if (selectedOrganizationIds && !selectedOrganizationIds.has(member.organization_id)) return;
      if (needle && !`${member.name} ${member.email}`.toLocaleLowerCase().includes(needle)) return;
      if (!byUser.has(member.user_id)) byUser.set(member.user_id, member);
    });
    return [...byUser.values()].sort((left, right) =>
      compareMemberRegistration(left, right) ||
      (left.name || left.email).localeCompare(right.name || right.email),
    );
  }, [members, search, selectedOrganizationIds]);
  const descendantMemberCounts = useMemo(() => {
    const counts = new Map<string, number>();
    organizations.forEach((organization) => {
      const descendants = collectDescendantIds(organization.id, organizations);
      counts.set(organization.id, new Set(
        members.filter((member) => descendants.has(member.organization_id)).map((member) => member.user_id),
      ).size);
    });
    return counts;
  }, [members, organizations]);
  const uniqueMemberTotal = useMemo(() => new Set(members.map((member) => member.user_id)).size, [members]);
  const directoryRootLabel = workspaceName?.trim() || t(($) => $.project_authorization_organizations.all_people);

  const toggleExpanded = (organizationId: string) => {
    setExpandedIds((current) => {
      const next = new Set(current);
      if (next.has(organizationId)) next.delete(organizationId);
      else next.add(organizationId);
      return next;
    });
  };
  const renderNode = (node: OrganizationNode, depth: number) => {
    const expanded = expandedIds.has(node.id);
    return (
      <div key={node.id}>
        <div
          className={cn(
            "flex min-w-0 items-center rounded-md text-body hover:bg-accent/60",
            selectedId === node.id && "bg-accent",
          )}
          style={{ paddingLeft: `${depth * 16 + 4}px` }}
        >
          {node.children.length > 0 ? (
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              aria-label={expanded ? t(($) => $.project_authorization_organizations.collapse) : t(($) => $.project_authorization_organizations.expand)}
              onClick={() => toggleExpanded(node.id)}
            >
              {expanded ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
            </Button>
          ) : <span className="w-8 shrink-0" />}
          <button type="button" className="flex min-w-0 flex-1 items-center justify-between gap-2 px-1 py-2 text-left" onClick={() => setSelectedId(node.id)}>
            <span className="truncate">{node.name || node.external_id}</span>
            <span className="shrink-0 text-caption text-muted-foreground">{descendantMemberCounts.get(node.id) ?? 0}</span>
          </button>
        </div>
        {expanded ? node.children.map((child) => renderNode(child, depth + 1)) : null}
      </div>
    );
  };

  return (
    <SettingsSection title={t(($) => $.project_authorization_organizations.directory_title)}>
      <SettingsCard>
        {query.isLoading ? (
          <div className="px-4 py-10 text-center text-body text-muted-foreground">{t(($) => $.project_authorization_organizations.directory_loading)}</div>
        ) : query.isError ? (
          <div className="px-4 py-10 text-center text-body text-destructive">{t(($) => $.project_authorization_organizations.directory_failed)}</div>
        ) : organizations.length === 0 && members.length === 0 ? (
          <div className="px-4 py-10 text-center text-body text-muted-foreground">{t(($) => $.project_authorization_organizations.directory_empty)}</div>
        ) : (
          <div className="grid min-h-[36rem] md:grid-cols-[minmax(260px,0.85fr)_minmax(420px,1.15fr)]">
            <aside className="max-h-[36rem] overflow-y-auto border-b border-surface-border p-3 md:border-b-0 md:border-r">
              <button
                type="button"
                className={cn("mb-1 flex w-full items-center justify-between rounded-md px-2 py-2 text-left text-body hover:bg-accent/60", selectedId === ALL_PEOPLE && "bg-accent")}
                onClick={() => setSelectedId(ALL_PEOPLE)}
              >
                <span className="flex min-w-0 items-center gap-2"><Users className="size-4 shrink-0" /><span className="truncate">{directoryRootLabel}</span></span>
                <span className="text-caption text-muted-foreground">{uniqueMemberTotal}</span>
              </button>
              {tree.map((node) => renderNode(node, 0))}
            </aside>
            <div className="min-w-0 p-4">
              <div className="relative mb-3">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder={t(($) => $.project_authorization_organizations.search_people)}
                  aria-label={t(($) => $.project_authorization_organizations.search_people)}
                  className="pl-8"
                />
              </div>
              <div className="mb-2 flex items-center justify-between text-caption text-muted-foreground">
                <span>{selectedId === ALL_PEOPLE ? directoryRootLabel : organizations.find((item) => item.id === selectedId)?.name}</span>
                <span>{t(($) => $.project_authorization_organizations.people_count, { count: visibleMembers.length })}</span>
              </div>
              <div className="max-h-[32rem] space-y-1 overflow-y-auto">
                {visibleMembers.length === 0 ? (
                  <div className="rounded-lg border border-dashed px-4 py-8 text-center text-body text-muted-foreground">{t(($) => $.project_authorization_organizations.no_people)}</div>
                ) : visibleMembers.map((member) => (
                  <div key={member.user_id} className="flex items-center gap-3 rounded-lg px-2 py-2 hover:bg-accent/40">
                    <div className="flex size-8 shrink-0 items-center justify-center rounded-full bg-muted text-caption font-medium">{(member.name || member.email || "?").slice(0, 1).toLocaleUpperCase()}</div>
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-body font-medium">{member.name || member.email}</div>
                      {member.name && member.email ? <div className="truncate text-caption text-muted-foreground">{member.email}</div> : null}
                    </div>
                    <div className="flex shrink-0 items-center gap-2 text-caption text-muted-foreground">
                      <span>{member.workspace_role}</span>
                      <span>{member.has_logged_in ? t(($) => $.project_authorization_organizations.logged_in) : t(($) => $.project_authorization_organizations.not_logged_in)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </SettingsCard>
    </SettingsSection>
  );
}
