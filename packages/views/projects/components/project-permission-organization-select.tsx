"use client";

import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Check, ChevronRight, Search } from "lucide-react";
import { api } from "@multica/core/api";
import type { ProjectAuthorizationOrganization } from "@multica/core/types";
import { Popover, PopoverContent, PopoverTrigger } from "@multica/ui/components/ui/popover";

type OrganizationSelectProps = {
  workspaceId: string;
  open: boolean;
  value: string[];
  onValueChange: (value: string[]) => void;
  ariaLabel: string;
  placeholder: string;
  emptyLabel: string;
};

export function ProjectPermissionOrganizationSelect({
  workspaceId,
  open,
  value,
  onValueChange,
  ariaLabel,
  placeholder,
  emptyLabel,
}: OrganizationSelectProps) {
  const query = useQuery({
    queryKey: ["project-permission-organizations", workspaceId],
    queryFn: () => api.listProjectAuthorizationOrganizations(workspaceId),
    enabled: open && !!workspaceId,
    staleTime: 60_000,
  });
  const organizations = query.data?.organizations ?? [];
  const [treeOpen, setTreeOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const selected = organizations.filter((organization) => value.includes(organization.id));
  const childrenByParent = useMemo(() => {
    const result = new Map<string | undefined, ProjectAuthorizationOrganization[]>();
    for (const organization of organizations) {
      const children = result.get(organization.parent_id) ?? [];
      children.push(organization);
      result.set(organization.parent_id, children);
    }
    return result;
  }, [organizations]);
  const visibleTree = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase();
    const matches = (organization: ProjectAuthorizationOrganization) => !needle
      || `${organization.name} ${organization.external_id} ${organization.provider}`.toLocaleLowerCase().includes(needle);
    const rows: Array<{ organization: ProjectAuthorizationOrganization; depth: number }> = [];
    const walk = (parentId: string | undefined, depth: number) => {
      for (const organization of (childrenByParent.get(parentId) ?? []).sort((a, b) => (a.name || a.external_id).localeCompare(b.name || b.external_id))) {
        const children = childrenByParent.get(organization.id) ?? [];
        const descendantMatches = children.some((child) => matches(child) || (childrenByParent.get(child.id) ?? []).some(matches));
        if (matches(organization) || descendantMatches || !needle) rows.push({ organization, depth });
        if (children.length > 0 && (needle || expanded.has(organization.id))) walk(organization.id, depth + 1);
      }
    };
    walk(undefined, 0);
    return rows;
  }, [childrenByParent, expanded, search]);

  if (!query.isLoading && organizations.length === 0) {
    return <div className="rounded-md border px-3 py-2 text-caption text-muted-foreground">{emptyLabel}</div>;
  }

  return (
    <Popover open={treeOpen} onOpenChange={(next) => { setTreeOpen(next); if (!next) setSearch(""); }}>
      <PopoverTrigger nativeButton aria-label={ariaLabel} className="flex h-9 w-full items-center justify-between rounded-md border px-3 text-body hover:bg-muted/40">
        <span className={selected.length > 0 ? "truncate" : "truncate text-muted-foreground"}>{query.isLoading ? "…" : selected.length > 0 ? selected.map((organization) => organization.name || organization.external_id).join(", ") : placeholder}</span>
        <ChevronRight className="size-4 rotate-90 text-muted-foreground" />
      </PopoverTrigger>
      <PopoverContent align="start" className="w-[min(28rem,calc(100vw-2rem))] p-2">
        <div className="flex items-center gap-2 rounded-md border px-2">
          <Search className="size-4 text-muted-foreground" />
          <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder={placeholder} className="h-9 min-w-0 flex-1 bg-transparent text-body outline-none" />
        </div>
        <div className="mt-2 max-h-64 overflow-y-auto">
          {visibleTree.length === 0 ? <div className="px-2 py-6 text-center text-caption text-muted-foreground">{emptyLabel}</div> : visibleTree.map(({ organization, depth }) => {
            const hasChildren = (childrenByParent.get(organization.id) ?? []).length > 0;
            const isExpanded = expanded.has(organization.id) || !!search;
            return <div key={organization.id} className="flex items-center gap-1 rounded-md px-1 py-1 hover:bg-muted/50" style={{ paddingLeft: `${depth * 18 + 4}px` }}>
              <button type="button" aria-label={isExpanded ? "Collapse" : "Expand"} className="flex size-5 items-center justify-center" disabled={!hasChildren} onClick={() => setExpanded((current) => { const next = new Set(current); if (next.has(organization.id)) next.delete(organization.id); else next.add(organization.id); return next; })}>{hasChildren && <ChevronRight className={`size-3.5 transition-transform ${isExpanded ? "rotate-90" : ""}`} />}</button>
              <button type="button" className="flex min-w-0 flex-1 items-center gap-2 text-left text-body" onClick={() => { onValueChange(value.includes(organization.id) ? value.filter((id) => id !== organization.id) : [...value, organization.id]); }}>
                <span className="truncate">{organization.name || organization.external_id}</span>
                {value.includes(organization.id) && <Check className="ml-auto size-4" />}
              </button>
            </div>;
          })}
        </div>
      </PopoverContent>
    </Popover>
  );
}
