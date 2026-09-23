"use client";

import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Check, ChevronDown, ChevronRight } from "lucide-react";
import type { ProjectAuthorizationOrganization } from "@multica/core/types";
import { Button } from "@multica/ui/components/ui/button";
import { Checkbox } from "@multica/ui/components/ui/checkbox";
import { Command, CommandEmpty, CommandInput, CommandItem, CommandList } from "@multica/ui/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@multica/ui/components/ui/popover";

type OrganizationTreeSelectProps = {
  organizations: ProjectAuthorizationOrganization[];
  selectedIds: ReadonlySet<string>;
  onToggle: (organizationId: string) => void;
  onSelectAll: (organizationIds: string[]) => void;
  onClear: () => void;
  placeholder: string;
  selectedLabel: string;
  selectAllLabel: string;
  clearLabel: string;
  noResultsLabel: string;
  loadingLabel: string;
  errorLabel: string;
  removeLabel: string;
  isLoading?: boolean;
  hasError?: boolean;
  disabled?: boolean;
  ariaLabel?: string;
};

type OrganizationNode = ProjectAuthorizationOrganization & { children: OrganizationNode[] };

function buildTree(organizations: ProjectAuthorizationOrganization[]) {
  const byId = new Map<string, OrganizationNode>();
  organizations.forEach((organization) => byId.set(organization.id, { ...organization, children: [] }));
  const roots: OrganizationNode[] = [];
  byId.forEach((node) => {
    const parent = node.parent_id ? byId.get(node.parent_id) : undefined;
    if (parent) parent.children.push(node);
    else roots.push(node);
  });
  const sort = (nodes: OrganizationNode[]) => {
    nodes.sort((left, right) => (left.name || left.external_id).localeCompare(right.name || right.external_id));
    nodes.forEach((node) => sort(node.children));
  };
  sort(roots);
  return roots;
}

function flatten(nodes: OrganizationNode[]): OrganizationNode[] {
  return nodes.flatMap((node) => [node, ...flatten(node.children)]);
}

function matchesSearch(node: OrganizationNode, needle: string): boolean {
  return !needle || `${node.name} ${node.external_id}`.toLocaleLowerCase().includes(needle)
    || node.children.some((child) => matchesSearch(child, needle));
}

export function ProjectPermissionOrganizationTreeSelect({
  organizations,
  selectedIds,
  onToggle,
  onSelectAll,
  onClear,
  placeholder,
  selectedLabel,
  selectAllLabel,
  clearLabel,
  noResultsLabel,
  loadingLabel,
  errorLabel,
  removeLabel,
  isLoading = false,
  hasError = false,
  disabled = false,
  ariaLabel,
}: OrganizationTreeSelectProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const tree = useMemo(() => buildTree(organizations), [organizations]);
  const [expandedIds, setExpandedIds] = useState<ReadonlySet<string>>(new Set());

  useEffect(() => {
    setExpandedIds(new Set(flatten(tree).filter((node) => node.children.length > 0).map((node) => node.id)));
  }, [tree]);
  useEffect(() => {
    if (!open) setSearch("");
  }, [open]);

  const filteredNodes = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase();
    return flatten(tree).filter((node) => matchesSearch(node, needle));
  }, [search, tree]);
  const allFilteredSelected = filteredNodes.length > 0 && filteredNodes.every((node) => selectedIds.has(node.id));
  const selectedOrganizations = useMemo(() => {
    const organizationsById = new Map(organizations.map((organization) => [organization.id, organization]));
    return [...selectedIds].map((id) => ({
      id,
      label: organizationsById.get(id)?.name || organizationsById.get(id)?.external_id || id,
    }));
  }, [organizations, selectedIds]);
  const triggerLabel = selectedIds.size === 0 ? placeholder : `${selectedLabel} ${selectedIds.size}`;

  const toggleExpanded = (organizationId: string) => {
    setExpandedIds((current) => {
      const next = new Set(current);
      if (next.has(organizationId)) next.delete(organizationId);
      else next.add(organizationId);
      return next;
    });
  };

  const renderNode = (node: OrganizationNode, depth = 0): ReactNode => {
    const visible = !search.trim() || matchesSearch(node, search.trim().toLocaleLowerCase());
    if (!visible) return null;
    const expanded = expandedIds.has(node.id) || Boolean(search.trim());
    const selected = selectedIds.has(node.id);
    return (
      <div key={node.id}>
        <CommandItem
          value={`${node.name} ${node.external_id}`}
          className="gap-1"
          style={{ paddingLeft: `${depth * 16 + 8}px` }}
          data-checked={selected ? "true" : undefined}
          aria-selected={selected}
          onSelect={() => onToggle(node.id)}
        >
          {node.children.length > 0 ? <button type="button" className="flex size-5 shrink-0 items-center justify-center rounded hover:bg-muted" aria-label={expanded ? `Collapse ${node.name}` : `Expand ${node.name}`} onPointerDown={(event) => event.preventDefault()} onClick={(event) => { event.stopPropagation(); toggleExpanded(node.id); }}>{expanded ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}</button> : <span className="size-5 shrink-0" />}
          <Checkbox
            checked={selected}
            aria-label={node.name || node.external_id}
            onPointerDown={(event) => {
              event.stopPropagation();
            }}
            onCheckedChange={() => {
              // 2026-09-04 coder(lq): Use Base UI's checkbox event so
              // controlled organization selection updates reliably inside a
              // cmdk command item.
              onToggle(node.id);
            }}
          />
          <span className="min-w-0 flex-1 truncate">{node.name || node.external_id}</span>
          {selected ? <Check className="size-3.5 shrink-0 text-primary" aria-hidden="true" /> : null}
        </CommandItem>
        {expanded ? node.children.map((child) => renderNode(child, depth + 1)) : null}
      </div>
    );
  };

  return (
    <Popover modal={false} open={disabled ? false : open} onOpenChange={(next) => { if (!disabled) setOpen(next); }}>
      <PopoverTrigger nativeButton={false} render={<div role="button" tabIndex={disabled ? -1 : 0} className="flex min-w-0 flex-1 items-center justify-between gap-2 rounded-lg border border-input bg-transparent px-2.5 py-1.5 text-body outline-none transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 data-[disabled=true]:cursor-not-allowed data-[disabled=true]:bg-muted/40 data-[disabled=true]:text-muted-foreground data-[disabled=true]:hover:bg-muted/40" aria-label={ariaLabel || triggerLabel} aria-haspopup="tree" aria-expanded={disabled ? false : open} aria-disabled={disabled} data-disabled={disabled ? "true" : undefined}><span className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto whitespace-nowrap">{selectedOrganizations.length === 0 ? <span className="text-muted-foreground">{placeholder}</span> : selectedOrganizations.map((organization) => <span key={organization.id} className="inline-flex shrink-0 items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-caption"><span className="max-w-40 truncate">{organization.label}</span>{disabled ? null : <button type="button" className="rounded-full text-muted-foreground hover:text-foreground" aria-label={`${removeLabel} ${organization.label}`} onPointerDown={(event) => event.stopPropagation()} onClick={(event) => { event.stopPropagation(); onToggle(organization.id); }}>×</button>}</span>)}<span className="sr-only">{triggerLabel}</span></span><ChevronDown className="size-4 shrink-0 text-muted-foreground" /></div>} />
      <PopoverContent align="start" className="w-[var(--anchor-width)] min-w-72 p-1">
        <Command shouldFilter={false}>
          <CommandInput value={search} onValueChange={setSearch} placeholder={placeholder} aria-label={placeholder} />
          <div className="flex items-center justify-between border-b px-2 py-1 text-caption"><span className="text-muted-foreground">{selectedLabel} {selectedIds.size}</span><div className="flex items-center gap-1"><Button type="button" variant="ghost" size="xs" onClick={() => onSelectAll(filteredNodes.map((node) => node.id))} disabled={allFilteredSelected || filteredNodes.length === 0 || isLoading || hasError}>{selectAllLabel}</Button><Button type="button" variant="ghost" size="xs" onClick={onClear} disabled={selectedIds.size === 0}>{clearLabel}</Button></div></div>
          <CommandList>
            {isLoading ? <div className="py-6 text-center text-body text-muted-foreground">{loadingLabel}</div> : null}
            {hasError ? <div className="py-6 text-center text-body text-destructive">{errorLabel}</div> : null}
            {!isLoading && !hasError && filteredNodes.length === 0 ? <CommandEmpty>{noResultsLabel}</CommandEmpty> : null}
            {!isLoading && !hasError ? tree.map((node) => renderNode(node)) : null}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
