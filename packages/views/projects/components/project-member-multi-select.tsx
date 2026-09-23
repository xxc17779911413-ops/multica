"use client";

import { useEffect, useMemo, useState } from "react";
import { Check, ChevronDown } from "lucide-react";
import type { MemberWithUser } from "@multica/core/types";
import { Button } from "@multica/ui/components/ui/button";
import { Checkbox } from "@multica/ui/components/ui/checkbox";
import {
  Command,
  CommandEmpty,
  CommandInput,
  CommandItem,
  CommandList,
} from "@multica/ui/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@multica/ui/components/ui/popover";
import { useT } from "../../i18n";
import { compareMemberRegistration } from "../../common/member-sorting";

function memberLabel(member: MemberWithUser | undefined, notRegisteredSuffix: string): string {
  if (!member) return "";
  const name = member.name || member.email;
  return `${name}${member.has_logged_in ? "" : notRegisteredSuffix}`;
}

type ProjectMemberMultiSelectProps = {
  members: MemberWithUser[];
  selectedIds: ReadonlySet<string>;
  onToggle: (userId: string) => void;
  onSelectAll: (userIds: string[]) => void;
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

// 2026-09-04 coder(lq): Keep searchable multi-selection in a small, reusable
// control so project creation and project editing share the same interaction.
export function ProjectMemberMultiSelect({
  members,
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
}: ProjectMemberMultiSelectProps) {
  const { t } = useT("settings");
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");

  useEffect(() => {
    if (!open) setSearch("");
  }, [open]);

  const filteredMembers = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase();
    return [...members]
      .filter((member) => {
        if (!needle) return true;
        return `${member.name} ${member.email}`.toLocaleLowerCase().includes(needle);
      })
      .sort((left, right) =>
        compareMemberRegistration(left, right) || left.name.localeCompare(right.name),
      );
  }, [members, search]);

  const selectedMembers = useMemo(() => {
    const membersById = new Map(members.map((member) => [member.user_id, member]));
    return [...selectedIds].map((id) => ({
      id,
      label: memberLabel(membersById.get(id), t(($) => $.members.not_registered_suffix)) || id,
    }));
  }, [members, selectedIds, t]);
  const allFilteredSelected = filteredMembers.length > 0
    && filteredMembers.every((member) => selectedIds.has(member.user_id));
  const triggerLabel = selectedIds.size === 0 ? placeholder : `${selectedLabel} ${selectedIds.size}`;

  return (
    <Popover
      // 2026-09-04 coder(lq): Keep the multi-select non-modal so the role
      // selector in the surrounding authorization row remains clickable.
      modal={false}
      open={disabled ? false : open}
      onOpenChange={(next) => {
        if (!disabled) setOpen(next);
      }}
    >
      <PopoverTrigger
        nativeButton={false}
        render={
          <div
            role="button"
            tabIndex={disabled ? -1 : 0}
            className="flex min-w-0 flex-1 items-center justify-between gap-2 rounded-lg border border-input bg-transparent px-2.5 py-1.5 text-body outline-none transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 data-[disabled=true]:cursor-not-allowed data-[disabled=true]:bg-muted/40 data-[disabled=true]:text-muted-foreground data-[disabled=true]:hover:bg-muted/40"
            aria-label={ariaLabel || triggerLabel}
            aria-haspopup="listbox"
            aria-expanded={disabled ? false : open}
            aria-disabled={disabled}
            data-disabled={disabled ? "true" : undefined}
          >
            <span className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto whitespace-nowrap">
              {selectedMembers.length === 0 ? <span className="text-muted-foreground">{placeholder}</span> : selectedMembers.map((member) => (
                <span key={member.id} className="inline-flex shrink-0 items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-caption">
                  <span className="max-w-40 truncate">{member.label}</span>
                  {disabled ? null : (
                    <button
                      type="button"
                      className="rounded-full text-muted-foreground hover:text-foreground"
                      aria-label={`${removeLabel} ${member.label}`}
                      onPointerDown={(event) => event.stopPropagation()}
                      onClick={(event) => {
                        event.stopPropagation();
                        onToggle(member.id);
                      }}
                    >
                      ×
                    </button>
                  )}
                </span>
              ))}
              <span className="sr-only">{triggerLabel}</span>
            </span>
            <ChevronDown className="size-4 shrink-0 text-muted-foreground" />
          </div>
        }
      />
      <PopoverContent align="start" className="w-[var(--anchor-width)] min-w-72 p-1">
        <Command shouldFilter={false}>
          <CommandInput
            value={search}
            onValueChange={setSearch}
            placeholder={placeholder}
            aria-label={placeholder}
          />
          <div className="flex items-center justify-between border-b px-2 py-1 text-caption">
            <span className="text-muted-foreground">{selectedLabel} {selectedIds.size}</span>
            <div className="flex items-center gap-1">
              <Button
                type="button"
                variant="ghost"
                size="xs"
                onClick={() => onSelectAll(filteredMembers.map((member) => member.user_id))}
                disabled={allFilteredSelected || filteredMembers.length === 0 || isLoading || hasError}
              >
                {selectAllLabel}
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="xs"
                onClick={onClear}
                disabled={selectedIds.size === 0}
              >
                {clearLabel}
              </Button>
            </div>
          </div>
          <CommandList>
            {isLoading ? <div className="py-6 text-center text-body text-muted-foreground">{loadingLabel}</div> : null}
            {hasError ? <div className="py-6 text-center text-body text-destructive">{errorLabel}</div> : null}
            {!isLoading && !hasError && filteredMembers.length === 0 ? <CommandEmpty>{noResultsLabel}</CommandEmpty> : null}
            {!isLoading && !hasError && filteredMembers.map((member) => {
              const selected = selectedIds.has(member.user_id);
              return (
                <CommandItem
                  key={member.user_id}
                  value={member.user_id}
                  data-checked={selected ? "true" : undefined}
                  aria-selected={selected}
                  onSelect={() => onToggle(member.user_id)}
                >
                  <Checkbox
                    checked={selected}
                    aria-label={memberLabel(member, t(($) => $.members.not_registered_suffix))}
                    onPointerDown={(event) => {
                      event.stopPropagation();
                    }}
                    onCheckedChange={() => {
                      // 2026-09-04 coder(lq): Use Base UI's checkbox event so
                      // controlled selection state updates reliably inside a
                      // cmdk command item.
                      onToggle(member.user_id);
                    }}
                  />
                  <span className="min-w-0 flex-1 truncate">{memberLabel(member, t(($) => $.members.not_registered_suffix))}</span>
                  {member.name && member.email ? <span className="max-w-40 truncate text-caption text-muted-foreground">{member.email}</span> : null}
                  {selected ? <Check className="size-3.5 shrink-0 text-primary" aria-hidden="true" /> : null}
                </CommandItem>
              );
            })}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
