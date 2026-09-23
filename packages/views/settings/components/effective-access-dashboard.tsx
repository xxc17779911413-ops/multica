/* eslint-disable i18next/no-literal-string */
"use client";

import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download, ShieldAlert } from "lucide-react";
import { api } from "@multica/core/api";
import { useWorkspaceId } from "@multica/core/hooks";
import type { ProjectPermissionReportRow } from "@multica/core/types";
import { Badge } from "@multica/ui/components/ui/badge";
import { Button } from "@multica/ui/components/ui/button";

type DashboardView = "resource" | "person" | "risk" | "change";
const PAGE_SIZE = 100;

const VIEW_LABELS: Record<DashboardView, string> = {
  resource: "按资源",
  person: "按人员",
  risk: "风险",
  change: "变更",
};

export function permissionRisk(row: ProjectPermissionReportRow, now = Date.now()): "high" | "medium" | "none" {
  if (row.subject_type === "everyone" || row.source === "workspace_role") return "high";
  if (["project.settings.manage", "project.member.manage"].includes(row.permission)) return "high";
  if (row.expires_at) {
    const remaining = Date.parse(row.expires_at) - now;
    if (remaining >= 0 && remaining <= 7 * 24 * 60 * 60 * 1000) return "medium";
  }
  return "none";
}

function csvCell(value: unknown): string {
  let text = value == null ? "" : String(value);
  // Spreadsheet applications interpret these prefixes as formulas. The
  // exported audit report is data, so neutralize them before CSV quoting.
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

export function permissionReportCSV(rows: ProjectPermissionReportRow[]): string {
  const columns: Array<keyof ProjectPermissionReportRow> = [
    "scope", "project_id", "project_title", "issue_id", "issue_title", "user_id", "user_name",
    "user_email", "permission", "role_scope", "project_role", "source", "subject_type", "subject_id",
    "grant_id", "granted_by", "created_at", "expires_at", "source_resource_scope", "source_resource_id",
    "project_access_mode", "policy_version", "inherited_from_project",
  ];
  return [columns.map(csvCell).join(","), ...rows.map((row) => columns.map((column) => csvCell(row[column])).join(","))].join("\n");
}

function downloadCSV(csv: string) {
  const blob = new Blob([`\uFEFF${csv}`], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `effective-access-${new Date().toISOString().slice(0, 10)}.csv`;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function EffectiveAccessDashboard({ projectId, userId }: { projectId?: string; userId?: string }) {
  const workspaceId = useWorkspaceId();
  const [view, setView] = useState<DashboardView>("resource");
  const [page, setPage] = useState(0);
  const [exporting, setExporting] = useState(false);
  const params = {
    project_id: projectId,
    user_id: userId,
    scope: "all" as const,
    limit: 1000,
  };

  useEffect(() => setPage(0), [projectId, userId, view]);

  const report = useQuery({
    queryKey: ["effective-access-report", workspaceId, projectId ?? "all", userId ?? "self"],
    queryFn: () => api.listProjectPermissionReport(params),
    enabled: !!workspaceId,
  });
  const rows = useMemo(() => {
    const values = [...(report.data?.rows ?? [])];
    if (view === "risk") return values.filter((row) => permissionRisk(row) !== "none");
    if (view === "change") return values.filter((row) => row.created_at).sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""));
    return values.sort((a, b) => view === "person"
      ? `${a.user_name}:${a.project_title}:${a.issue_title}`.localeCompare(`${b.user_name}:${b.project_title}:${b.issue_title}`)
      : `${a.project_title}:${a.issue_title}:${a.user_name}`.localeCompare(`${b.project_title}:${b.issue_title}:${b.user_name}`));
  }, [report.data?.rows, view]);
  const visibleRows = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const pageCount = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));

  const exportRows = async () => {
    setExporting(true);
    try {
      // The export flag records an audit event. The server returns the same
      // filtered row contract used by the visible table to prevent drift.
      const result = await api.listProjectPermissionReport({ ...params, export: true });
      downloadCSV(permissionReportCSV(result.rows));
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-body font-medium">有效权限看板</h3>
          <p className="text-caption text-muted-foreground">权限、角色作用域、全部授权来源、有效期与策略版本使用同一报表口径。</p>
        </div>
        <Button variant="outline" size="sm" disabled={exporting || report.isLoading} onClick={() => void exportRows()}>
          <Download aria-hidden="true" />{exporting ? "导出中…" : "导出 CSV"}
        </Button>
      </div>
      <div className="flex flex-wrap gap-2" role="tablist" aria-label="权限看板视图">
        {(Object.keys(VIEW_LABELS) as DashboardView[]).map((key) => (
          <Button key={key} size="sm" variant={view === key ? "default" : "outline"} role="tab" aria-selected={view === key} onClick={() => setView(key)}>
            {key === "risk" && <ShieldAlert aria-hidden="true" />}{VIEW_LABELS[key]}
          </Button>
        ))}
      </div>
      {report.isLoading ? <p className="text-caption text-muted-foreground">加载中…</p>
        : report.isError ? <p className="text-caption text-destructive">无法加载权限看板。</p>
          : rows.length === 0 ? <p className="text-caption text-muted-foreground">没有符合条件的权限记录。</p>
            : (
              <div className="max-h-[55vh] overflow-auto rounded-md border border-surface-border">
                <table className="w-full min-w-[1100px] text-caption">
                  <thead className="sticky top-0 bg-surface">
                    <tr className="text-left text-muted-foreground">
                      <th className="px-3 py-2">资源</th><th className="px-3 py-2">人员</th><th className="px-3 py-2">有效权限</th>
                      <th className="px-3 py-2">角色 / 作用域</th><th className="px-3 py-2">来源资源</th><th className="px-3 py-2">授权来源</th>
                      <th className="px-3 py-2">有效期</th><th className="px-3 py-2">策略</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleRows.map((row, index) => {
                      const risk = permissionRisk(row);
                      return (
                        <tr key={`${row.scope}:${row.project_id}:${row.issue_id}:${row.user_id}:${row.permission}:${row.grant_id}:${index}`} className="border-t border-surface-border/60">
                          <td className="px-3 py-2"><div>{row.issue_title || row.project_title}</div><div className="text-muted-foreground">{row.scope}:{row.issue_id || row.project_id}</div></td>
                          <td className="px-3 py-2"><div>{row.user_name || row.user_email || row.user_id}</div><div className="text-muted-foreground">{row.user_email}</div></td>
                          <td className="px-3 py-2"><Badge variant="secondary">{row.permission}</Badge></td>
                          <td className="px-3 py-2">{row.project_role || "—"} / {row.role_scope || "—"}</td>
                          <td className="px-3 py-2">{row.source_resource_scope || "—"}:{row.source_resource_id || "—"}</td>
                          <td className="px-3 py-2"><div>{row.source}</div><div className="text-muted-foreground">{row.subject_type}:{row.subject_id || "*"}</div>{risk !== "none" && <Badge variant={risk === "high" ? "destructive" : "outline"}>{risk === "high" ? "高风险" : "即将到期"}</Badge>}</td>
                          <td className="px-3 py-2">{row.expires_at ? new Date(row.expires_at).toLocaleString() : "长期"}</td>
                          <td className="px-3 py-2">{row.project_access_mode || "—"} / v{row.policy_version ?? 0}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
      <div className="flex flex-wrap items-center justify-between gap-2 text-caption text-muted-foreground">
        <p>共 {report.data?.total ?? 0} 条；普通成员仅能查看自己的权限，管理者和启用 bypass 的空间 Owner 可查看授权范围内的全量结果。</p>
        {rows.length > PAGE_SIZE && (
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>上一页</Button>
            <span>{page + 1} / {pageCount}</span>
            <Button variant="outline" size="sm" disabled={page + 1 >= pageCount} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>下一页</Button>
          </div>
        )}
      </div>
    </div>
  );
}
