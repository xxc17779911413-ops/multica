"use client";

import { useMemo, useRef, useState } from "react";
import { Download, FileText, Loader2, RefreshCw, Upload } from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@multica/core/api";
import { useAuthStore } from "@multica/core/auth";
import { useWorkspaceId } from "@multica/core/hooks";
import { useCurrentWorkspace } from "@multica/core/paths";
import { memberListOptions } from "@multica/core/workspace/queries";
import type {
  ProjectAuthorizationDingTalkSyncResult,
  ProjectAuthorizationImportKind,
  ProjectAuthorizationImportPreview,
  ProjectAuthorizationImportResult,
} from "@multica/core/types";
import { Button } from "@multica/ui/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@multica/ui/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@multica/ui/components/ui/select";
import { toast } from "sonner";
import { SettingsTab } from "./settings-layout";
import { ProjectAuthorizationDirectory } from "./project-authorization-directory";
import { useT } from "../../i18n";

const IMPORT_KINDS: ProjectAuthorizationImportKind[] = ["organizations", "members"];

// 2026-09-04 coder(lq): Keep directory browsing focused and move maintenance
// workflows into dialogs so the page remains easy to scan as providers grow.
export function ProjectAuthorizationOrganizationsTab() {
  const { t } = useT("settings");
  const workspaceId = useWorkspaceId();
  const workspaceName = useCurrentWorkspace()?.name;
  const currentUser = useAuthStore((state) => state.user);
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [syncDialogOpen, setSyncDialogOpen] = useState(false);
  const [kind, setKind] = useState<ProjectAuthorizationImportKind>("organizations");
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<ProjectAuthorizationImportPreview | null>(null);
  const [importResult, setImportResult] = useState<ProjectAuthorizationImportResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [importing, setImporting] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<ProjectAuthorizationDingTalkSyncResult | null>(null);

  const { data: members = [] } = useQuery({
    ...memberListOptions(workspaceId),
    enabled: !!workspaceId,
  });
  const canManage = useMemo(
    () => members.some((member) => member.user_id === currentUser?.id && ["owner", "admin"].includes(member.role)),
    [currentUser?.id, members],
  );

  const resetImport = (nextKind: ProjectAuthorizationImportKind = kind) => {
    setKind(nextKind);
    setFile(null);
    setPreview(null);
    setImportResult(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const openImportDialog = () => {
    resetImport();
    setImportDialogOpen(true);
  };

  const closeImportDialog = (open: boolean) => {
    setImportDialogOpen(open);
    if (!open) resetImport();
  };

  const closeSyncDialog = (open: boolean) => {
    setSyncDialogOpen(open);
    if (!open) setSyncResult(null);
  };

  const downloadTemplate = async () => {
    try {
      const blob = await api.downloadProjectAuthorizationOrganizationTemplate(workspaceId, kind);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${kind}-template.csv`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t(($) => $.project_authorization_organizations.download_failed));
    }
  };

  const previewFile = async () => {
    if (!file) {
      toast.error(t(($) => $.project_authorization_organizations.no_file));
      return;
    }
    setLoading(true);
    try {
      const result = await api.previewProjectAuthorizationOrganizationImport(workspaceId, kind, file);
      setPreview(result);
      setImportResult(null);
    } catch (error) {
      setPreview(null);
      toast.error(error instanceof Error ? error.message : t(($) => $.project_authorization_organizations.import_failed));
    } finally {
      setLoading(false);
    }
  };

  const confirmImport = async () => {
    if (!preview || preview.errors.length > 0) return;
    setImporting(true);
    try {
      const result = await api.importProjectAuthorizationOrganizations(workspaceId, {
        kind,
        organizations: preview.organizations,
        members: preview.members,
      });
      setImportResult(result);
      await queryClient.invalidateQueries({ queryKey: ["project-permission-organizations", workspaceId] });
      toast.success(t(($) => $.project_authorization_organizations.import_success));
      setFile(null);
      setPreview(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t(($) => $.project_authorization_organizations.import_failed));
    } finally {
      setImporting(false);
    }
  };

  const syncDingTalk = async () => {
    setSyncing(true);
    try {
      const result = await api.syncProjectAuthorizationDingTalk(workspaceId);
      setSyncResult(result);
      await queryClient.invalidateQueries({ queryKey: ["project-permission-organizations", workspaceId] });
      toast.success(t(($) => $.project_authorization_organizations.sync_success));
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t(($) => $.project_authorization_organizations.sync_failed));
    } finally {
      setSyncing(false);
    }
  };

  const previewRows = kind === "organizations" ? preview?.organizations ?? [] : preview?.members ?? [];

  return (
    <>
      <SettingsTab
        title={t(($) => $.project_authorization_organizations.title)}
        description={t(($) => $.project_authorization_organizations.description)}
        action={
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="outline" onClick={openImportDialog} disabled={!canManage}>
              <Upload className="mr-1 size-4" />
              {t(($) => $.project_authorization_organizations.file_import)}
            </Button>
            <Button variant="outline" onClick={() => setSyncDialogOpen(true)} disabled={!canManage}>
              <RefreshCw className="mr-1 size-4" />
              {t(($) => $.project_authorization_organizations.sync_dingtalk_button)}
            </Button>
          </div>
        }
      >
        <ProjectAuthorizationDirectory workspaceId={workspaceId} workspaceName={workspaceName} />
        {!canManage ? <p className="text-caption text-muted-foreground">{t(($) => $.project_authorization_organizations.admin_only)}</p> : null}
      </SettingsTab>

      <Dialog open={importDialogOpen} onOpenChange={closeImportDialog}>
        <DialogContent className="max-h-[min(90vh,52rem)] overflow-y-auto sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>{t(($) => $.project_authorization_organizations.file_import_title)}</DialogTitle>
            <DialogDescription>{t(($) => $.project_authorization_organizations.file_import_description)}</DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <div className="min-w-48 flex-1 space-y-1">
                <label className="text-caption font-medium" htmlFor="projectauth-import-kind">
                  {t(($) => $.project_authorization_organizations.kind)}
                </label>
                <Select
                  items={IMPORT_KINDS.map((value) => ({
                    value,
                    label: t(($) => $.project_authorization_organizations[value]),
                  }))}
                  value={kind}
                  onValueChange={(value) => value && resetImport(value as ProjectAuthorizationImportKind)}
                >
                  <SelectTrigger id="projectauth-import-kind" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {IMPORT_KINDS.map((value) => (
                      <SelectItem key={value} value={value}>{t(($) => $.project_authorization_organizations[value])}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <Button variant="outline" onClick={() => void downloadTemplate()}>
                <Download className="mr-1 size-4" />
                {t(($) => $.project_authorization_organizations.download_template)}
              </Button>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <input
                ref={fileInputRef}
                type="file"
                accept=".csv,text/csv"
                className="sr-only"
                id="projectauth-import-file"
                onChange={(event) => {
                  setFile(event.target.files?.[0] ?? null);
                  setPreview(null);
                  setImportResult(null);
                }}
              />
              <Button variant="outline" onClick={() => fileInputRef.current?.click()}>
                <FileText className="mr-1 size-4" />
                {t(($) => $.project_authorization_organizations.upload_file)}
              </Button>
              {file ? <span className="inline-flex min-w-0 items-center gap-1 text-caption text-muted-foreground"><FileText className="size-4 shrink-0" /><span className="truncate">{file.name}</span></span> : null}
              <Button onClick={() => void previewFile()} disabled={!file || loading}>
                {loading ? <Loader2 className="mr-1 size-4 animate-spin" /> : null}
                {t(($) => $.project_authorization_organizations.preview)}
              </Button>
            </div>

            {preview ? (
              <div className="overflow-hidden rounded-lg border border-surface-border">
                <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-caption">
                  <span>{t(($) => $.project_authorization_organizations.rows, { count: preview.rows })}</span>
                  <span className={preview.errors.length ? "text-destructive" : "text-muted-foreground"}>{t(($) => $.project_authorization_organizations.errors, { count: preview.errors.length })}</span>
                  <span className="text-muted-foreground">{t(($) => $.project_authorization_organizations.warnings, { count: preview.warnings.length })}</span>
                  <Button onClick={() => void confirmImport()} disabled={preview.errors.length > 0 || importing}>
                    {importing ? <Loader2 className="mr-1 size-4 animate-spin" /> : null}
                    {t(($) => $.project_authorization_organizations.confirm_import)}
                  </Button>
                </div>
                {preview.errors.length ? <div className="space-y-1 border-t border-surface-border px-4 py-3 text-caption text-destructive">{preview.errors.map((error) => <p key={error}>{error}</p>)}</div> : null}
                {preview.warnings.length ? <div className="space-y-1 border-t border-surface-border px-4 py-3 text-caption text-muted-foreground">{preview.warnings.map((warning) => <p key={warning}>{warning}</p>)}</div> : null}
                {previewRows.length ? (
                  <div className="max-h-80 overflow-auto border-t border-surface-border">
                    <table className="w-full text-caption">
                      <thead><tr className="text-left text-muted-foreground">{Object.keys(previewRows[0] ?? {}).map((key) => <th key={key} className="whitespace-nowrap px-4 py-2 font-medium">{key}</th>)}</tr></thead>
                      <tbody>{previewRows.slice(0, 100).map((row, index) => <tr key={index} className="border-t border-surface-border">{Object.values(row).map((value, valueIndex) => <td key={valueIndex} className="whitespace-nowrap px-4 py-2">{value || "—"}</td>)}</tr>)}</tbody>
                    </table>
                  </div>
                ) : <p className="border-t border-surface-border px-4 py-5 text-caption text-muted-foreground">{t(($) => $.project_authorization_organizations.empty)}</p>}
              </div>
            ) : null}

            {importResult ? (
              <div className="rounded-lg border border-surface-border">
                <div className="px-4 py-3 text-body font-medium">{t(($) => $.project_authorization_organizations.result_title)}</div>
                <div className="grid gap-3 border-t border-surface-border px-4 py-4 text-caption sm:grid-cols-3">
                  <span>{t(($) => $.project_authorization_organizations.created, { count: kind === "organizations" ? importResult.organizations_created : importResult.members_created })}</span>
                  <span>{t(($) => $.project_authorization_organizations.updated, { count: kind === "organizations" ? importResult.organizations_updated : importResult.members_updated })}</span>
                  <span>{t(($) => $.project_authorization_organizations.disabled, { count: importResult.disabled })}</span>
                  {kind === "members" ? <>
                    <span>{t(($) => $.project_authorization_organizations.sync_users_created, { count: importResult.users_created })}</span>
                    <span>{t(($) => $.project_authorization_organizations.sync_workspace_members, { count: importResult.workspace_members_created })}</span>
                  </> : null}
                </div>
                {importResult.unmatched.length ? <div className="border-t border-surface-border px-4 py-3 text-caption text-muted-foreground"><p className="font-medium">{t(($) => $.project_authorization_organizations.unmatched, { count: importResult.unmatched.length })}</p><p className="mt-1 break-words">{importResult.unmatched.join("、")}</p></div> : null}
              </div>
            ) : null}
          </div>

          <DialogFooter>
            <DialogClose render={<Button variant="outline" />}>{t(($) => $.project_authorization_organizations.close)}</DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={syncDialogOpen} onOpenChange={closeSyncDialog}>
        <DialogContent className="max-h-[min(90vh,52rem)] overflow-y-auto sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>{t(($) => $.project_authorization_organizations.sync_dingtalk_title)}</DialogTitle>
            <DialogDescription>{t(($) => $.project_authorization_organizations.sync_dingtalk_description)}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <Button className="w-full sm:w-auto" onClick={() => void syncDingTalk()} disabled={syncing}>
              {syncing ? <Loader2 className="mr-1 size-4 animate-spin" /> : <RefreshCw className="mr-1 size-4" />}
              {t(($) => $.project_authorization_organizations.sync_dingtalk)}
            </Button>
            {syncResult ? (
              <div className="rounded-lg border border-surface-border">
                <div className="px-4 py-3 text-body font-medium">{t(($) => $.project_authorization_organizations.sync_result_title)}</div>
                <div className="grid gap-3 border-t border-surface-border px-4 py-4 text-caption sm:grid-cols-2">
                  <span>{t(($) => $.project_authorization_organizations.sync_created, { count: syncResult.organizations_created })}</span>
                  <span>{t(($) => $.project_authorization_organizations.sync_updated, { count: syncResult.organizations_updated })}</span>
                  <span>{t(($) => $.project_authorization_organizations.sync_disabled, { count: syncResult.organizations_disabled })}</span>
                  <span>{t(($) => $.project_authorization_organizations.sync_members, { count: syncResult.members_created })}</span>
                  <span>{t(($) => $.project_authorization_organizations.sync_removed, { count: syncResult.members_removed })}</span>
                  <span>{t(($) => $.project_authorization_organizations.sync_users_created, { count: syncResult.users_created })}</span>
                  <span>{t(($) => $.project_authorization_organizations.sync_users_matched, { count: syncResult.users_matched })}</span>
                  <span>{t(($) => $.project_authorization_organizations.sync_workspace_members, { count: syncResult.workspace_members_created })}</span>
                </div>
                {syncResult.unmatched.length ? <p className="border-t border-surface-border px-4 py-3 text-caption text-muted-foreground break-words">{syncResult.unmatched.join("、")}</p> : null}
              </div>
            ) : null}
          </div>
          <DialogFooter>
            <DialogClose render={<Button variant="outline" />}>{t(($) => $.project_authorization_organizations.close)}</DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
