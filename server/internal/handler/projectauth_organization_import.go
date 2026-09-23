package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

const organizationImportMaxBytes = 5 << 20

type organizationImportRequest struct {
	Kind          projectauth.ImportKind              `json:"kind"`
	Organizations []projectauth.OrganizationImportRow `json:"organizations"`
	Members       []projectauth.MemberImportRow       `json:"members"`
}

type organizationImportResult struct {
	OrganizationsCreated    int      `json:"organizations_created"`
	OrganizationsUpdated    int      `json:"organizations_updated"`
	MembersCreated          int      `json:"members_created"`
	MembersUpdated          int      `json:"members_updated"`
	Disabled                int      `json:"disabled"`
	Unmatched               []string `json:"unmatched"`
	UsersCreated            int      `json:"users_created"`
	WorkspaceMembersCreated int      `json:"workspace_members_created"`
}

func (h *Handler) ProjectAuthorizationOrganizationTemplate(w http.ResponseWriter, r *http.Request) {
	kind := projectauth.ImportKind(r.URL.Query().Get("kind"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", string(kind)+"-template.csv"))
	writer := csv.NewWriter(w)
	switch kind {
	case projectauth.ImportOrganizations:
		_ = writer.Write([]string{"部门ID", "部门名称", "上级部门ID", "状态"})
		_ = writer.Write([]string{"dept-001", "示例部门", "", "active"})
	case projectauth.ImportMembers:
		_ = writer.Write([]string{"人员ID", "姓名", "邮箱", "手机号", "部门ID", "状态"})
		_ = writer.Write([]string{"用户UUID或外部ID", "张三", "zhangsan@example.com", "", "dept-001", "active"})
	default:
		writeError(w, http.StatusBadRequest, "kind must be organizations or members")
		return
	}
	writer.Flush()
}

func (h *Handler) PreviewProjectAuthorizationOrganizationImport(w http.ResponseWriter, r *http.Request) {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeErrorCode(w, http.StatusNotFound, "project_permission_disabled", "project permissions are disabled")
		return
	}
	kind := projectauth.ImportKind(r.URL.Query().Get("kind"))
	if kind != projectauth.ImportOrganizations && kind != projectauth.ImportMembers {
		writeError(w, http.StatusBadRequest, "kind must be organizations or members")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, organizationImportMaxBytes)
	if err := r.ParseMultipartForm(organizationImportMaxBytes); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart upload")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	file, err := files[0].Open()
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read file")
		return
	}
	defer file.Close()
	preview, err := projectauth.ParseOrganizationImport(kind, file)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (h *Handler) ImportProjectAuthorizationOrganizations(w http.ResponseWriter, r *http.Request) {
	if !h.requireProjectAuthorizationEnabled(w) {
		return
	}
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeErrorCode(w, http.StatusNotFound, "project_permission_disabled", "project permissions are disabled")
		return
	}
	var req organizationImportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, organizationImportMaxBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid import payload")
		return
	}
	if req.Kind != projectauth.ImportOrganizations && req.Kind != projectauth.ImportMembers {
		writeError(w, http.StatusBadRequest, "kind must be organizations or members")
		return
	}
	if err := projectauth.ValidateOrganizationImportRows(req.Kind, req.Organizations, req.Members); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	workspaceID := chi.URLParam(r, "id")
	if workspaceID == "" || h.resolveWorkspaceID(r) != workspaceID {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}
	result := organizationImportResult{Unmatched: []string{}}
	if err := h.withOrganizationImportTransaction(r.Context(), func(tx dbExecutor) error {
		if req.Kind == projectauth.ImportOrganizations {
			return importOrganizations(r.Context(), tx, workspaceID, req.Organizations, &result)
		}
		return importMembers(r.Context(), tx, workspaceID, req.Members, &result)
	}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) withOrganizationImportTransaction(ctx context.Context, fn func(dbExecutor) error) error {
	starter, ok := h.TxStarter.(txStarter)
	if !ok {
		return errors.New("organization import requires transaction starter")
	}
	tx, err := starter.Begin(ctx)
	if err != nil {
		return err
	}
	// 2026-09-01 coder(lq): Rollback is a no-op after Commit and safely cleans
	// up the error path when any row fails.
	defer tx.Rollback(ctx)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func importOrganizations(ctx context.Context, tx dbExecutor, workspaceID string, rows []projectauth.OrganizationImportRow, result *organizationImportResult) error {
	ids := make(map[string]string, len(rows))
	for _, row := range rows {
		var id string
		var existed bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projectauth_organizations WHERE workspace_id=$1 AND provider='custom_upload' AND external_id=$2)`, workspaceID, row.ExternalID).Scan(&existed); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `INSERT INTO projectauth_organizations (workspace_id, provider, external_id, name, status)
			VALUES ($1, 'custom_upload', $2, $3, $4)
			ON CONFLICT (workspace_id, provider, external_id) DO UPDATE SET name=EXCLUDED.name, status=EXCLUDED.status
			RETURNING id::text`, workspaceID, row.ExternalID, row.Name, row.Status).Scan(&id)
		if err != nil {
			return err
		}
		ids[row.ExternalID] = id
		if existed {
			result.OrganizationsUpdated++
		} else {
			result.OrganizationsCreated++
		}
		if row.Status == "disabled" {
			result.Disabled++
		}
	}
	for _, row := range rows {
		if row.ParentID == row.ExternalID {
			return fmt.Errorf("部门不能将自己设为上级部门: %s", row.ExternalID)
		}
		parentID := ""
		if row.ParentID != "" {
			parentID = ids[row.ParentID]
			if parentID == "" {
				// 2026-09-01 coder(lq): A directory may be uploaded in batches;
				// reuse an existing custom-upload department instead of requiring its
				// parent in every subsequent file.
				if err := tx.QueryRow(ctx, `SELECT id::text FROM projectauth_organizations WHERE workspace_id=$1 AND provider='custom_upload' AND external_id=$2 AND status='active'`, workspaceID, row.ParentID).Scan(&parentID); err != nil {
					return fmt.Errorf("上级部门不存在或已停用: %s", row.ParentID)
				}
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE projectauth_organizations SET parent_id=NULLIF($1,'')::uuid, updated_at=now() WHERE workspace_id=$2 AND provider='custom_upload' AND external_id=$3`, parentID, workspaceID, row.ExternalID); err != nil {
			return err
		}
	}
	return nil
}
func importMembers(ctx context.Context, tx dbExecutor, workspaceID string, rows []projectauth.MemberImportRow, result *organizationImportResult) error {
	for _, row := range rows {
		var orgID string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM projectauth_organizations WHERE workspace_id=$1 AND provider='custom_upload' AND external_id=$2 AND status='active'`, workspaceID, row.OrgID).Scan(&orgID); err != nil {
			return fmt.Errorf("人员 %s 的部门不存在或已停用", row.Name)
		}
		var userID string
		err := tx.QueryRow(ctx, `SELECT u.id::text FROM "user" u
			WHERE (($1 <> '' AND u.id::text=$1) OR ($2 <> '' AND lower(u.email)=lower($2))) LIMIT 1`, row.ExternalID, row.Email).Scan(&userID)
		if err != nil {
			// 2026-09-03 coder(lq): A directory upload is authoritative for
			// people as well as departments. Create the local account when this
			// person has not logged in yet, then attach it to the workspace.
			accountEmail := strings.ToLower(strings.TrimSpace(row.Email))
			if accountEmail == "" {
				stable := strings.TrimSpace(row.ExternalID)
				if stable == "" {
					stable = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(row.Name)), " ", "-")
				}
				accountEmail = "directory-" + stable + "@invalid.local"
			}
			name := strings.TrimSpace(row.Name)
			if name == "" {
				name = accountEmail
			}
			if err := tx.QueryRow(ctx, `INSERT INTO "user" (name,email) VALUES ($1,$2) ON CONFLICT (email) DO UPDATE SET email=EXCLUDED.email RETURNING id::text`, name, accountEmail).Scan(&userID); err != nil {
				result.Unmatched = append(result.Unmatched, row.Name)
				continue
			}
			result.UsersCreated++
		}
		if row.Status == "disabled" {
			if _, err := tx.Exec(ctx, `DELETE FROM projectauth_organization_members WHERE workspace_id=$1 AND organization_id=$2::uuid AND user_id=$3::uuid`, workspaceID, orgID, userID); err != nil {
				return err
			}
			result.Disabled++
			continue
		}
		memberInsert, err := tx.Exec(ctx, `INSERT INTO member (workspace_id,user_id,role) VALUES ($1,$2::uuid,'member') ON CONFLICT (workspace_id,user_id) DO NOTHING`, workspaceID, userID)
		if err != nil {
			return err
		}
		if memberInsert.RowsAffected() > 0 {
			result.WorkspaceMembersCreated++
		}
		var existed bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projectauth_organization_members WHERE workspace_id=$1 AND organization_id=$2::uuid AND user_id=$3::uuid)`, workspaceID, orgID, userID).Scan(&existed); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO projectauth_organization_members (organization_id, workspace_id, user_id) VALUES ($1::uuid,$2,$3::uuid) ON CONFLICT (organization_id,user_id) DO NOTHING`, orgID, workspaceID, userID); err != nil {
			return err
		}
		if existed {
			result.MembersUpdated++
		} else {
			result.MembersCreated++
		}
	}
	return nil
}
