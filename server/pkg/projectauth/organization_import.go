package projectauth

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// 2026-09-01 coder(lq): ImportKind identifies the provider-neutral directory
// file being imported.
type ImportKind string

const (
	ImportOrganizations ImportKind = "organizations"
	ImportMembers       ImportKind = "members"
)

type OrganizationImportRow struct {
	ExternalID string `json:"external_id"`
	Name       string `json:"name"`
	ParentID   string `json:"parent_external_id,omitempty"`
	Status     string `json:"status"`
}

type MemberImportRow struct {
	ExternalID string `json:"external_id"`
	Name       string `json:"name"`
	Email      string `json:"email,omitempty"`
	Phone      string `json:"phone,omitempty"`
	OrgID      string `json:"organization_external_id"`
	Status     string `json:"status"`
}

type OrganizationImportPreview struct {
	Kind          ImportKind              `json:"kind"`
	Organizations []OrganizationImportRow `json:"organizations,omitempty"`
	Members       []MemberImportRow       `json:"members,omitempty"`
	Errors        []string                `json:"errors"`
	Warnings      []string                `json:"warnings"`
	Rows          int                     `json:"rows"`
}

// 2026-09-01 coder(lq): ValidateOrganizationImportRows validates the JSON
// payload used by the confirm step. The preview endpoint validates CSV input,
// but the browser payload is untrusted and must be checked again before any
// database write, keeping confirmation fail-closed when preview data is
// replayed or modified by a client.
func ValidateOrganizationImportRows(kind ImportKind, organizations []OrganizationImportRow, members []MemberImportRow) error {
	if kind != ImportOrganizations && kind != ImportMembers {
		return fmt.Errorf("unsupported import kind %q", kind)
	}
	if kind == ImportOrganizations {
		if len(members) > 0 {
			return fmt.Errorf("members payload is not allowed for organization import")
		}
		seen := make(map[string]struct{}, len(organizations))
		for i, row := range organizations {
			if strings.TrimSpace(row.ExternalID) == "" || strings.TrimSpace(row.Name) == "" {
				return fmt.Errorf("第 %d 行部门ID和名称不能为空", i+2)
			}
			if strings.TrimSpace(row.Status) != "active" && strings.TrimSpace(row.Status) != "disabled" {
				return fmt.Errorf("第 %d 行状态无效", i+2)
			}
			if _, exists := seen[row.ExternalID]; exists {
				return fmt.Errorf("第 %d 行部门ID重复: %s", i+2, row.ExternalID)
			}
			seen[row.ExternalID] = struct{}{}
		}
		return nil
	}
	if len(organizations) > 0 {
		return fmt.Errorf("organizations payload is not allowed for member import")
	}
	seen := make(map[string]struct{}, len(members))
	for i, row := range members {
		if strings.TrimSpace(row.ExternalID) == "" && strings.TrimSpace(row.Email) == "" {
			return fmt.Errorf("第 %d 行人员ID或邮箱至少填写一个", i+2)
		}
		if strings.TrimSpace(row.Name) == "" || strings.TrimSpace(row.OrgID) == "" {
			return fmt.Errorf("第 %d 行姓名和部门ID不能为空", i+2)
		}
		if strings.TrimSpace(row.Status) != "active" && strings.TrimSpace(row.Status) != "disabled" {
			return fmt.Errorf("第 %d 行状态无效", i+2)
		}
		key := strings.TrimSpace(row.ExternalID) + "\x00" + strings.ToLower(strings.TrimSpace(row.Email))
		if _, exists := seen[key]; exists {
			return fmt.Errorf("第 %d 行人员重复", i+2)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func normalizeImportHeader(value string, kind ImportKind) string {
	value = strings.TrimSpace(strings.TrimPrefix(value, "\ufeff"))
	value = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(value, " ", ""), "_", ""))
	switch value {
	case "部门id", "部门编号", "组织id", "组织编号", "departmentid", "organizationid":
		if kind == ImportMembers {
			return "organization_external_id"
		}
		return "external_id"
	case "部门名称", "组织名称", "departmentname", "organizationname":
		return "name"
	case "上级部门id", "上级组织id", "parentdepartmentid", "parentorganizationid":
		return "parent_external_id"
	case "人员id", "用户id", "员工id", "userid", "employeeid", "useruuid":
		return "external_id"
	case "姓名", "人员姓名", "员工姓名", "用户名", "username":
		return "name"
	case "邮箱", "电子邮箱", "email", "mail":
		return "email"
	case "手机号", "手机", "电话", "phone", "mobile":
		return "phone"
	case "所属部门id", "所属组织id", "所属部门", "所属组织", "部门", "组织", "organization", "department":
		return "organization_external_id"
	case "状态", "status", "启用状态":
		return "status"
	default:
		return value
	}
}

func normalizedHeaders(header []string, kind ImportKind) map[string]int {
	result := make(map[string]int, len(header))
	for i, value := range header {
		result[normalizeImportHeader(value, kind)] = i
	}
	return result
}

func csvValue(record []string, indexes map[string]int, key string) string {
	if i, ok := indexes[key]; ok && i < len(record) {
		return strings.TrimSpace(record[i])
	}
	return ""
}

func normalizeImportStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "active", "启用", "正常", "在职":
		return "active"
	case "disabled", "inactive", "停用", "禁用", "离职":
		return "disabled"
	default:
		return ""
	}
}

// 2026-09-01 coder(lq): ParseOrganizationImport validates a UTF-8 CSV without
// touching persistence and accepts common Chinese and English template headers
// so an operator can prepare the file in either language.
func ParseOrganizationImport(kind ImportKind, input io.Reader) (OrganizationImportPreview, error) {
	preview := OrganizationImportPreview{Kind: kind, Errors: []string{}, Warnings: []string{}}
	if kind != ImportOrganizations && kind != ImportMembers {
		return preview, fmt.Errorf("unsupported import kind %q", kind)
	}
	reader := csv.NewReader(input)
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err == io.EOF {
		preview.Errors = append(preview.Errors, "CSV 文件为空")
		return preview, nil
	}
	if err != nil {
		return preview, fmt.Errorf("read CSV header: %w", err)
	}
	indexes := normalizedHeaders(header, kind)
	required := []string{"external_id", "name", "status"}
	if kind == ImportOrganizations {
		required = append(required, "parent_external_id")
	} else {
		required = append(required, "organization_external_id")
	}
	for _, key := range required {
		if _, ok := indexes[key]; !ok && key != "parent_external_id" {
			preview.Errors = append(preview.Errors, fmt.Sprintf("缺少列: %s", key))
		}
	}
	line := 1
	seen := map[string]struct{}{}
	for {
		record, readErr := reader.Read()
		if readErr == io.EOF {
			break
		}
		line++
		if readErr != nil {
			preview.Errors = append(preview.Errors, fmt.Sprintf("第 %d 行格式错误: %v", line, readErr))
			continue
		}
		if len(record) == 0 || strings.TrimSpace(strings.Join(record, "")) == "" {
			continue
		}
		preview.Rows++
		if kind == ImportOrganizations {
			row := OrganizationImportRow{ExternalID: csvValue(record, indexes, "external_id"), Name: csvValue(record, indexes, "name"), ParentID: csvValue(record, indexes, "parent_external_id"), Status: normalizeImportStatus(csvValue(record, indexes, "status"))}
			if row.ExternalID == "" || row.Name == "" {
				preview.Errors = append(preview.Errors, fmt.Sprintf("第 %d 行部门ID和名称不能为空", line))
				continue
			}
			if row.Status == "" {
				preview.Errors = append(preview.Errors, fmt.Sprintf("第 %d 行状态无效", line))
				continue
			}
			if _, exists := seen[row.ExternalID]; exists {
				preview.Errors = append(preview.Errors, fmt.Sprintf("第 %d 行部门ID重复: %s", line, row.ExternalID))
				continue
			}
			seen[row.ExternalID] = struct{}{}
			preview.Organizations = append(preview.Organizations, row)
		} else {
			row := MemberImportRow{ExternalID: csvValue(record, indexes, "external_id"), Name: csvValue(record, indexes, "name"), Email: csvValue(record, indexes, "email"), Phone: csvValue(record, indexes, "phone"), OrgID: csvValue(record, indexes, "organization_external_id"), Status: normalizeImportStatus(csvValue(record, indexes, "status"))}
			if row.ExternalID == "" && row.Email == "" {
				preview.Errors = append(preview.Errors, fmt.Sprintf("第 %d 行人员ID或邮箱至少填写一个", line))
				continue
			}
			if row.Name == "" || row.OrgID == "" {
				preview.Errors = append(preview.Errors, fmt.Sprintf("第 %d 行姓名和部门ID不能为空", line))
				continue
			}
			if row.Status == "" {
				preview.Errors = append(preview.Errors, fmt.Sprintf("第 %d 行状态无效", line))
				continue
			}
			key := row.ExternalID + "\x00" + strings.ToLower(row.Email)
			if _, exists := seen[key]; exists {
				preview.Errors = append(preview.Errors, fmt.Sprintf("第 %d 行人员重复", line))
				continue
			}
			seen[key] = struct{}{}
			preview.Members = append(preview.Members, row)
		}
	}
	return preview, nil
}
