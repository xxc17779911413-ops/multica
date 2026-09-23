package projectauth

import (
	"strings"
	"testing"
)

func TestParseOrganizationImportOrganizations(t *testing.T) {
	input := "\ufeff部门ID,部门名称,上级部门ID,状态\ndept-1,研发,,启用\ndept-2,平台,dept-1,active\n"
	preview, err := ParseOrganizationImport(ImportOrganizations, strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseOrganizationImport returned error: %v", err)
	}
	if preview.Rows != 2 || len(preview.Organizations) != 2 || len(preview.Errors) != 0 {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	if preview.Organizations[1].ParentID != "dept-1" || preview.Organizations[0].Status != "active" {
		t.Fatalf("unexpected normalized rows: %+v", preview.Organizations)
	}
}

func TestParseOrganizationImportMembersDepartmentHeader(t *testing.T) {
	input := "user_id,name,email,phone,department_id,status\nuser-1,Alice,alice@example.com,,dept-1,active\n"
	preview, err := ParseOrganizationImport(ImportMembers, strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseOrganizationImport returned error: %v", err)
	}
	if len(preview.Errors) != 0 || len(preview.Members) != 1 {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	member := preview.Members[0]
	if member.ExternalID != "user-1" || member.OrgID != "dept-1" {
		t.Fatalf("unexpected member row: %+v", member)
	}
}

func TestParseOrganizationImportMembers(t *testing.T) {
	input := "人员ID,姓名,邮箱,手机号,部门ID,状态\nuser-1,Alice,alice@example.com,,dept-1,在职\n"
	preview, err := ParseOrganizationImport(ImportMembers, strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseOrganizationImport returned error: %v", err)
	}
	if len(preview.Errors) != 0 || len(preview.Members) != 1 {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	member := preview.Members[0]
	if member.ExternalID != "user-1" || member.OrgID != "dept-1" || member.Status != "active" {
		t.Fatalf("unexpected member row: %+v", member)
	}
}

func TestParseOrganizationImportValidation(t *testing.T) {
	input := "人员ID,姓名,邮箱,手机号,部门ID,状态\nuser-1,Alice,a@example.com, ,dept-1,active\nuser-1,Alice2,a@example.com,,dept-1,active\n"
	preview, err := ParseOrganizationImport(ImportMembers, strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseOrganizationImport returned error: %v", err)
	}
	if len(preview.Errors) != 1 || !strings.Contains(preview.Errors[0], "人员重复") {
		t.Fatalf("expected duplicate error, got: %v", preview.Errors)
	}

	empty, err := ParseOrganizationImport(ImportOrganizations, strings.NewReader(""))
	if err != nil {
		t.Fatalf("empty CSV returned error: %v", err)
	}
	if len(empty.Errors) != 1 || empty.Rows != 0 {
		t.Fatalf("unexpected empty preview: %+v", empty)
	}
}

func TestValidateOrganizationImportRowsRejectsTamperedPayload(t *testing.T) {
	if err := ValidateOrganizationImportRows(ImportOrganizations, []OrganizationImportRow{{ExternalID: "dept-1", Name: "研发", Status: "启用"}}, nil); err == nil {
		t.Fatal("expected non-canonical status to be rejected during confirmation")
	}
	if err := ValidateOrganizationImportRows(ImportOrganizations, nil, []MemberImportRow{{ExternalID: "user-1"}}); err == nil {
		t.Fatal("expected member payload to be rejected for organization import")
	}
	if err := ValidateOrganizationImportRows(ImportMembers, []OrganizationImportRow{{ExternalID: "dept-1", Name: "研发", Status: "active"}}, nil); err == nil {
		t.Fatal("expected organization payload to be rejected for member import")
	}
}

func TestValidateOrganizationImportRowsAcceptsPreviewPayload(t *testing.T) {
	err := ValidateOrganizationImportRows(ImportMembers, nil, []MemberImportRow{{
		ExternalID: "user-1", Name: "Alice", Email: "alice@example.com", OrgID: "dept-1", Status: "active",
	}})
	if err != nil {
		t.Fatalf("preview payload should validate: %v", err)
	}
}
