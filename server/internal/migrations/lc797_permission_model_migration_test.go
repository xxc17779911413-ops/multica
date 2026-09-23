package migrations

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var lc797MigrationStems = []string{
	"509_projectauth_issue_policies",
	"510_projectauth_issue_policies_unique",
	"511_projectauth_grant_constraints",
	"512_projectauth_grant_constraints_unique",
	"513_projectauth_grant_constraints_expiry_index",
	"514_projectauth_access_requests",
	"515_projectauth_access_requests_id_unique",
	"516_projectauth_access_requests_pending_resource_index",
	"517_projectauth_access_requests_principal_index",
	"518_projectauth_access_requests_idempotency_unique",
	"519_projectauth_task_roles",
	"520_projectauth_task_roles_unique",
	"521_projectauth_task_role_permissions",
	"522_projectauth_task_role_permissions_unique",
	"523_projectauth_task_system_roles_seed",
}

func TestLC797PermissionModelMigrationsRespectPrivateSchemaContract(t *testing.T) {
	tableMigrations := map[string][]string{
		"509_projectauth_issue_policies.up.sql": {
			"CREATE TABLE", "projectauth_issue_policies", "project_access_mode", "policy_version",
		},
		"511_projectauth_grant_constraints.up.sql": {
			"CREATE TABLE", "projectauth_grant_constraints", "grant_id", "expires_at", "origin_kind", "origin_id",
		},
		"514_projectauth_access_requests.up.sql": {
			"CREATE TABLE", "projectauth_access_requests", "requester_user_id", "requested_role_key", "status", "idempotency_key",
		},
		"519_projectauth_task_roles.up.sql": {
			"CREATE TABLE", "projectauth_task_roles", "workspace_id", "role_key", "is_system",
		},
		"521_projectauth_task_role_permissions.up.sql": {
			"CREATE TABLE", "projectauth_task_role_permissions", "role_id", "permission",
		},
	}

	for migration, required := range tableMigrations {
		t.Run(migration, func(t *testing.T) {
			sql := readMigrationFile(t, migration)
			upper := strings.ToUpper(sql)
			if strings.Contains(upper, "REFERENCES ") || strings.Contains(upper, " CASCADE") {
				t.Fatalf("%s must not add foreign keys or cascades", migration)
			}
			for _, fragment := range required {
				if !strings.Contains(sql, fragment) {
					t.Errorf("%s missing %q", migration, fragment)
				}
			}
		})
	}
}

func TestLC797IndexesUseOneConcurrentStatementPerMigration(t *testing.T) {
	indexMigrations := []string{
		"510_projectauth_issue_policies_unique.up.sql",
		"512_projectauth_grant_constraints_unique.up.sql",
		"513_projectauth_grant_constraints_expiry_index.up.sql",
		"515_projectauth_access_requests_id_unique.up.sql",
		"516_projectauth_access_requests_pending_resource_index.up.sql",
		"517_projectauth_access_requests_principal_index.up.sql",
		"518_projectauth_access_requests_idempotency_unique.up.sql",
		"520_projectauth_task_roles_unique.up.sql",
		"522_projectauth_task_role_permissions_unique.up.sql",
	}
	statementPattern := regexp.MustCompile(`(?is)^\s*(?:--[^\n]*\n\s*)*CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\b.*;\s*$`)

	for _, migration := range indexMigrations {
		t.Run(migration, func(t *testing.T) {
			sql := readMigrationFile(t, migration)
			if !statementPattern.MatchString(sql) {
				t.Fatalf("%s must contain exactly one CREATE [UNIQUE] INDEX CONCURRENTLY statement", migration)
			}
			withoutComments := regexp.MustCompile(`(?m)^\s*--.*$`).ReplaceAllString(sql, "")
			if strings.Count(withoutComments, ";") != 1 {
				t.Fatalf("%s has %d SQL statements, want 1", migration, strings.Count(withoutComments, ";"))
			}
		})
	}
}

func TestLC797PermissionModelMigrationsApplyRollbackAndReapply(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("integration test requires Postgres at DATABASE_URL")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect to Postgres: %v", err)
	}
	defer pool.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire Postgres connection: %v", err)
	}
	defer conn.Release()

	schema := fmt.Sprintf("lc797_permission_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatalf("create isolated schema: %v", err)
	}
	defer func() {
		_, _ = conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+identifier+" CASCADE")
	}()
	if _, err := conn.Exec(ctx, "SET search_path TO "+identifier); err != nil {
		t.Fatalf("set isolated search path: %v", err)
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE workspace (id UUID NOT NULL)`); err != nil {
		t.Fatalf("create workspace fixture: %v", err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO workspace (id) VALUES ('00000000-0000-0000-0000-000000000797')`); err != nil {
		t.Fatalf("insert workspace fixture: %v", err)
	}

	applyLC797Migrations(t, ctx, conn.Conn(), "up")
	assertLC797SeededTaskMember(t, ctx, conn.Conn())
	applyLC797Migrations(t, ctx, conn.Conn(), "down")
	applyLC797Migrations(t, ctx, conn.Conn(), "up")
	assertLC797SeededTaskMember(t, ctx, conn.Conn())
}

func applyLC797Migrations(t *testing.T, ctx context.Context, conn *pgx.Conn, direction string) {
	t.Helper()
	if direction == "up" {
		for _, stem := range lc797MigrationStems {
			applyMigrationFile(t, ctx, conn, stem+".up.sql")
		}
		return
	}
	for index := len(lc797MigrationStems) - 1; index >= 0; index-- {
		applyMigrationFile(t, ctx, conn, lc797MigrationStems[index]+".down.sql")
	}
}

func assertLC797SeededTaskMember(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	var count int
	if err := conn.QueryRow(ctx, `
		SELECT count(*)
		FROM projectauth_task_roles role
		JOIN projectauth_task_role_permissions permission ON permission.role_id = role.id
		WHERE role.workspace_id = '00000000-0000-0000-0000-000000000797'
		  AND role.role_key = 'member'
		  AND permission.permission IN (
			  'project.view', 'project.edit', 'project.issue.comment', 'project.issue.child.create'
		  )`).Scan(&count); err != nil {
		t.Fatalf("read seeded task Member: %v", err)
	}
	if count != 4 {
		t.Fatalf("seeded task Member permission count = %d, want 4", count)
	}
}
