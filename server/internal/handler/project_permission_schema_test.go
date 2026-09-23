package handler

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestProjectPermissionSchemaMissing(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "missing table", err: &pgconn.PgError{Code: "42P01"}, want: true},
		{name: "wrapped missing table", err: errors.Join(errors.New("query failed"), &pgconn.PgError{Code: "42P01"}), want: true},
		{name: "missing column", err: &pgconn.PgError{Code: "42703"}, want: true},
		{name: "missing grant uniqueness", err: &pgconn.PgError{Code: "42P10"}, want: true},
		{name: "different postgres error", err: &pgconn.PgError{Code: "42501"}, want: false},
		{name: "plain error", err: errors.New("query failed"), want: false},
		{name: "nil", err: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := projectPermissionSchemaMissing(tt.err); got != tt.want {
				t.Fatalf("projectPermissionSchemaMissing(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
