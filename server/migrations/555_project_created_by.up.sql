-- Project creator is nullable so projects created before this migration remain readable.
-- 2026-08-28 lq: Record the user who created each project for list attribution.
ALTER TABLE project
    ADD COLUMN created_by UUID REFERENCES "user"(id) ON DELETE SET NULL;

CREATE INDEX idx_project_created_by ON project(created_by);
