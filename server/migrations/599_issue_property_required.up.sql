-- Required-on-create custom properties. The flag lives on the definition;
-- enforcement is create-time only (unsetting later stays allowed).
ALTER TABLE issue_property ADD COLUMN required BOOLEAN NOT NULL DEFAULT false;
