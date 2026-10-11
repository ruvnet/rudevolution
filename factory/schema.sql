PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL, repository TEXT NOT NULL, mode TEXT NOT NULL CHECK(mode IN ('own','cleanroom')), created_at TEXT NOT NULL, UNIQUE(id, owner));
CREATE INDEX IF NOT EXISTS projects_owner ON projects(owner, created_at);
CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES users(id), project_id TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('queued','awaiting_review','running','blocked','failed','published')), idempotency_key TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT, evidence_url TEXT, error_code TEXT, lease_until TEXT, lease_token TEXT, UNIQUE(owner,idempotency_key), FOREIGN KEY(project_id,owner) REFERENCES projects(id,owner));
CREATE INDEX IF NOT EXISTS runs_owner ON runs(owner, created_at);
