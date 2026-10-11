ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'free' CHECK(plan IN ('free','operator'));
CREATE TABLE runs_freemium (id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES users(id), project_id TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('queued','awaiting_authorization','awaiting_review','running','blocked','failed','published')), idempotency_key TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT, evidence_url TEXT, error_code TEXT, lease_until TEXT, lease_token TEXT, UNIQUE(owner,idempotency_key), FOREIGN KEY(project_id,owner) REFERENCES projects(id,owner));
INSERT INTO runs_freemium SELECT * FROM runs;
DROP TABLE runs;
ALTER TABLE runs_freemium RENAME TO runs;
CREATE INDEX runs_owner ON runs(owner, created_at);
CREATE TABLE IF NOT EXISTS upgrade_requests (id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES users(id), message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'requested' CHECK(status IN ('requested','reviewed')), created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS upgrades_owner ON upgrade_requests(owner, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS upgrades_pending_owner ON upgrade_requests(owner) WHERE status = 'requested';
