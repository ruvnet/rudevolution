const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const {DatabaseSync}=require('node:sqlite');const q=require('./queue.cjs');
test('freemium migration preserves populated run evidence and excludes free-owned queued rows',()=>{
 const db=new DatabaseSync(':memory:');
 db.exec("PRAGMA foreign_keys=ON; CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT NOT NULL,created_at TEXT NOT NULL); CREATE TABLE projects(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES users(id),name TEXT NOT NULL,repository TEXT NOT NULL,mode TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(id,owner)); CREATE TABLE runs(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES users(id),project_id TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('queued','awaiting_review','running','blocked','failed','published')),idempotency_key TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT,evidence_url TEXT,error_code TEXT,lease_until TEXT,lease_token TEXT,UNIQUE(owner,idempotency_key),FOREIGN KEY(project_id,owner) REFERENCES projects(id,owner)); CREATE INDEX runs_owner ON runs(owner,created_at);");
 const pid='11111111-1111-1111-1111-111111111111',rid='22222222-2222-2222-2222-222222222222';
 db.prepare('INSERT INTO users VALUES (?,?,?)').run('free-user','free@example.com','2026-10-11');
 db.prepare('INSERT INTO projects VALUES (?,?,?,?,?,?)').run(pid,'free-user','Test','https://github.com/a/b','own','2026-10-11');
 db.prepare('INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(rid,'free-user',pid,'queued','preserved-key','2026-10-11','2026-10-11','https://example.invalid/evidence','OLD_CODE','2026-10-12','old-token');
 const old=db.prepare('SELECT * FROM runs').get();
 db.exec('BEGIN');db.exec(fs.readFileSync(__dirname+'/migrations/0002-freemium.sql','utf8'));db.exec('COMMIT');
 assert.deepEqual(db.prepare('SELECT * FROM runs').get(),old);
 assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(),[]);
 const claim=q.claim({runId:rid,leaseToken:'33333333-3333-3333-3333-333333333333',ownerEmails:['free@example.com']});
 assert.equal(db.prepare(claim.sql).all(...claim.params).length,0);
 const pending=q.pending({ownerEmails:['free@example.com']});assert.equal(db.prepare(pending.sql).all(...pending.params).length,0);
 db.close();
});
