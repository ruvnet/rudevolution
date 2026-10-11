'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const {DatabaseSync}=require('node:sqlite');const fs=require('node:fs');const q=require('./queue.cjs');
test('queue claims once, excludes cleanroom, binds completion to lease and blocks expired jobs',()=>{
 const db=new DatabaseSync(':memory:');db.exec(fs.readFileSync(__dirname+'/schema.sql','utf8'));
 const owner='user'; const own='11111111-1111-1111-1111-111111111111',clean='22222222-2222-2222-2222-222222222222',rid='33333333-3333-3333-3333-333333333333',cid='44444444-4444-4444-4444-444444444444',token='55555555-5555-5555-5555-555555555555',other='66666666-6666-6666-6666-666666666666';
 db.prepare("INSERT INTO users (id,email,created_at,plan) VALUES (?,?,?,'operator')").run(owner,'test@example.com','2026-10-11');
 for(const [id,mode] of [[own,'own'],[clean,'cleanroom']]) db.prepare('INSERT INTO projects VALUES (?,?,?,?,?,?)').run(id,owner,'Test','https://github.com/ruvnet/rudevolution',mode,'2026-10-11');
 for(const [id,project] of [[rid,own],[cid,clean]])db.prepare('INSERT INTO runs (id,owner,project_id,status,idempotency_key,created_at) VALUES (?,?,?,?,?,?)').run(id,owner,project,'queued',id,'2026-10-11');
 const exec=s=>db.prepare(s.sql).all(...s.params); const now=new Date('2026-10-11T18:00:00Z');
 assert.equal(exec(q.claim({runId:cid,leaseToken:token,ownerEmails:['test@example.com'],now})).length,0);
 assert.equal(exec(q.claim({runId:rid,leaseToken:token,ownerEmails:['revoked@example.com'],now})).length,0);
 assert.equal(exec(q.claim({runId:rid,leaseToken:token,ownerEmails:['test@example.com'],now})).length,1);
 assert.equal(exec(q.claim({runId:rid,leaseToken:other,ownerEmails:['test@example.com'],now})).length,0);
 assert.equal(exec(q.finish({runId:rid,leaseToken:other,status:'blocked',now})).length,0);
 assert.throws(()=>q.finish({runId:rid,leaseToken:token,status:'published',now}),/evidence/);
 assert.equal(exec(q.expire(new Date('2026-10-11T18:46:00Z'))).length,1);
 assert.equal(exec(q.finish({runId:rid,leaseToken:token,status:'published',evidenceUrl:'https://github.com/ruvnet/rudevolution/releases/tag/v1',now})).length,0);
 db.close();
});
