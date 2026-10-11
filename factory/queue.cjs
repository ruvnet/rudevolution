'use strict';
// Operator-side statements for the authenticated Cloudflare connector. No credentials.
const uuid = value => { if (typeof value !== 'string' || !/^[a-f0-9-]{36}$/.test(value)) throw Error('Invalid identifier'); return value; };
function claim({runId, leaseToken, now = new Date()}) {
  const start = now.toISOString();
  return {sql: `UPDATE runs SET status='running', lease_token=?, lease_until=?, updated_at=? WHERE id=? AND status='queued' AND EXISTS (SELECT 1 FROM projects p WHERE p.id=runs.project_id AND p.owner=runs.owner AND p.mode='own') RETURNING id,owner,project_id,lease_token`, params:[uuid(leaseToken),new Date(now.getTime()+45*60*1000).toISOString(),start,uuid(runId)]};
}
// Caller must independently reconcile package integrity and release evidence first.
// A URL is an evidence pointer, never verification by itself.
function finish({runId,leaseToken,status,evidenceUrl='',errorCode='',now=new Date()}) {
  if (!['published','failed','blocked'].includes(status)) throw Error('Invalid outcome');
  if (status==='published' && !/^https:\/\/github\.com\/ruvnet\/[A-Za-z0-9_.-]+\/releases\/tag\/[A-Za-z0-9_.\/-]+$/.test(evidenceUrl)) throw Error('Verified release evidence required');
  if (evidenceUrl.length>2048 || !/^[A-Z0-9_]{0,64}$/.test(errorCode)) throw Error('Invalid evidence');
  const time=now.toISOString();
  return {sql:'UPDATE runs SET status=?, evidence_url=?, error_code=?, updated_at=?, lease_token=NULL, lease_until=NULL WHERE id=? AND status=\'running\' AND lease_token=? AND lease_until>=? RETURNING id,status',params:[status,evidenceUrl,errorCode,time,uuid(runId),uuid(leaseToken),time]};
}
const pending = {sql:"SELECT r.id,r.owner,r.project_id,p.repository,p.name FROM runs r JOIN projects p ON p.id=r.project_id AND p.owner=r.owner WHERE r.status='queued' AND p.mode='own' ORDER BY r.created_at LIMIT 1",params:[]};
// An expired run may have published. Require reconciliation, never blindly retry it.
function expire(now=new Date()) { return {sql:"UPDATE runs SET status='blocked',error_code='LEASE_EXPIRED_RECONCILE',lease_token=NULL,lease_until=NULL,updated_at=? WHERE status='running' AND lease_until<? RETURNING id",params:[now.toISOString(),now.toISOString()]}; }
module.exports={claim,finish,pending,expire};
