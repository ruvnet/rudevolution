import { html, css, js } from './ui.mjs';
const encoder = new TextEncoder();
// Only public, identity-independent representations belong in this cache.
const publicAssets = Promise.all([css, js].map(async content => {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(content)));
  return { content, version: Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('') };
})).then(async ([style, script]) => {
  const page = html.replace('href="/style.css"', 'href="/style.css?v=' + style.version + '"').replace('src="/app.js"', 'src="/app.js?v=' + script.version + '"');
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(page)));
  return { '/style.css': style, '/app.js': script, '/': { content: page, version: Array.from(digest, b => b.toString(16).padStart(2, '0')).join('') } };
});
async function publicResponse(request, url) {
  const asset = (await publicAssets)[url.pathname];
  const versioned = url.pathname !== '/' && url.searchParams.get('v') === asset.version;
  const headers = new Headers({ 'content-type': url.pathname === '/' ? 'text/html; charset=utf-8' : url.pathname === '/style.css' ? 'text/css; charset=utf-8' : 'application/javascript; charset=utf-8', 'cache-control': versioned ? 'public, max-age=31536000, immutable' : 'public, no-cache', 'etag': '"' + asset.version + '"', 'x-content-type-options': 'nosniff' });
  if (url.pathname === '/') {
    headers.set('content-security-policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https://github.com/ruvnet/readme-proof/releases/download/ https://release-assets.githubusercontent.com; connect-src 'self'; media-src https://github.com/ruvnet/readme-proof/releases/download/ https://release-assets.githubusercontent.com; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    headers.set('referrer-policy', 'no-referrer');
  }
  const matches = (request.headers.get('if-none-match') || '').split(',').map(value => value.trim().replace(/^W\//, ''));
  if (matches.includes('*') || matches.includes(headers.get('etag'))) return new Response(null, { status: 304, headers });
  return new Response(request.method === 'HEAD' ? null : asset.content, { headers });
}
const MAX_BODY = 8192;
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const json = (value, status = 200) => new Response(JSON.stringify(value), {status, headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'}});
function decode(segment) { try { return Uint8Array.from(atob(segment.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0)); } catch { throw new HttpError(401,'Invalid identity'); } }
function parsed(segment) { try { return JSON.parse(new TextDecoder().decode(decode(segment))); } catch { throw new HttpError(401,'Invalid identity'); } }
export async function identity(request, env, fetcher = fetch) {
  const domain = env.ACCESS_TEAM_DOMAIN;
  if (!domain || !/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(domain) || !env.ACCESS_AUD) throw new HttpError(503,'Identity is not configured');
  const token = request.headers.get('cf-access-jwt-assertion');
  if (!token || token.length > 16384) throw new HttpError(401,'Authentication required');
  const parts = token.split('.');
  if (parts.length !== 3) throw new HttpError(401,'Invalid identity');
  const header = parsed(parts[0]), claims = parsed(parts[1]);
  const now = Math.floor(Date.now()/1000);
  if (header.alg !== 'RS256' || typeof header.kid !== 'string' || claims.iss !== `https://${domain}` || !Array.isArray(claims.aud) || !claims.aud.includes(env.ACCESS_AUD) || !Number.isFinite(claims.exp) || claims.exp <= now || !Number.isFinite(claims.iat) || claims.iat > now + 30 || (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf > now)) || typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 512 || typeof claims.email !== 'string' || !/^[^\s@]+@[^\s@]+$/.test(claims.email) || claims.email.length > 320) throw new HttpError(401,'Invalid identity');
  let keys;
  try { const response = await fetcher(`https://${domain}/cdn-cgi/access/certs`,{redirect:'error',signal:AbortSignal.timeout(5000)}); if (!response.ok) throw Error(); const text = await response.text(); if (text.length>65536) throw Error(); keys = JSON.parse(text).keys; } catch { throw new HttpError(503,'Identity service unavailable'); }
  const key = Array.isArray(keys) && keys.find(k=>k.kid===header.kid && k.kty==='RSA' && (!k.use || k.use==='sig') && (!k.alg || k.alg==='RS256'));
  if (!key) throw new HttpError(401,'Invalid identity');
  try { const cryptoKey = await crypto.subtle.importKey('jwk',key,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']); if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',cryptoKey,decode(parts[2]),encoder.encode(`${parts[0]}.${parts[1]}`))) throw Error(); } catch { throw new HttpError(401,'Invalid identity'); }
  return {id:claims.sub,sub:claims.sub,email:claims.email};
}
async function body(request) {
  if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) throw new HttpError(415,'JSON required');
  if (Number(request.headers.get('content-length')) > MAX_BODY) throw new HttpError(413,'Request too large');
  const reader = request.body?.getReader(); let chunks=[], size=0;
  if (reader) { while (true) { const {done,value}=await reader.read(); if(done) break; size+=value.length; if(size>MAX_BODY) { await reader.cancel(); throw new HttpError(413,'Request too large'); } chunks.push(value); } }
  const bytes = new Uint8Array(size); let offset=0; for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  try { const result=JSON.parse(new TextDecoder().decode(bytes)); if(!result || typeof result!=='object' || Array.isArray(result)) throw Error(); return result; } catch { throw new HttpError(400,'Invalid JSON'); }
}
function fields(value, allowed) { if(Object.keys(value).some(k=>!allowed.includes(k))) throw new HttpError(400,'Unknown fields'); }
export function projectInput(value) {
  fields(value,['name','repository','mode']);
  if(typeof value.name!=='string' || !value.name.trim() || value.name.length>100 || /[\x00-\x1f]/.test(value.name)) throw new HttpError(400,'Invalid project name');
  if(typeof value.repository!=='string' || !/^https:\/\/github\.com\/[a-zA-Z0-9][a-zA-Z0-9-]{0,38}\/[a-zA-Z0-9_.-]{1,100}$/.test(value.repository) || ['.','..'].includes(value.repository.split('/').at(-1))) throw new HttpError(400,'Use a GitHub repository URL');
  if(!['own','cleanroom'].includes(value.mode)) throw new HttpError(400,'Invalid project mode');
  return {name:value.name.trim(),repository:value.repository,mode:value.mode};
}
export async function handle(request, env, fetcher = fetch) {
  const url=new URL(request.url);
  try {
    if(url.pathname==='/login' && request.method==='GET') return new Response(null,{status:302,headers:{location:'/api/login','cache-control':'no-store'}});
    if(url.pathname==='/api/health' && request.method==='GET') return json({ready:Boolean(env.DB && env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD),execution_enabled:false});
    if(['GET','HEAD'].includes(request.method) && ['/','/style.css','/app.js'].includes(url.pathname)) return publicResponse(request,url);
    if(!url.pathname.startsWith('/api/')) throw new HttpError(404,'Not found');
    if(!['GET','POST'].includes(request.method)) throw new HttpError(405,'Method not allowed');
    if(request.method==='POST' && request.headers.get('origin')!==url.origin) throw new HttpError(403,'Same-origin request required');
    const user=await identity(request,env,fetcher);
    if(url.pathname==='/api/login' && request.method==='GET') return new Response(null,{status:302,headers:{location:'/','cache-control':'no-store'}});
    if(!env.DB) throw new HttpError(503,'Database is not configured');
    const db=env.DB;
    const registered=await db.prepare('SELECT id, email, plan FROM users WHERE id = ?').bind(user.id).first();
    const trustedPlan=String(env.OWNER_EMAILS||'').split(',').map(s=>s.trim().toLowerCase()).filter(Boolean).includes(user.email.toLowerCase())?'operator':'free';
    if(registered && registered.plan!==trustedPlan) await db.prepare('UPDATE users SET plan = ? WHERE id = ?').bind(trustedPlan,user.id).run();
    const plan=registered?trustedPlan:'free';
    const cutoff=new Date(Date.now()-86400000).toISOString();
    if(url.pathname==='/api/session' && request.method==='GET') {
      const projects=registered?await db.prepare('SELECT COUNT(*) AS count FROM projects WHERE owner = ?').bind(user.id).first():{count:0};
      const runs=registered?await db.prepare('SELECT COUNT(*) AS count FROM runs WHERE owner = ? AND created_at >= ?').bind(user.id,cutoff).first():{count:0};
      return json({user:{email:user.email,sub:user.sub},registered:Boolean(registered),plan,limits:{projects:plan==='free'?1:null,runs_per_24h:plan==='free'?1:null},usage:{projects:projects.count,runs_last_24h:runs.count}});
    }
    if(url.pathname==='/api/register' && request.method==='POST') {
      fields(await body(request),[]);
      const initialPlan=trustedPlan;
      await db.prepare('INSERT INTO users (id, email, plan, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET email = excluded.email').bind(user.id,user.email,initialPlan,new Date().toISOString()).run();
      return json({user:{id:user.id,email:user.email}});
    }
    if(!registered) throw new HttpError(403,'Registration required');
    if(url.pathname==='/api/upgrade' && request.method==='POST') {
      const value=await body(request); fields(value,['message']);
      if(typeof value.message!=='string' || !value.message.trim() || value.message.length>1000 || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(value.message)) throw new HttpError(400,'Invalid upgrade message');
      const upgrade={id:crypto.randomUUID(),status:'requested',created_at:new Date().toISOString()};
      await db.prepare('INSERT INTO upgrade_requests (id, owner, message, status, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING').bind(upgrade.id,user.id,value.message.trim(),upgrade.status,upgrade.created_at).run();
      const saved=await db.prepare("SELECT id, status, created_at FROM upgrade_requests WHERE owner = ? AND status = 'requested'").bind(user.id).first();
      return json({request:saved},saved.id===upgrade.id?201:200);
    }
    if(url.pathname==='/api/projects') {
      if(request.method==='GET') return json({projects:(await db.prepare('SELECT id, name, repository, mode, created_at FROM projects WHERE owner = ? ORDER BY created_at DESC LIMIT 100').bind(user.id).all()).results});
      const input=projectInput(await body(request));
      const project={id:crypto.randomUUID(),...input,created_at:new Date().toISOString()};
      const inserted=await db.prepare("INSERT INTO projects (id, owner, name, repository, mode, created_at) SELECT ?, ?, ?, ?, ?, ? WHERE (SELECT plan FROM users WHERE id = ?) = 'operator' OR (SELECT COUNT(*) FROM projects WHERE owner = ?) < 1").bind(project.id,user.id,project.name,project.repository,project.mode,project.created_at,user.id,user.id).run();
      if(!inserted.meta.changes) throw new HttpError(429,'Free plan allows one project. Request an upgrade.');
      return json({project},201);
    }
    if(url.pathname==='/api/runs') {
      if(request.method==='GET') return json({runs:(await db.prepare('SELECT id, project_id, status, idempotency_key, created_at, updated_at, evidence_url, error_code FROM runs WHERE owner = ? ORDER BY created_at DESC LIMIT 100').bind(user.id).all()).results});
      const value=await body(request); fields(value,['project_id','idempotency_key']);
      if(typeof value.project_id!=='string' || !/^[a-f0-9-]{36}$/.test(value.project_id) || typeof value.idempotency_key!=='string' || !/^[a-zA-Z0-9_-]{8,128}$/.test(value.idempotency_key)) throw new HttpError(400,'Invalid run request');
      const project=await db.prepare('SELECT id, mode FROM projects WHERE id = ? AND owner = ?').bind(value.project_id,user.id).first();
      if(!project) throw new HttpError(404,'Project not found');
      const run={id:crypto.randomUUID(),project_id:project.id,status:project.mode==='cleanroom'?'awaiting_review':plan==='operator'?'queued':'awaiting_authorization',idempotency_key:value.idempotency_key,created_at:new Date().toISOString()};
      await db.prepare("INSERT INTO runs (id, owner, project_id, status, idempotency_key, created_at) SELECT ?, ?, ?, ?, ?, ? WHERE (SELECT plan FROM users WHERE id = ?) = 'operator' OR (SELECT COUNT(*) FROM runs WHERE owner = ? AND created_at >= ?) < 1 ON CONFLICT(owner, idempotency_key) DO NOTHING").bind(run.id,user.id,run.project_id,run.status,run.idempotency_key,run.created_at,user.id,user.id,cutoff).run();
      const saved=await db.prepare('SELECT id, project_id, status, idempotency_key, created_at, updated_at, evidence_url, error_code FROM runs WHERE owner = ? AND idempotency_key = ?').bind(user.id,value.idempotency_key).first();
      if(!saved) throw new HttpError(429,'Free plan allows one run request per 24 hours. Request an upgrade.');
      if(saved.project_id!==project.id) throw new HttpError(409,'Idempotency key belongs to another project');
      return json({run:saved},saved.id===run.id?201:200);
    }
    throw new HttpError(404,'Not found');
  } catch(error) { return json({error:error instanceof HttpError?error.message:'Request failed'},error instanceof HttpError?error.status:500); }
}
export default {fetch(request, env) { return handle(request, env); }};
