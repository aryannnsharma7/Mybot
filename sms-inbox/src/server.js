import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { verifyTelnyxWebhook } from './telnyx.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const USERNAME = process.env.DASHBOARD_USER || '';
const PASSWORD = process.env.DASHBOARD_PASSWORD || '';
const OWNED_NUMBER = process.env.OWNED_NUMBER || '';
const TELNYX_PUBLIC_KEY = process.env.TELNYX_PUBLIC_KEY || '';
const RETENTION_HOURS = Number(process.env.RETENTION_HOURS || 24);
const DATABASE_PATH = resolve(ROOT, process.env.DATABASE_PATH || './data/messages.sqlite');
const MAX_BODY_BYTES = 512 * 1024;

const issues = [];
if (!USERNAME.trim()) issues.push('DASHBOARD_USER is required.');
if (PASSWORD.length < 20) issues.push('DASHBOARD_PASSWORD must be at least 20 characters.');
if (!/^\+[1-9]\d{7,14}$/.test(OWNED_NUMBER)) issues.push('OWNED_NUMBER must be your assigned E.164 number.');
if (Buffer.from(TELNYX_PUBLIC_KEY, 'base64').length !== 32) issues.push('TELNYX_PUBLIC_KEY must be the 32-byte base64 Ed25519 public key from Telnyx.');
if (!Number.isFinite(RETENTION_HOURS) || RETENTION_HOURS < 1 || RETENTION_HOURS > 168) issues.push('RETENTION_HOURS must be between 1 and 168.');
if (issues.length) { console.error('Configuration error:\n- ' + issues.join('\n- ')); process.exit(1); }

mkdirSync(dirname(DATABASE_PATH), { recursive: true });
const db = new DatabaseSync(DATABASE_PATH);
db.exec(`PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, provider_message_id TEXT NOT NULL UNIQUE, from_number TEXT NOT NULL, to_number TEXT NOT NULL, message_text TEXT NOT NULL, received_at TEXT NOT NULL, saved_at_ms INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_messages_saved_at ON messages(saved_at_ms DESC);`);
const insertMessage = db.prepare('INSERT OR IGNORE INTO messages (provider_message_id, from_number, to_number, message_text, received_at, saved_at_ms) VALUES (?, ?, ?, ?, ?, ?)');
const listMessages = db.prepare('SELECT id, from_number AS fromNumber, to_number AS toNumber, message_text AS text, received_at AS receivedAt FROM messages ORDER BY saved_at_ms DESC LIMIT 200');
const deleteMessages = db.prepare('DELETE FROM messages');
const purgeOldMessages = db.prepare('DELETE FROM messages WHERE saved_at_ms < ?');

function sameSecret(a, b) { const x = Buffer.from(String(a)); const y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); }
function authorized(req) {
  const header = req.headers.authorization || ''; if (!header.startsWith('Basic ')) return false;
  let decoded; try { decoded = Buffer.from(header.slice(6), 'base64').toString('utf8'); } catch { return false; }
  const split = decoded.indexOf(':'); if (split < 1) return false;
  return sameSecret(decoded.slice(0, split), USERNAME) && sameSecret(decoded.slice(split + 1), PASSWORD);
}
function sendJson(res, status, value) { const body = JSON.stringify(value); res.writeHead(status, { 'content-type':'application/json; charset=utf-8', 'content-length':Buffer.byteLength(body), 'cache-control':'no-store', 'x-content-type-options':'nosniff' }); res.end(body); }
function requireAuth(req, res) { if (authorized(req)) return true; res.writeHead(401, { 'www-authenticate':'Basic realm="Private SMS Inbox", charset="UTF-8"', 'content-type':'text/plain; charset=utf-8', 'cache-control':'no-store' }); res.end('Authentication required.'); return false; }
async function readRawBody(req) { const chunks=[]; let length=0; for await (const chunk of req) { length += chunk.length; if (length > MAX_BODY_BYTES) throw new Error('Request body too large.'); chunks.push(chunk); } return Buffer.concat(chunks); }
function handleInbound(event) {
  if (event?.data?.event_type !== 'message.received') return { accepted:true, stored:false, reason:'Ignored non-inbound-message event.' };
  const payload=event?.data?.payload; if (!payload || (payload.direction && payload.direction !== 'inbound')) return { accepted:true, stored:false, reason:'Ignored non-inbound payload.' };
  const from=payload?.from?.phone_number; const destinations=Array.isArray(payload?.to)?payload.to:[];
  const owned=destinations.some(item=>item?.phone_number===OWNED_NUMBER); const text=typeof payload?.text==='string'?payload.text:''; const id=payload?.id||event?.data?.id;
  if (!owned || !/^\+[1-9]\d{7,14}$/.test(from||'') || !id) return { accepted:true, stored:false, reason:'Message did not match the configured owned number.' };
  if (!text || text.length>5000) return { accepted:true, stored:false, reason:'Empty or oversized SMS body.' };
  const received=payload.received_at||event?.data?.occurred_at||new Date().toISOString();
  const result=insertMessage.run(String(id),from,OWNED_NUMBER,text,String(received),Date.now());
  return { accepted:true, stored:Number(result.changes)===1, duplicate:Number(result.changes)===0 };
}
const html=readFileSync(resolve(ROOT,'public/index.html')); const js=readFileSync(resolve(ROOT,'public/app.js'));
const server=createServer(async(req,res)=>{
  const url=new URL(req.url||'/',`http://${req.headers.host||'localhost'}`);
  if(url.pathname==='/webhooks/telnyx'&&req.method==='POST'){
    let raw; try { raw=await readRawBody(req); } catch { return sendJson(res,413,{error:'Request body too large.'}); }
    const check=verifyTelnyxWebhook({rawBody:raw,headers:req.headers,publicKeyBase64:TELNYX_PUBLIC_KEY});
    if(!check.valid) return sendJson(res,401,{error:'Webhook signature rejected.'});
    let event; try { event=JSON.parse(raw.toString('utf8')); } catch { return sendJson(res,400,{error:'Invalid JSON webhook.'}); }
    return sendJson(res,200,handleInbound(event));
  }
  if(!requireAuth(req,res)) return;
  if(url.pathname==='/'&&req.method==='GET') { res.writeHead(200,{'content-type':'text/html; charset=utf-8','content-length':Buffer.byteLength(html),'cache-control':'no-store','x-content-type-options':'nosniff','x-frame-options':'DENY','content-security-policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",'referrer-policy':'no-referrer'}); return res.end(html); }
  if(url.pathname==='/app.js'&&req.method==='GET') { res.writeHead(200,{'content-type':'text/javascript; charset=utf-8','content-length':Buffer.byteLength(js),'cache-control':'no-store','x-content-type-options':'nosniff'}); return res.end(js); }
  if(url.pathname==='/api/messages'&&req.method==='GET') { purgeOldMessages.run(Date.now()-RETENTION_HOURS*3600000); return sendJson(res,200,{messages:listMessages.all(),retentionHours:RETENTION_HOURS}); }
  if(url.pathname==='/api/messages'&&req.method==='DELETE') { deleteMessages.run(); return sendJson(res,200,{deleted:true}); }
  return sendJson(res,404,{error:'Not found.'});
});
server.listen(PORT,HOST,()=>console.log(`Private SMS Inbox listening on http://${HOST}:${PORT}; destination ${OWNED_NUMBER}; retention ${RETENTION_HOURS}h`));
function shutdown(){server.close(()=>{db.close();process.exit(0);});}
process.on('SIGINT',shutdown); process.on('SIGTERM',shutdown);
