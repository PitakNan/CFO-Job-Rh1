// CFO-Job-Rh1 API — เก็บช่วงเวลา Gantt + ตรวจสิทธิ์รายคน
// หน้าเว็บ (GitHub Pages) อ่านได้โดยไม่ต้อง login · เขียนต้องมี token
import { OWNERS } from './owners.js';

const ALLOW_ORIGINS = [
  'https://pitaknan.github.io',
  'http://localhost:8080',
  'http://127.0.0.1:8080',
  'http://localhost:5500',
];
const TOKEN_TTL_SEC = 60 * 60 * 24 * 30; // 30 วัน
const MAX_SEG = 11;

/* ---------- utils ---------- */
const enc = new TextEncoder();
const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uToBytes = (s) => {
  const t = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(t + '==='.slice((t.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function sign(secret, payloadB64) {
  const key = await hmacKey(secret);
  return b64u(await crypto.subtle.sign('HMAC', key, enc.encode(payloadB64)));
}
async function makeToken(secret, claims) {
  const body = { ...claims, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SEC };
  const p = b64u(enc.encode(JSON.stringify(body)));
  return `${p}.${await sign(secret, p)}`;
}
async function readToken(secret, token) {
  if (!token || token.indexOf('.') < 0) return null;
  const [p, sig] = token.split('.');
  const key = await hmacKey(secret);
  let ok = false;
  try { ok = await crypto.subtle.verify('HMAC', key, b64uToBytes(sig), enc.encode(p)); } catch { return null; }
  if (!ok) return null;
  let claims;
  try { claims = JSON.parse(new TextDecoder().decode(b64uToBytes(p))); } catch { return null; }
  if (!claims.exp || claims.exp < Math.floor(Date.now() / 1000)) return null;
  return claims;
}
// เทียบรหัสแบบใช้เวลาคงที่ กันการเดาทีละตัวอักษร
function sameSecret(a, b) {
  const x = enc.encode(a), y = enc.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

function cors(req) {
  const o = req.headers.get('Origin') || '';
  const allow = ALLOW_ORIGINS.includes(o) ? o : ALLOW_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET,PUT,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}
const json = (req, obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...cors(req) },
  });

/* ---------- Durable Object ---------- */
export class TreeStore {
  constructor(state, env) { this.state = state; this.env = env; }

  async fetch(request) {
    const url = new URL(request.url);
    const op = url.pathname;

    if (op === '/read') {
      const spans = (await this.state.storage.get('spans')) || {};
      const meta = (await this.state.storage.get('meta')) || { rev: 0 };
      return new Response(JSON.stringify({ spans, meta }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (op === '/write') {
      const { ops, who } = await request.json();
      const spans = (await this.state.storage.get('spans')) || {};
      for (const o of ops) {
        const cur = spans[o.id] || [];
        while (cur.length <= o.i) cur.push(null);
        cur[o.i] = o.segs && o.segs.length ? { segs: o.segs, draft: !!o.draft } : null;
        spans[o.id] = cur;
      }
      const meta = (await this.state.storage.get('meta')) || { rev: 0 };
      meta.rev = (meta.rev || 0) + 1;
      meta.updatedAt = new Date().toISOString();
      meta.updatedBy = who;
      await this.state.storage.put({ spans, meta });
      return new Response(JSON.stringify({ spans, meta }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (op === '/seed') {
      const existing = await this.state.storage.get('spans');
      const { spans, force } = await request.json();
      if (existing && !force) return new Response(JSON.stringify({ seeded: false, reason: 'already has data' }), { headers: { 'Content-Type': 'application/json' } });
      await this.state.storage.put({ spans, meta: { rev: 1, updatedAt: new Date().toISOString(), updatedBy: 'seed' } });
      return new Response(JSON.stringify({ seeded: true, nodes: Object.keys(spans).length }), { headers: { 'Content-Type': 'application/json' } });
    }

    // กันเดารหัส: นับครั้งที่ล็อกอินพลาดต่อ IP
    if (op === '/throttle') {
      const { ip, fail } = await request.json();
      const k = 'fail:' + ip;
      const rec = (await this.state.storage.get(k)) || { n: 0, t: 0 };
      const now = Date.now();
      if (now - rec.t > 15 * 60 * 1000) { rec.n = 0; }
      if (fail) { rec.n++; rec.t = now; await this.state.storage.put(k, rec); }
      return new Response(JSON.stringify({ blocked: rec.n >= 8 }), { headers: { 'Content-Type': 'application/json' } });
    }

    return new Response('not found', { status: 404 });
  }
}

/* ---------- Worker ---------- */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(request) });

    const id = env.TREE.idFromName('cfo-job-rh1');
    const stub = env.TREE.get(id);
    const call = async (path, body) =>
      (await stub.fetch('https://do' + path, {
        method: body === undefined ? 'GET' : 'POST',
        body: body === undefined ? undefined : JSON.stringify(body),
      })).json();

    const auth = async () => {
      const h = request.headers.get('Authorization') || '';
      return readToken(env.CFO_SECRET, h.replace(/^Bearer\s+/i, ''));
    };

    try {
      /* อ่านช่วงเวลา — เปิดสาธารณะ */
      if (url.pathname === '/api/tree' && request.method === 'GET') {
        return json(request, await call('/read'));
      }

      /* เข้าสู่ระบบด้วยรหัสประจำตัว */
      if (url.pathname === '/api/login' && request.method === 'POST') {
        const ip = request.headers.get('CF-Connecting-IP') || 'x';
        if ((await call('/throttle', { ip, fail: false })).blocked)
          return json(request, { error: 'ใส่รหัสผิดหลายครั้ง รอ 15 นาทีแล้วลองใหม่' }, 429);

        const { code } = await request.json().catch(() => ({}));
        // บาง shell ใส่ BOM นำหน้าตอนอัปโหลด secret
        const raw = env.CFO_CODES || '{}';
        const people = JSON.parse(raw.slice(Math.max(0, raw.indexOf('{'))));
        let hit = null;
        for (const [c, p] of Object.entries(people)) if (sameSecret(String(code || ''), c)) hit = p;
        if (!hit) {
          await call('/throttle', { ip, fail: true });
          return json(request, { error: 'รหัสไม่ถูกต้อง' }, 401);
        }
        return json(request, { token: await makeToken(env.CFO_SECRET, hit), user: { uid: hit.uid, name: hit.name, admin: !!hit.admin } });
      }

      /* ใครกำลังล็อกอินอยู่ */
      if (url.pathname === '/api/me' && request.method === 'GET') {
        const c = await auth();
        return c ? json(request, { user: { uid: c.uid, name: c.name, admin: !!c.admin } }) : json(request, { user: null }, 401);
      }

      /* แก้ช่วงเวลา */
      if (url.pathname === '/api/spans' && request.method === 'PUT') {
        const c = await auth();
        if (!c) return json(request, { error: 'ต้องเข้าสู่ระบบก่อน' }, 401);

        const { ops } = await request.json().catch(() => ({}));
        if (!Array.isArray(ops) || !ops.length || ops.length > 200) return json(request, { error: 'คำสั่งไม่ถูกต้อง' }, 400);

        for (const o of ops) {
          const own = OWNERS[o.id];
          if (!own) return json(request, { error: 'ไม่รู้จักกล่องงาน ' + o.id }, 400);
          if (!c.admin && own[0] !== c.uid) return json(request, { error: 'แก้ได้เฉพาะงานของตัวเอง' }, 403);
          if (!Number.isInteger(o.i) || o.i < 0 || o.i >= own[1]) return json(request, { error: 'ลำดับรายการไม่ถูกต้อง' }, 400);
          if (o.segs != null) {
            if (!Array.isArray(o.segs) || o.segs.length > 6) return json(request, { error: 'ช่วงเวลาไม่ถูกต้อง' }, 400);
            for (const s of o.segs) {
              if (!Array.isArray(s) || s.length !== 2) return json(request, { error: 'ช่วงเวลาไม่ถูกต้อง' }, 400);
              const [a, b] = s;
              if (!Number.isInteger(a) || !Number.isInteger(b) || a < 0 || b > MAX_SEG || a > b)
                return json(request, { error: 'ช่วงเวลาต้องอยู่ในเดือน 0–11 และเริ่มก่อนสิ้นสุด' }, 400);
            }
          }
        }
        return json(request, await call('/write', { ops, who: c.name }));
      }

      /* ใส่ข้อมูลตั้งต้นครั้งแรก (ต้องเป็นหัวหน้ากลุ่มงาน) */
      if (url.pathname === '/api/seed' && request.method === 'POST') {
        const c = await auth();
        if (!c || !c.admin) return json(request, { error: 'เฉพาะหัวหน้ากลุ่มงาน' }, 403);
        const { spans, force } = await request.json().catch(() => ({}));
        if (!spans || typeof spans !== 'object') return json(request, { error: 'ไม่มีข้อมูล' }, 400);
        return json(request, await call('/seed', { spans, force: !!force }));
      }

      return json(request, { error: 'not found' }, 404);
    } catch (e) {
      return json(request, { error: 'server error', detail: String(e && e.message || e) }, 500);
    }
  },
};
