// D1 Dashboard on Cloudflare Workers. No outside packages.
// Logins and sessions live in Workers KV (binding D1_STORE). Pages and data are bundled into this file.
import dashboardHtml from '../views/dashboard.html';
import adminHtml from '../views/admin.html';
import weekly from '../data/weekly.json';
import parts_lines from '../data/parts_lines.json';
import parts_week from '../data/parts_week.json';
import lead_sources from '../data/lead_sources.json';
import attention from '../data/attention.json';

const DATA = { weekly, parts_lines, parts_week, lead_sources, attention };
const COOKIE = 'd1s';
const SESSION_HOURS = 12;
const MAX_FAILS = 5;
const LOCK_MINUTES = 10;
const PBKDF2_ITERATIONS = 10000; // kept low to fit the free plan 10 ms CPU limit; stored with each hash so it can be raised later (paid plan) without locking anyone out
const ROLES = ['admin', 'viewer'];

const SECURITY_HEADERS = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Robots-Tag': 'noindex, nofollow',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'Cache-Control': 'no-store',
};

// ---------- small helpers ----------
const enc = new TextEncoder();
const b64 = (bytes) => { let s = ''; bytes = new Uint8Array(bytes); for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (bytes) => b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = (s) => unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const normEmail = (e) => String(e || '').trim().toLowerCase();
const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length <= 120;

function respond(body, status, extra) {
  return new Response(body, { status, headers: Object.assign({}, SECURITY_HEADERS, extra || {}) });
}
const json = (obj, status = 200) => respond(JSON.stringify(obj), status, { 'Content-Type': 'application/json; charset=utf-8' });
const html = (text, status = 200) => respond(text, status, { 'Content-Type': 'text/html; charset=utf-8' });
const redirect = (to, extraHeaders) => respond(null, 302, Object.assign({ Location: to }, extraHeaders || {}));

// ---------- storage (Workers KV) ----------
function store(env) {
  if (!env.D1_STORE) throw new Error('STORAGE_NOT_CONNECTED');
  return env.D1_STORE;
}
async function kget(env, key) { const v = await store(env).get(key); return v ? JSON.parse(v) : null; }
const kset = (env, key, val) => store(env).put(key, JSON.stringify(val));
const getUsers = async (env) => (await kget(env, 'users')) || [];
const saveUsers = (env, users) => kset(env, 'users', users);

// ---------- passwords (PBKDF2 through the built in Web Crypto) ----------
async function pbkdf2(pw, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256));
}
async function hashPassword(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${PBKDF2_ITERATIONS}$${b64(salt)}$${b64(await pbkdf2(pw, salt, PBKDF2_ITERATIONS))}`;
}
async function verifyPassword(pw, stored) {
  try {
    const [, it, s, h] = stored.split('$');
    const got = await pbkdf2(pw, unb64(s), parseInt(it, 10));
    const want = unb64(h);
    let diff = got.length ^ want.length;
    for (let i = 0; i < got.length; i++) diff |= got[i] ^ (want[i] || 0);
    return diff === 0;
  } catch (e) { return false; }
}
function tempPassword() {
  const a = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const r = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(r, (x) => a[x % a.length]).join('');
}
function passwordProblem(pw, email) {
  if (typeof pw !== 'string' || pw.length < 10) return 'Use at least 10 characters.';
  if (pw.length > 100) return 'That password is too long.';
  if (email && pw.toLowerCase() === email.toLowerCase()) return 'The password cannot be your email.';
  return null;
}

// ---------- sessions (signed cookie, checked against the live user list) ----------
function secretKey(env) {
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 24) throw new Error('SESSION_SECRET_MISSING');
  return crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function signToken(env, payload) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', await secretKey(env), enc.encode(body)));
  return body + '.' + b64url(mac);
}
async function readToken(env, tok) {
  if (typeof tok !== 'string' || tok.indexOf('.') < 0) return null;
  const [body, mac] = tok.split('.');
  try {
    const ok = await crypto.subtle.verify('HMAC', await secretKey(env), unb64url(mac), enc.encode(body));
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(unb64url(body)));
    return p.x > Date.now() ? p : null;
  } catch (e) { if (String(e.message).includes('SESSION_SECRET')) throw e; return null; }
}
function cookies(request) {
  const o = {};
  (request.headers.get('Cookie') || '').split(';').forEach((p) => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return o;
}
async function sessionCookie(env, user) {
  const tok = await signToken(env, { e: user.email, v: user.sv, x: Date.now() + SESSION_HOURS * 3600 * 1000 });
  return `${COOKIE}=${tok}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_HOURS * 3600}`;
}
const clearedCookie = () => `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
async function getSession(request, env) {
  const p = await readToken(env, cookies(request)[COOKIE]);
  if (!p) return null;
  const u = (await getUsers(env)).find((x) => x.email === p.e);
  return !u || u.disabled || u.sv !== p.v ? null : u;
}
const publicUser = (u) => ({ email: u.email, name: u.name, role: u.role, must_change: !!u.must_change, disabled: !!u.disabled, created: u.created, last_login: u.last_login || null });

// ---------- request guards ----------
function sameOrigin(request) {
  const o = request.headers.get('Origin');
  if (!o) return true;
  try { return new URL(o).host === new URL(request.url).host; } catch (e) { return false; }
}
function postGuard(request) {
  if (!sameOrigin(request)) return json({ error: 'Blocked.' }, 403);
  if (!(request.headers.get('Content-Type') || '').startsWith('application/json')) return json({ error: 'Bad request.' }, 415);
  return null;
}
async function body(request) {
  try { const t = await request.text(); if (t.length > 20000) return {}; return JSON.parse(t || '{}'); } catch (e) { return {}; }
}
function problem(e) {
  const m = String(e && e.message);
  if (m === 'STORAGE_NOT_CONNECTED') return json({ error: 'Storage is not connected yet. See the setup guide.' }, 503);
  if (m === 'SESSION_SECRET_MISSING') return json({ error: 'SESSION_SECRET is not set yet. See the setup guide.' }, 503);
  console.error(e && e.stack || e);
  return json({ error: 'Something went wrong.' }, 500);
}

// ---------- routes ----------
async function login(request, env) {
  const g = postGuard(request); if (g) return g;
  const b = await body(request);
  const email = normEmail(b.email), pw = String(b.password || '');
  const bad = () => json({ error: 'Wrong email or password.' }, 401);
  if (!email || !pw) return bad();

  const fail = (await kget(env, 'fail:' + email)) || { n: 0, until: 0 };
  if (fail.until > Date.now()) {
    const mins = Math.ceil((fail.until - Date.now()) / 60000);
    return json({ error: `Too many tries. Please wait ${mins} minute${mins === 1 ? '' : 's'} and try again.` }, 429);
  }
  let users = await getUsers(env);
  // First time only: the owner login comes from the two settings ADMIN_EMAIL and ADMIN_PASSWORD.
  if (users.length === 0 && env.ADMIN_EMAIL && env.ADMIN_PASSWORD && email === normEmail(env.ADMIN_EMAIL) && pw === env.ADMIN_PASSWORD) {
    users = [{ email, name: 'Jeen', role: 'admin', hash: await hashPassword(pw), sv: 1, must_change: true, created: new Date().toISOString() }];
    await saveUsers(env, users);
  }
  const u = users.find((x) => x.email === email);
  const ok = u ? await verifyPassword(pw, u.hash) : false;
  if (!u || !ok || u.disabled) {
    fail.n += 1;
    if (fail.n >= MAX_FAILS) { fail.until = Date.now() + LOCK_MINUTES * 60000; fail.n = 0; }
    await kset(env, 'fail:' + email, fail);
    return bad();
  }
  if (fail.n || fail.until) await kset(env, 'fail:' + email, { n: 0, until: 0 });
  u.last_login = new Date().toISOString();
  await saveUsers(env, users);
  return respond(JSON.stringify({ ok: true, must_change: !!u.must_change }), 200, { 'Content-Type': 'application/json; charset=utf-8', 'Set-Cookie': await sessionCookie(env, u) });
}

async function changePassword(request, env) {
  const g = postGuard(request); if (g) return g;
  const me = await getSession(request, env);
  if (!me) return json({ error: 'Not signed in.' }, 401);
  const b = await body(request);
  if (!(await verifyPassword(String(b.current || ''), me.hash))) return json({ error: 'Your current password is not right.' }, 400);
  const p = passwordProblem(b.next, me.email);
  if (p) return json({ error: p }, 400);
  if (b.next === b.current) return json({ error: 'Please choose a new password, not the same one.' }, 400);
  const users = await getUsers(env);
  const u = users.find((x) => x.email === me.email);
  u.hash = await hashPassword(b.next); u.must_change = false; u.sv = (u.sv || 1) + 1;
  await saveUsers(env, users);
  return respond(JSON.stringify({ ok: true }), 200, { 'Content-Type': 'application/json; charset=utf-8', 'Set-Cookie': await sessionCookie(env, u) });
}

async function users(request, env) {
  const me = await getSession(request, env);
  if (!me) return json({ error: 'Not signed in.' }, 401);
  if (me.must_change) return json({ error: 'Please change your password first.' }, 403);
  if (me.role !== 'admin') return json({ error: 'Admins only.' }, 403);
  const list = await getUsers(env);
  if (request.method === 'GET') return json({ users: list.map(publicUser) });
  if (!['POST', 'PUT', 'DELETE'].includes(request.method)) return json({ error: 'Method not allowed.' }, 405);
  const g = postGuard(request); if (g) return g;
  const b = await body(request);
  const email = normEmail(b.email);

  if (request.method === 'POST') {
    if (!validEmail(email)) return json({ error: 'That email does not look right.' }, 400);
    if (list.some((x) => x.email === email)) return json({ error: 'That person already has a login.' }, 400);
    const role = ROLES.includes(b.role) ? b.role : 'viewer';
    const name = String(b.name || '').trim().slice(0, 60) || email.split('@')[0];
    const temp = tempPassword();
    list.push({ email, name, role, hash: await hashPassword(temp), sv: 1, must_change: true, created: new Date().toISOString() });
    await saveUsers(env, list);
    return json({ ok: true, temp });
  }
  const u = list.find((x) => x.email === email);
  if (!u) return json({ error: 'No such person.' }, 404);
  const lastAdmin = u.role === 'admin' && !u.disabled && list.filter((x) => x.role === 'admin' && !x.disabled).length === 1;

  if (request.method === 'DELETE') {
    if (u.email === me.email) return json({ error: 'You cannot remove your own login.' }, 400);
    if (lastAdmin) return json({ error: 'At least one admin must stay.' }, 400);
    await saveUsers(env, list.filter((x) => x.email !== email));
    return json({ ok: true });
  }
  if (b.action === 'reset') {
    const temp = tempPassword();
    u.hash = await hashPassword(temp); u.must_change = true; u.sv = (u.sv || 1) + 1;
    await saveUsers(env, list);
    return json({ ok: true, temp });
  }
  if (b.action === 'disable') {
    if (u.email === me.email) return json({ error: 'You cannot turn off your own login.' }, 400);
    if (lastAdmin) return json({ error: 'At least one admin must stay.' }, 400);
    u.disabled = true; u.sv = (u.sv || 1) + 1;
  } else if (b.action === 'enable') {
    u.disabled = false;
  } else if (b.action === 'role') {
    if (!ROLES.includes(b.role)) return json({ error: 'Unknown role.' }, 400);
    if (lastAdmin && b.role !== 'admin') return json({ error: 'At least one admin must stay.' }, 400);
    u.role = b.role;
  } else return json({ error: 'Unknown action.' }, 400);
  await saveUsers(env, list);
  return json({ ok: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    try {
      if (path === '/api/login' && request.method === 'POST') return await login(request, env);
      if (path === '/api/logout' && request.method === 'POST') {
        const g = postGuard(request); if (g) return g;
        return respond(JSON.stringify({ ok: true }), 200, { 'Content-Type': 'application/json; charset=utf-8', 'Set-Cookie': clearedCookie() });
      }
      if (path === '/api/password' && request.method === 'POST') return await changePassword(request, env);
      if (path === '/api/me') {
        const u = await getSession(request, env);
        return u ? json(publicUser(u)) : json({ error: 'Not signed in.' }, 401);
      }
      if (path === '/api/users') return await users(request, env);
      if (path === '/api/data') {
        const u = await getSession(request, env);
        if (!u || u.must_change) return json({ error: 'Not signed in.' }, 401);
        const id = url.searchParams.get('id');
        return Object.prototype.hasOwnProperty.call(DATA, id) ? json(DATA[id]) : json({ error: 'Unknown data.' }, 404);
      }
      if (path === '/' || path === '/admin') {
        const u = await getSession(request, env);
        if (!u) return redirect('/login');
        if (u.must_change) return redirect('/login?change=1');
        if (path === '/admin') return u.role === 'admin' ? html(adminHtml) : redirect('/');
        return html(dashboardHtml.replace('__EMAIL__', esc(u.email)).replace('__NAME__', esc(u.name))
          .replace('__ADMIN_LINK__', u.role === 'admin' ? '<a href="/admin">Manage logins</a>' : ''));
      }
      if (path.startsWith('/api/')) return json({ error: 'Not found.' }, 404);
      return env.ASSETS.fetch(request);
    } catch (e) {
      if (path === '/' || path === '/admin') return html('<p style="font-family:sans-serif">The app is not fully set up yet. Please see the setup guide.</p>', 503);
      return problem(e);
    }
  },
};
