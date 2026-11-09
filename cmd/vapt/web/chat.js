// KAVACH console. The conversation is the interface: plans, approvals, findings and proof are cards inside it.
// Every piece of dynamic text is set with textContent / text nodes. Tool output, banners and model text are untrusted data.
import { initMenu } from './menu.js';

const $ = (id) => document.getElementById(id);
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') e.className = v;
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) e.addEventListener(ev, fn);
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const k of kids.flat(2)) if (k != null && k !== false) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
}
const NS = 'http://www.w3.org/2000/svg';
const ICON = {
  check: 'M5 12.5l4.5 4.5L19 7.5', x: 'M6 6l12 12M18 6L6 18', chev: 'M6 9l6 6 6-6', doc: 'M7 3h7l5 5v13H7zM14 3v5h5M10 13h6M10 17h6',
  alert: 'M12 3l10 18H2zM12 10v5M12 18v.5', shield: 'M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z',
};
function ic(name, size = 16) {
  const v = document.createElementNS(NS, 'svg'); v.setAttribute('viewBox', '0 0 24 24'); v.setAttribute('width', size); v.setAttribute('height', size); v.setAttribute('aria-hidden', 'true'); v.setAttribute('class', 'ic');
  const p = document.createElementNS(NS, 'path'); p.setAttribute('d', ICON[name]); v.append(p); return v;
}
const csv = (s) => String(s || '').split(/[,\s;]+/).map((x) => x.trim()).filter(Boolean);
const fmtT = (t) => (t ? new Date(t).toLocaleTimeString([], { hour12: false }) : '');
const hostShort = (t) => String(t || '').replace(/^https?:\/\//, '');
const pct = (x) => Math.round((x || 0) * 100);
const cap = (s) => String(s || '').replace(/_/g, ' ');
const store = {
  get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { sessionStorage.setItem(k, v); } catch { /* private mode */ } },
  del(k) { try { sessionStorage.removeItem(k); } catch { /* private mode */ } },
};
// The scope-form fields live in a popover that stays in the page, but cache them anyway so no later DOM change can null them.
const FI = Object.fromEntries(['f-name', 'f-auth', 'f-targets', 'f-authdom', 'f-excl', 'f-hosts', 'f-active', 'f-exploit'].map((i) => [i, $(i)]));

const S = {
  token: '', cfg: null, user: null, seen: '', id: '', snap: null, timer: 0, proofId: '', proofSig: '', proofHi: '',
  pending: null, fresh: true, asking: false, extra: new Map(), locals: [], showAll: false, auditN: -1, auditE: [], busy: false, open: new Map(), recentSig: '',
};
const PHASE = { planning: 'Planning', awaiting_approval: 'Waiting for approval', running: 'Running', analysing: 'Analysing', review: 'Complete', done: 'Stopped' };
const ACTIVE = new Set(['planning', 'running', 'analysing']);
const VERB = { portscan: 'Port scan', webcheck: 'Web checks', nmap: 'nmap', nikto: 'nikto', zap: 'ZAP scan', nessus: 'Nessus import', openvas: 'OpenVAS import', burp: 'Burp import', metasploit: 'Metasploit check' };

async function api(path, opts = {}) {
  const o = Object.assign({ headers: {} }, opts);
  o.headers['X-VAPT-Token'] = S.token;
  if (o.json !== undefined) { o.headers['content-type'] = 'application/json'; o.body = JSON.stringify(o.json); o.method = o.method || 'POST'; }
  const r = await fetch(path, o); const t = await r.text(); let d; try { d = JSON.parse(t); } catch { d = { raw: t }; }
  if (r.status === 401) { sessionEnded(); throw new Error('Your session ended. Sign in again.'); }
  if (!r.ok) throw new Error(d.error || r.statusText);
  return d;
}

// ------------------------------------------------------------------ sign-in
// KAVACH keeps its own accounts. The server sets an HttpOnly session cookie; the page holds no secret. Who you are comes from
// that session, never from a field in a request, so an approval is always recorded under the account that made it.
let gateMode = 'login', gateBusy = false;
const GATE = {
  login: { h: 'Sign in', p: 'Every approval and denial is recorded in the tamper-evident audit log under your account.', go: 'Sign in', busy: 'Signing inâ€¦', note: 'Sessions end after 2 hours without activity.' },
  setup: { h: 'Create your account', p: 'This is the first run, so this account becomes the administrator. It is stored only on this machine, and the password is kept as a salted hash.', go: 'Create account', busy: 'Creatingâ€¦', note: 'At least 10 characters, and not your username or a common word.' },
};
function gateErr(msg) { const e = $('g-err'); e.textContent = msg || ''; e.hidden = !msg; }
function setLocked(on) { $('side').inert = on; $('main').inert = on; }
function showGate(msg, mode) {
  if (mode) gateMode = mode;
  const g = GATE[gateMode], setup = gateMode === 'setup';
  closeAcct(); palClose();
  $('g-h').textContent = g.h; $('g-p').textContent = g.p; $('g-go').textContent = g.go; $('g-note').textContent = g.note;
  $('g-pw').autocomplete = setup ? 'new-password' : 'current-password';
  $('g-pw2-l').hidden = !setup; $('g-disp-l').hidden = !setup;
  $('g-pw').value = ''; $('g-pw2').value = ''; gateErr(msg);
  setLocked(true); $('gate').hidden = false;
  setTimeout(() => $($('g-name').value ? 'g-pw' : 'g-name').focus(), 30);
}
function hideGate() { $('gate').hidden = true; setLocked(false); }
$('g-eye').addEventListener('click', () => {
  const show = $('g-pw').type === 'password';
  $('g-pw').type = show ? 'text' : 'password'; $('g-pw2').type = $('g-pw').type;
  $('g-eye').setAttribute('aria-pressed', String(show)); $('g-eye').setAttribute('aria-label', show ? 'Hide password' : 'Show password');
});
$('g-form').addEventListener('submit', async (e) => {
  e.preventDefault(); if (gateBusy) return;
  const setup = gateMode === 'setup', name = $('g-name').value.trim(), pw = $('g-pw').value;
  if (!name || !pw) { gateErr('Enter your username and password.'); return; }
  if (setup && pw !== $('g-pw2').value) { gateErr('The two passwords do not match.'); $('g-pw2').focus(); return; }
  gateBusy = true; $('g-go').disabled = true; $('g-go').textContent = GATE[gateMode].busy; gateErr('');
  try {
    const r = await fetch(setup ? '/api/auth/setup' : '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(setup ? { name, display: $('g-disp').value.trim(), password: pw } : { name, password: pw }) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { gateErr(d.error || 'Could not sign in.'); $('g-pw').value = ''; $('g-pw2').value = ''; $('g-pw').focus(); return; }
    S.user = d.user; $('g-pw').value = ''; $('g-pw2').value = ''; hideGate(); await enter();
  } catch { gateErr('Could not reach the KAVACH server. Is it still running?'); }
  finally { gateBusy = false; $('g-go').disabled = false; $('g-go').textContent = GATE[gateMode].go; }
});
const who = () => (S.user && S.user.name) || 'analyst';
const shown = () => (S.user && S.user.display) || who();
async function authStatus() { try { return await (await fetch('/api/auth/status', { cache: 'no-store' })).json(); } catch { return null; } }
function sessionEnded(msg) {
  clearTimeout(S.timer);
  if (!$('gate').hidden) return;
  authStatus().then((st) => showGate(msg || 'Your session ended. Sign in to carry on.', st && st.setup_required ? 'setup' : 'login'));
}
async function signOut() {
  try { await fetch('/api/auth/logout', { method: 'POST' }); } catch { /* the server may already be gone */ }
  store.del('vapt-chat-aid'); store.set('vapt-out', '1'); location.reload();
}

// ------------------------------------------------------------------ boot
async function boot() {
  const st = await authStatus();
  if (!st) { showGate('Could not reach the KAVACH server. Is it still running?', 'login'); return; }
  if (!st.user) { const out = store.get('vapt-out'); store.del('vapt-out'); showGate(out ? 'You are signed out.' : '', st.setup_required ? 'setup' : 'login'); return; }
  S.user = st.user; await enter();
}
let entered = false;
async function enter() {
  const r = await fetch('/api/config', { cache: 'no-store' });
  if (r.status === 401) { sessionEnded(); return; }
  S.cfg = await r.json(); S.token = S.cfg.token; badges();
  if (S.seen && S.seen !== S.user.name) { store.del('vapt-chat-aid'); resetState(); S.id = ''; showEmpty(true); } // another account signed in on this tab: do not show them the previous thread
  S.seen = S.user.name;
  $('w-name').textContent = shown(); $('w-auth').textContent = S.user.role; $('w-av').textContent = shown().slice(0, 1).toUpperCase();
  const h = new Date().getHours(), g = h < 5 ? 'Working late' : h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
  $('e-h').textContent = `${g}, ${shown()}`; $('cmd').placeholder = 'What should we assess?';
  scopeSum();
  if (entered) { if (S.id) { await poll(); schedule(); } return; }
  entered = true;
  const aid = store.get('vapt-chat-aid');
  if (aid) { S.id = aid; await poll(); if (!S.snap) { S.id = ''; store.del('vapt-chat-aid'); } }
  if (!S.id) showEmpty(true);
  loadRecent(); schedule(); labLoop();
}
function badges() {
  const m = String(S.cfg.model || ''), rules = /rules-only/.test(m), p = $('b-model');
  $('b-model-t').textContent = rules ? 'No model Â· rules only' : m.replace(/^openai-compatible:/, '');
  if (rules) { p.className = 'pill ok'; p.title = 'Rules-only mode: nothing leaves this machine.'; }
  else if (S.cfg.data_leaves_machine) { p.className = 'pill warn'; p.title = 'Remote model: assessment evidence is sent to it when you chat.'; }
  else { p.className = 'pill ok'; p.title = 'Local model: assessment data stays on this machine.'; }
}

// ------------------------------------------------------------------ empty state and scope
const form = () => ({ name: FI['f-name'].value, auth: FI['f-auth'].value, targets: FI['f-targets'].value, authdom: FI['f-authdom'].value, excl: FI['f-excl'].value, hosts: FI['f-hosts'].value, active: FI['f-active'].checked, exploit: FI['f-exploit'].checked });
function scopeSum() {
  if (S.id) return;
  const f = form(), nx = csv(f.excl).length;
  $('sc-sum').textContent = `Scope: ${f.targets || 'none'}${nx ? ` Â· ${nx} excluded` : ''} Â· ${f.active ? 'active scans on' : 'passive only'}`;
}
Object.values(FI).forEach((i) => i.addEventListener('input', scopeSum));
const scopeBtn = $('scope-btn');
function scopePop(on) { if (S.id) on = false; $('scope-pop').hidden = !on; scopeBtn.setAttribute('aria-expanded', String(on)); }
scopeBtn.addEventListener('click', () => scopePop($('scope-pop').hidden));
const CHIPS = [
  ['Quick scan of the lab host', 'Assess the lab host 127.0.0.1: network exposure and web configuration. Keep it quick.'],
  ['Thorough network and web review', 'Do a thorough network and web assessment of 127.0.0.1, including an active scan if the tools are available.'],
  ['See an out-of-scope request refused', 'Assess 127.0.0.1 and also 8.8.8.8'],
];
CHIPS.forEach(([t, v]) => $('chips').append(el('button', { class: 'chip', type: 'button', on: { click: () => { $('cmd').value = v; autosize(); $('cmd').focus(); } } }, t)));
const emptyEl = $('empty'), labLine = $('lab-t');
let labTimer = 0;
async function labCheck() {
  if (!/127\.0\.0\.1|localhost/.test(FI['f-hosts'].value)) { labLine.textContent = ''; return; }
  try {
    const res = await fetch('/api/lab-status', { cache: 'no-store' }); if (!res.ok) { labLine.textContent = ''; return; }
    const r = await res.json();
    const n = (r.web || []).length + (r.ftp || []).length + (r.telnet || []).length;
    labLine.className = 'e-lab ' + (n ? 'ok' : 'warn');
    labLine.textContent = n ? `Lab is up: web ${(r.web || []).join(', ') || 'none'}, ftp ${(r.ftp || []).join(', ') || 'none'}, telnet ${(r.telnet || []).join(', ') || 'none'}` : 'The lab is not running. In another terminal, run  go run ./cmd/lab';
  } catch { labLine.textContent = ''; }
}
function labLoop() { labCheck(); clearInterval(labTimer); labTimer = setInterval(() => { if (!document.hidden && !S.id) labCheck(); }, 6000); }
function showEmpty(on) {
  document.body.classList.toggle('is-empty', on);
  if (on) { if (!emptyEl.isConnected) $('thread').prepend(emptyEl); $('t-title').textContent = 'New assessment'; } else emptyEl.remove();
}

// ------------------------------------------------------------------ sending
async function send(text) {
  text = text.trim(); if (!text || S.busy) return;
  S.busy = true; $('send').disabled = true;
  try { if (!S.id) await startAssessment(text); else await ask(text); } catch (e) { local({ kind: 'error', text: e.message }); }
  S.busy = false; $('send').disabled = false;
}
function showBatchReports(items) {
  const box = $('batch-reports');
  if (!box) return;

  box.replaceChildren();
  box.hidden = !items.length;

  items.forEach((item) => {
    const link = document.createElement('a');
    link.href = `/api/assessments/${encodeURIComponent(item.id)}/report.pdf`;
    link.textContent = `${item.host} — PDF report`;
    link.style.display = 'block';
    link.style.margin = '7px 0';
    link.style.color = 'var(--accent, #65b5ff)';
    link.style.textDecoration = 'underline';
    box.append(link);
  });
}

async function startAssessment(text) {
  const f = form();
  const authorization = String(f.auth || '').trim();

  if (!authorization) {
    throw new Error('Replace the default authorization placeholder with the actual organiser-issued reference before starting.');
  }

  const domains = [
    'www.hackthecore.in',
    'dataops.co.in'
  ];

  const exclusions = csv(f.excl);
  const created = [];

  try {
    scopePop(false);

    for (const host of domains) {
      const body = {
        name: `${f.name || 'Assessment'} - ${host}`,
        authorization,
        request: text,
        targets: [host],
        hosts: [host],
        authorized_domains: [host],
        exclusions,
        allow_active: f.active,
        allow_exploit: f.exploit,
        max_req_per_sec: 0
      };

      const result = await api('/api/assessments', { json: body });

      if (!result.id) {
        throw new Error(`Server did not return an assessment ID for ${host}.`);
      }

      created.push({ host, id: result.id });
      showBatchReports(created);

      if (created.length === 1) {
        S.id = result.id;
        store.set('vapt-chat-aid', S.id);
        S.showAll = false;
        $('cmd').value = '';
        autosize();
        showEmpty(false);
      }

      await api(`/api/assessments/${result.id}/start`, { json: {} });
    }

    await poll();
    loadRecent();
    schedule();

  } catch (error) {
    showBatchReports(created);

    if (created.length) {
      S.id = created[0].id;
      store.set('vapt-chat-aid', S.id);
      await poll().catch(() => {});
      loadRecent();

      throw new Error(
        `${created.length} of ${domains.length} assessment(s) created. ` +
        `Check the recent assessments and report links. ${error.message}`
      );
    }

    throw error;
  }
}async function ask(text) {
  const base = ((S.snap && S.snap.assessment.messages) || []).length;
  const pend = el('div', { class: 'turn user' }, el('div', { class: 'bub' }, text));
  S.pending = { text, base, node: pend }; $('cmd').value = ''; autosize(); S.asking = true;
  $('thread').append(pend); thinking(); toEnd(true);
  try {
    const r = await api(`/api/assessments/${S.id}/chat`, { json: { message: text } });
    S.extra.set(r.reply, { suggest: r.suggest || [], rejected: r.rejected || '', verified: r.verified || [], source: r.source });
  } finally { S.asking = false; if (S.pending && S.pending.node) S.pending.node.remove(); S.pending = null; }
  await poll();
}
$('composer').addEventListener('submit', (e) => { e.preventDefault(); send($('cmd').value); });
$('cmd').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); send($('cmd').value); } });
function autosize() { const c = $('cmd'); c.style.height = 'auto'; c.style.height = Math.min(200, c.scrollHeight) + 'px'; }
$('cmd').addEventListener('input', autosize);

// ------------------------------------------------------------------ polling
function schedule() {
  clearTimeout(S.timer);
  const a = S.snap && S.snap.assessment;
  const ms = !S.id ? 0 : (a && (ACTIVE.has(a.phase) || S.asking)) ? 1000 : 2600;
  if (ms) S.timer = setTimeout(async () => { await poll(); schedule(); }, ms);
}
async function poll() {
  if (!S.id) return;
  let snap;
  try { snap = await api(`/api/assessments/${S.id}`); } catch (e) { if (/unknown/.test(e.message)) S.snap = null; return; }
  S.snap = snap; render(); loadRecent();
}

// ------------------------------------------------------------------ keyed reconciliation of the thread
const nodes = new Map(), TAIL = ['findings', 'report'];
function upsert(key, data, build) {
  const sig = JSON.stringify(data), n = nodes.get(key);
  if (n && n.sig === sig) return;
  if (n && n.el.dataset.hold === '1') return; // never rebuild a card while the analyst is holding its button
  const fresh = build(data); fresh.dataset.key = key;
  if (n) { fresh.classList.add('still'); n.el.replaceWith(fresh); n.el = fresh; n.sig = sig; }
  else { nodes.set(key, { el: fresh, sig }); $('thread').append(fresh); }
}
function drop(key) { const n = nodes.get(key); if (n) { n.el.remove(); nodes.delete(key); } }
function resetThread() { nodes.forEach((n) => n.el.remove()); nodes.clear(); }
const near = () => { const s = $('scroll'); return s.scrollTop + s.clientHeight >= s.scrollHeight - 140; };
function toEnd(force) { if (force) { const s = $('scroll'); s.scrollTop = s.scrollHeight; } }

function render() {
  const a = S.snap.assessment, wasNear = near();
  showEmpty(false);
  $('t-title').textContent = a.request.length > 90 ? a.request.slice(0, 90) + 'â€¦' : a.request;
  scopeBtn.classList.add('locked'); scopePop(false);
  $('sc-sum').textContent = 'In scope: ' + ((a.scope.targets || []).join(', ') || 'nothing');
  upsert('req', { t: a.request }, () => userTurn(a.request));
  upsert('scope', { h: a.hosts, r: refused(a), s: a.scope.targets, x: a.scope.exclusions }, () => scopeCard(a));
  const steps = a.steps || [], rounds = [...new Set(steps.map((s) => s.round))].sort((x, y) => x - y), last = rounds[rounds.length - 1];
  rounds.forEach((r) => {
    const mine = steps.filter((s) => s.round === r), cur = r === last;
    upsert('plan:' + r, { r, mine, ph: a.phase, cur, ev: cur ? (a.events || []).slice(-12) : null, lim: cur ? a.limitations : null, who: who() }, () => planCard(a, r, mine, cur));
  });
  if (a.messages && S.pending && a.messages.length > S.pending.base) { if (S.pending.node) S.pending.node.remove(); S.pending.node = null; }
  (a.messages || []).forEach((m, i) => upsert('msg:' + i, { m, x: S.extra.get(m.text) || null }, () => (m.role === 'analyst' ? userTurn(m.text) : agentTurn(m))));
  (a.approvals || []).forEach((p) => upsert('apv:' + p.id, { p, who: who() }, () => approvalCard(p)));
  S.locals.forEach((l, i) => upsert('loc:' + i, l, () => localCard(l)));
  const fs = a.findings || [];
  if (fs.length) upsert('findings', { f: fs.map((f) => [f.id, f.severity, f.status, f.confidence, f.validation, f.risk && f.risk.score]), all: S.showAll }, () => findingsCard(a)); else drop('findings');
  if (fs.length && (a.phase === 'review' || a.phase === 'done')) upsert('report', { id: S.id, n: fs.length }, () => reportCard()); else drop('report');
  // Findings and the report belong right after the run that produced them. Until the analyst starts chatting they sit at the
  // end; once they do, they stay where they are so replies always read top to bottom. A reloaded conversation puts them
  // just before the first analyst message.
  const th = $('thread'), tail = TAIL.map((k) => nodes.get(k)).filter(Boolean).map((n) => n.el), kids = [...th.children].slice(-tail.length);
  const firstAsk = (a.messages || []).findIndex((m) => m.role === 'analyst'), anchor = firstAsk >= 0 ? nodes.get('msg:' + firstAsk) : null;
  if (!anchor) { if (tail.length && !tail.every((n, i) => kids[i] === n)) tail.forEach((n) => th.append(n)); }
  else if (S.fresh) tail.forEach((n) => anchor.el.before(n));
  S.fresh = false;
  if (S.pending && S.pending.node && !S.pending.node.isConnected) th.append(S.pending.node);
  side(a); thinking();
  if (S.proofId) refreshProof(a);
  if (wasNear) toEnd(true);
}
function refused(a) {
  const set = new Set();
  (a.events || []).forEach((e) => { const m = /REFUSED target (\S+?):/.exec(e.text) || /Scope probe (\S+?): REFUSED/.exec(e.text); if (m) set.add(m[1]); });
  return [...set];
}

// ------------------------------------------------------------------ turns and cards
function refify(text) {
  const out = [];
  String(text).split(/(F-\d{3}|E-\d{4}|S-\d{2})/g).forEach((p) => {
    if (/^(F-\d{3}|E-\d{4}|S-\d{2})$/.test(p)) out.push(el('button', { class: 'ref', type: 'button', on: { click: () => gotoRef(p) } }, p));
    else if (p) out.push(p);
  });
  return out;
}
function gotoRef(id) {
  const a = S.snap && S.snap.assessment; if (!a) return;
  if (id[0] === 'F') openProof(id);
  else if (id[0] === 'E') { const f = (a.findings || []).find((x) => (x.evidence || []).includes(id)); if (f) openProof(f.id, id); }
  else { const n = document.querySelector(`[data-step="${id}"]`); if (n) { const d = n.closest('details'); if (d) d.open = true; n.scrollIntoView({ block: 'center', behavior: 'smooth' }); n.classList.add('flash'); setTimeout(() => n.classList.remove('flash'), 1500); } }
}
const userTurn = (text) => el('div', { class: 'turn user' }, el('div', { class: 'bub' }, text));
function agentTurn(m) {
  const x = S.extra.get(m.text), src = m.source || '', bd = el('div', { class: 'turn agent' }, el('div', { class: 'tx' }, refify(m.text)));
  if (src.startsWith('model:')) bd.append(el('div', { class: 'src ok' }, ic('check', 14), `Checked against this assessment (${src.slice(6).replace(/^openai-compatible:/, '')}). Every finding, evidence, step and CVE reference exists.`));
  else if (src === 'rules') bd.append(el('div', { class: 'src' }, 'Answered from stored data by code. No model was involved.'));
  if (x && x.rejected) bd.append(el('div', { class: 'src warn' }, ic('alert', 14), 'A model answer was discarded and logged: ' + x.rejected + '.'));
  if (x && x.suggest && x.suggest.length) bd.append(el('div', { class: 'sugs' }, x.suggest.map((s) => el('button', { class: 'chip sug', type: 'button', on: { click: () => { $('cmd').value = s; autosize(); $('cmd').focus(); } } }, s))));
  return bd;
}
function card(cls, title, meta, ...body) {
  return el('section', { class: 'card ' + (cls || '') }, title ? el('div', { class: 'ch' }, el('h3', {}, title), meta ? (meta.nodeType ? meta : el('span', { class: 'meta' }, meta)) : null) : null, el('div', { class: 'cb' }, body));
}
const badge = (txt, kind) => el('span', { class: 'badge ' + (kind || '') }, txt);
function scopeCard(a) {
  const rf = refused(a), tg = (a.scope.targets || []).join(', '), ex = a.scope.exclusions || [];
  return card('', 'Scope check', badge(rf.length ? `${rf.length} refused` : 'All in scope', rf.length ? 'bad' : 'ok'),
    el('div', { class: 'scopeline' }, ...(a.hosts || []).map((h) => el('span', { class: 'tag' }, ic('check', 12), h)), ...rf.map((h) => el('span', { class: 'tag no' }, h))),
    el('div', { class: 'note' }, `Authorised: ${tg || 'nothing'}${ex.length ? '. Excluded: ' + ex.join(', ') : ''}. Scope is deny-by-default, and the guard checks every step again just before it runs.`),
    rf.length ? el('div', { class: 'note' }, 'Refused targets received no traffic. Each refusal is a block in the audit chain.') : null);
}
function stIcon(s) {
  const k = s.status === 'done' ? 'done' : ['failed', 'blocked', 'declined'].includes(s.status) ? 'bad' : s.status === 'running' ? 'run' : '';
  const i = el('span', { class: 'st-ic ' + k }); if (k === 'done') i.append(ic('check', 12)); if (k === 'bad') i.append(ic('x', 12)); return i;
}
function planCard(a, r, mine, cur) {
  const waiting = cur && a.phase === 'awaiting_approval', prop = mine.filter((s) => s.status === 'proposed'), done = mine.filter((s) => s.status === 'done').length;
  const open = waiting || (S.open.has(r) ? S.open.get(r) : cur);
  const d = el('details', Object.assign({ class: 'card plan' }, open ? { open: '' } : {}),
    el('summary', {}, el('h3', {}, `Plan, round ${r + 1}`), el('span', { class: 'meta' }, `${done} of ${mine.length} steps done`), el('span', { class: 'chev' }, ic('chev', 18))));
  d.addEventListener('toggle', () => S.open.set(r, d.open));
  const cb = el('div', { class: 'cb' }, el('div', { class: 'note' }, 'Each step was checked against the scope guard before it was proposed. The reasons are the agentâ€™s own; the guard verdicts are code.'), ...mine.map(stepRow));
  if (waiting && prop.length) cb.append(approvalBlock(a, r, prop));
  if (cur) {
    const ev = (a.events || []).slice(-12);
    if (ev.length) cb.append(el('details', Object.assign({ class: 'lg' }, ACTIVE.has(a.phase) ? { open: '' } : {}), el('summary', {}, 'Activity'), el('div', { class: 'log' }, ev.map((e) => el('div', { class: e.level }, el('span', {}, fmtT(e.time)), el('span', {}, e.level === 'decision' ? [el('b', {}, 'Decision '), e.text] : e.text))))));
    (a.limitations || []).forEach((l) => cb.append(el('div', { class: 'src warn' }, ic('alert', 14), l)));
  }
  d.append(cb); return d;
}
function stepRow(s) {
  const g = s.guard ? (s.guard.allowed === false ? 'refused' : 'allowed') : 'unknown', dur = s.ended && s.started && s.status !== 'running' ? ` Â· ${Math.max(0, new Date(s.ended) - new Date(s.started))} ms` : '';
  const raw = (s.raw_file || '').split('/').pop();
  return el('div', { class: 'step', 'data-step': s.id }, stIcon(s),
    el('div', { class: 't1' }, VERB[s.tool] || s.tool, ' ', el('em', {}, 'on ' + hostShort(s.target))), el('span', { class: 'sid' }, s.id),
    el('div', { class: 'why' }, s.rationale || ''),
    el('div', { class: 'meta' }, `${cap(s.status)}${dur} Â· guard ${g}${s.guard && s.guard.reason ? ' (' + s.guard.reason + ')' : ''} Â· proposed by ${s.proposed_by}${(s.trigger_evidence || []).length ? ' Â· because ' : ''}`, ...(s.trigger_evidence || []).flatMap((id, i) => [i ? ', ' : '', el('button', { class: 'ref', type: 'button', on: { click: () => gotoRef(id) } }, id)])),
    s.summary ? el('div', { class: 'meta' }, s.summary, raw ? ' Â· ' : '', raw ? el('a', { href: `/api/assessments/${S.id}/raw/${raw}`, target: '_blank', rel: 'noopener' }, 'raw output') : null, s.raw_sha256 ? ' Â· sha256 ' + s.raw_sha256.slice(0, 12) + 'â€¦' : '') : null,
    s.error ? el('div', { class: 'err' }, s.error) : null);
}

// Hold-to-approve: one second of deliberate pressure. Deny asks twice. The card is not rebuilt while the button is held.
function approvalBlock(a, r, prop) {
  const one = prop.length === 1 ? prop[0] : null;
  const head = one ? `${VERB[one.tool] || one.tool} on ${hostShort(one.target)}` : `${prop.length} steps: ${[...new Set(prop.map((s) => VERB[s.tool] || s.tool))].join(', ')}`;
  const sc = a.scope || {}, chks = [];
  chks.push('In scope: ' + (sc.targets || []).join(', '));
  chks.push((sc.exclusions || []).length ? 'Not excluded (' + sc.exclusions.join(', ') + ')' : 'No exclusions hit');
  chks.push(prop.some((s) => /active/.test((s.guard && s.guard.reason) || '')) ? 'Active scan permitted by scope' : 'Passive only');
  let t0 = 0, raf = 0, root = null;
  const fill = el('span', { class: 'fill' }), hold = el('button', { class: 'hold', type: 'button', 'aria-label': 'Hold for one second to approve this plan' }, fill, el('span', { class: 'lab' }, 'Hold to approve'));
  const stop = () => { t0 = 0; cancelAnimationFrame(raf); hold.style.setProperty('--p', 0); if (root) delete root.dataset.hold; };
  const start = () => {
    if (t0) return; root = hold.closest('.card'); if (root) root.dataset.hold = '1'; t0 = performance.now();
    const tick = () => { const p = Math.min(1, (performance.now() - t0) / 1000); hold.style.setProperty('--p', p); if (p >= 1) { stop(); doApprove(); return; } raf = requestAnimationFrame(tick); };
    tick();
  };
  hold.addEventListener('pointerdown', (e) => { e.preventDefault(); start(); });
  ['pointerup', 'pointerleave', 'pointercancel', 'blur'].forEach((n) => hold.addEventListener(n, stop));
  hold.addEventListener('keydown', (e) => { if ((e.key === ' ' || e.key === 'Enter') && !e.repeat) { e.preventDefault(); start(); } });
  hold.addEventListener('keyup', stop);
  let arm = 0; const deny = el('button', { class: 'deny', type: 'button' }, 'Deny');
  deny.addEventListener('click', async () => {
    if (!arm) { arm = setTimeout(() => { arm = 0; deny.textContent = 'Deny'; }, 3500); deny.textContent = 'Click again to deny'; return; }
    clearTimeout(arm); arm = 0;
    try { await api(`/api/assessments/${S.id}/deny`, { json: { reason: 'denied in console' } }); await poll(); } catch (e) { local({ kind: 'error', text: e.message }); }
  });
  async function doApprove() { try { await api(`/api/assessments/${S.id}/approve`, { json: {} }); await poll(); schedule(); } catch (e) { local({ kind: 'error', text: e.message }); } }
  return el('div', { class: 'apv' }, el('h4', {}, 'Approve this plan? Nothing runs until you do.'),
    el('div', { class: 'note' }, `${head}. Signed as ${who()}.`),
    el('div', { class: 'cmds' }, prop.map((s) => `${s.tool}  ${hostShort(s.target)}  ${s.options && Object.keys(s.options).length ? JSON.stringify(s.options) : ''}`).join('\n')),
    el('div', { class: 'chks' }, chks.map((t) => el('span', { class: 'tag' }, ic('check', 12), t))),
    el('div', { class: 'acts' }, hold, deny, el('span', { class: 'rel' }, 'Release early to cancel.')));
}

function approvalCard(p) {
  const meta = badge(cap(p.status), p.status === 'approved' ? 'ok' : p.status === 'pending' ? 'warn' : 'bad');
  const info = el('div', { class: 'note' }, `${p.module} against ${p.target} for `, el('button', { class: 'ref', type: 'button', on: { click: () => gotoRef(p.finding_id) } }, p.finding_id), '. This is a module check only; the agent never exploits.');
  if (p.status !== 'pending') return card('', `Validation ${p.id}`, meta, info, el('div', { class: 'note' }, `${cap(p.status)} by ${p.analyst || '-'}: ${p.reason || ''}`), p.outcome ? el('div', { class: 'src ok' }, ic('check', 14), 'Outcome: ' + p.outcome) : null);
  const reason = el('input', { placeholder: 'Reason (required)' }), conf = el('input', { placeholder: 'Type ' + p.target + ' to confirm' }), err = el('div', { class: 'errline' });
  const decide = (ok) => async () => { try { await api(`/api/assessments/${S.id}/decide`, { json: { approval_id: p.id, approve: ok, reason: reason.value, confirm_target: conf.value } }); await poll(); schedule(); } catch (e) { err.textContent = e.message; } };
  return card('tint', `Approve validation ${p.id}?`, meta, info, el('div', { class: 'apform' }, el('span', {}, 'Signed as'), el('span', { class: 'asme' }, who()), el('span', {}, 'Reason'), reason, el('span', {}, 'Target'), conf,
    el('div', { class: 'row' }, el('button', { class: 'btn pri sm', type: 'button', on: { click: decide(true) } }, 'Approve and run check'), el('button', { class: 'btn sm', type: 'button', on: { click: decide(false) } }, 'Decline'))), err);
}

function findingsCard(a) {
  const fs = [...(a.findings || [])].sort((x, y) => (y.risk && y.risk.score || 0) - (x.risk && x.risk.score || 0)), cnt = {};
  fs.forEach((f) => { cnt[f.severity] = (cnt[f.severity] || 0) + 1; });
  const shown = S.showAll ? fs : fs.slice(0, 6);
  return card('', `${fs.length} finding${fs.length === 1 ? '' : 's'}`, 'Ranked by risk, computed in code',
    el('div', { class: 'sevs' }, ['critical', 'high', 'medium', 'low', 'info'].filter((s) => cnt[s]).map((s) => el('span', { class: 'sev ' + s }, `${s} ${cnt[s]}`))),
    el('div', {}, shown.map((f) => el('button', { class: 'frow', type: 'button', on: { click: () => openProof(f.id) } },
      el('span', { class: 'sev ' + f.severity }, f.severity), el('span', { class: 'ft' }, f.id + '  ' + f.title),
      el('span', { class: 'mini' + (f.confidence < 0.6 ? ' low' : '') }, el('span', { class: 'bar' }, el('i', { style: `width:${pct(f.confidence)}%` })), pct(f.confidence) + '%'),
      el('span', { class: 'fm' }, `${cap(f.status)} Â· ${(f.tools || []).join(', ')} Â· ${(f.assets || []).slice(0, 2).map((x) => x.host + ':' + x.port).join(', ')}`)))),
    el('div', { class: 'acts2' }, fs.length > 6 ? el('button', { class: 'lnk', type: 'button', on: { click: () => { S.showAll = !S.showAll; render(); } } }, S.showAll ? 'Show the top 6' : `Show all ${fs.length}`) : null,
      el('span', { class: 'src' }, 'Select a finding to see its proof. The percentage is an evidence-strength score, not a probability.')));
}
function reportCard() {
  return card('', 'Report ready', badge('PDF', 'soft'),
    el('div', { class: 'note' }, 'Executive summary, methodology and rules of engagement, severity distribution, findings with evidence and confidence, remediation, and limitations. Observed evidence and AI inference are labelled apart.'),
    el('div', { class: 'acts2' }, el('a', { class: 'btn pri sm', href: `/api/assessments/${S.id}/report.pdf`, download: '' }, ic('doc', 16), 'Download PDF'), el('button', { class: 'lnk', type: 'button', on: { click: () => { $('cmd').value = 'Summarise what is most urgent to fix and why'; autosize(); $('cmd').focus(); } } }, 'Ask what to fix first')));
}
function local(l) {
  S.locals.push(l);
  if (S.snap) { render(); return; }
  const i = S.locals.length - 1, n = localCard(l); n.dataset.key = 'loc:' + i; nodes.set('loc:' + i, { el: n, sig: JSON.stringify(l) }); $('thread').append(n); toEnd(true);
}
function localCard(l) {
  if (l.kind === 'error') return card('', 'That did not work', badge('Error', 'bad'), el('div', { class: 'errline' }, l.text));
  if (l.kind === 'guard') return card('', 'Scope check', badge(l.allowed ? 'Allowed' : 'Refused', l.allowed ? 'ok' : 'bad'), el('div', { class: 'scopeline' }, el('span', { class: 'tag' + (l.allowed ? '' : ' no') }, l.target)), el('div', { class: 'note' }, l.reason || ''),
    el('div', { class: 'src' }, l.logged ? 'Written to the audit chain. No traffic was sent.' : 'Dry run against the scope form. No assessment exists yet, so nothing was logged. No traffic was sent.'));
  if (l.kind === 'chain') return card('', 'Audit chain', badge(l.ok ? 'Verified' : 'Broken', l.ok ? 'ok' : 'bad'), el('div', { class: 'note' }, l.text));
  return card('', null, null, l.text);
}
function thinking() {
  const a = S.snap && S.snap.assessment, ph = a && a.phase;
  const txt = S.asking ? 'Reading this assessmentâ€™s evidenceâ€¦' : ph === 'planning' ? 'Planning: choosing tools from your request and the scopeâ€¦' : ph === 'running' ? 'Running approved stepsâ€¦' : ph === 'analysing' ? 'Correlating evidence across toolsâ€¦' : '';
  $('thinking').hidden = !txt; $('th-t').textContent = txt; $('th-stop').hidden = ph !== 'running' || S.asking;
}
$('th-stop').addEventListener('click', () => api(`/api/assessments/${S.id}/stop`, { method: 'POST' }).then(poll).catch((e) => local({ kind: 'error', text: e.message })));

// ------------------------------------------------------------------ sidebar: history, audit ribbon
async function loadRecent() {
  let rows; try { rows = (await api('/api/assessments')).assessments; } catch { return; }
  const sig = JSON.stringify([S.id, rows.map((r) => [r.id, r.phase, r.findings])]); if (sig === S.recentSig) return; S.recentSig = sig;
  const box = $('recent'); box.replaceChildren();
  if (!rows.length) { box.append(el('p', { class: 's-none' }, 'Nothing yet. Start one and it will appear here.')); return; }
  rows.forEach((r) => box.append(el('a', { href: '#', class: r.id === S.id ? 'on' : '', on: { click: (e) => { e.preventDefault(); openAssessment(r.id); } } },
    el('b', {}, r.request.length > 42 ? r.request.slice(0, 42) + 'â€¦' : r.request), el('span', {}, `${PHASE[r.phase] || r.phase} Â· ${r.findings} finding${r.findings === 1 ? '' : 's'}`))));
}
function side(a) {
  const rp = $('l-report'); rp.hidden = !(a.findings || []).length; rp.href = `/api/assessments/${S.id}/report.pdf`;
  chain(S.snap.audit_status, S.snap.audit_count);
}
async function chain(status, count, force) {
  $('r-chain').hidden = false;
  const t = $('r-chain-t'), rb = $('ribbon'), ok = status === 'verified';
  t.textContent = ok ? `Verified by the server Â· ${count} blocks` : `Broken at block ${count}`; t.className = 's-cs ' + (ok ? 'ok' : 'bad'); rb.className = ok ? '' : 'bad';
  if (count === S.auditN && !force) return;
  const prev = S.auditN; S.auditN = count;
  try {
    const r = await api(`/api/assessments/${S.id}/audit`); S.auditE = r.entries || [];
    rb.replaceChildren(); const n = S.auditE.length, step = Math.max(1, Math.ceil(n / 96));
    for (let i = 0; i < n; i += step) { const e = S.auditE[i]; const b = el('i', { title: `#${e.seq} ${e.type} by ${e.actor}\n${String(e.hash).slice(0, 16)}â€¦` }); if (prev >= 0 && i >= prev) b.className = 'fresh'; rb.append(b); }
  } catch { /* the ribbon is decoration; the status line is the truth */ }
}
async function reverify() {
  if (!S.id) return;
  try {
    const r = await api(`/api/assessments/${S.id}/audit`), ok = r.status === 'verified', n = (r.entries || []).length, head = n ? String(r.entries[n - 1].hash).slice(0, 16) : '-';
    local({ kind: 'chain', ok, text: ok ? `The server recomputed every link: ${n} blocks, each hash chained to the one before it. Head ${head}â€¦` : `The server found a break in the chain (${r.status}).` }); await chain(r.status, n, true);
  } catch (e) { local({ kind: 'error', text: e.message }); }
}
$('reverify').addEventListener('click', reverify);

// ------------------------------------------------------------------ proof panel
function showProof(on) { $('proof').hidden = !on; document.body.classList.toggle('proof-on', on); if (!on) { S.proofId = ''; S.proofSig = ''; } }
$('p-x').addEventListener('click', () => showProof(false));
async function openProof(id, hi) { if (!S.id) return; S.proofId = id; S.proofHi = hi || ''; S.proofSig = ''; showProof(true); await loadProof(true); }
function findingSig(a) { const f = (a.findings || []).find((x) => x.id === S.proofId); return f ? JSON.stringify([f.confidence, f.status, f.validation, (f.evidence || []).length, (f.notes || []).length, (a.approvals || []).map((p) => p.status).join()]) : ''; }
function refreshProof(a) { const sg = findingSig(a); if (sg && sg !== S.proofSig) loadProof(false); }
async function loadProof(scroll) {
  const body = $('p-body'); if (scroll) body.replaceChildren(el('div', { class: 'src' }, 'Loading proofâ€¦'));
  try {
    const r = await api(`/api/assessments/${S.id}/proof?finding=${encodeURIComponent(S.proofId)}`);
    S.proofSig = findingSig(S.snap.assessment); body.replaceChildren(...proofView(r.proof[0]));
    if (S.proofHi) { const n = body.querySelector(`[data-ev="${S.proofHi}"]`); if (n) { n.scrollIntoView({ block: 'center' }); n.animate([{ background: 'var(--c-soft)' }, { background: 'transparent' }], { duration: 1600 }); } }
    else if (scroll) body.scrollTop = 0;
  } catch (e) { body.replaceChildren(el('div', { class: 'errline' }, e.message)); }
}
function proofView(p) {
  const a = S.snap.assessment, s = p.strength, low = s.percent < 60, out = [];
  const rawLink = (ref) => { const m = /raw\/([A-Za-z0-9._-]+)/.exec(ref || ''); return m ? el('a', { href: `/api/assessments/${S.id}/raw/${m[1]}`, target: '_blank', rel: 'noopener' }, 'Open raw file') : null; };
  out.push(el('div', { class: 'ph' }, el('div', { class: 'row' }, el('span', { class: 'sev ' + p.severity }, p.severity), badge(cap(p.status), p.status === 'confirmed' ? 'ok' : p.status === 'likely_false_positive' ? 'bad' : 'warn'), badge('Validation: ' + cap(p.validation))),
    el('h2', {}, p.finding + '  ' + p.title), el('div', { class: 'where' }, (p.assets || []).join(' Â· '))));
  out.push(el('div', { class: 'sec' }, el('h3', {}, 'Evidence strength'),
    el('div', { class: 'meter' + (low ? ' low' : '') }, el('div', { class: 'num' }, s.percent + '%'), el('div', { class: 'rt' }, el('div', { class: 'track' }, el('i', { style: `width:${s.percent}%` })), el('div', { class: 'cap' }, `${cap(s.label)}. Basis: ${s.basis}.`))),
    el('p', { class: 'caveat' }, s.caveat), el('h3', { style: 'margin:14px 0 8px' }, 'How it was computed'), el('ol', { class: 'how' }, (s.how_computed || []).map((t) => el('li', {}, t)))));
  out.push(el('div', { class: 'sec' }, el('h3', {}, badge('Observed', 'ok'), el('small', {}, 'verbatim from the tools')),
    (p.observed || []).length ? p.observed.map((o) => el('div', { class: 'ev', 'data-ev': o.evidence }, el('div', { class: 'eh' }, el('b', {}, o.evidence), el('span', {}, o.tool), el('span', {}, o.asset), el('span', {}, fmtT(o.time)), rawLink(o.raw_ref)), el('pre', {}, o.excerpt), el('div', { class: 'ef' }, 'Source ' + o.raw_ref + (o.raw_sha256 ? ' Â· sha256 ' + o.raw_sha256 : '')))) : el('div', { class: 'src warn' }, 'No stored evidence excerpt is attached to this finding.')));
  out.push(el('div', { class: 'sec' }, el('h3', {}, badge('Inferred', 'warn'), el('small', {}, 'reasoning, not observation')),
    (p.inferred || []).length ? p.inferred.map((i) => el('div', { class: 'infer' }, el('div', {}, refify(i.text)), el('div', { class: 'by' }, 'By ' + i.by))) : el('div', { class: 'src' }, 'Nothing is inferred beyond the observations above.')));
  if ((p.missing || []).length) out.push(el('div', { class: 'sec' }, el('h3', {}, badge('Not established', 'bad'), el('small', {}, 'what this record does not prove')), el('div', { class: 'miss' }, p.missing.map((m) => el('div', {}, m)))));
  if (p.validated) out.push(el('div', { class: 'sec' }, el('h3', {}, 'Validation result'), el('div', { class: 'infer', style: 'border-color:var(--c-ok-bg)' }, el('div', {}, `${p.validated.module}: ${p.validated.verdict}`), el('div', { class: 'by' }, `Approved by ${p.validated.analyst || '-'} Â· evidence ${p.validated.evidence_id}`))));
  else if (p.validation === 'pending_approval') out.push(el('div', { class: 'sec' }, el('h3', {}, 'Validation'), el('div', { class: 'src warn' }, 'A check is waiting for your approval in the conversation.')));
  else if (a.scope && a.scope.allow_exploit) {
    const mod = el('input', { placeholder: 'Module path, for example auxiliary/scanner/â€¦', spellcheck: 'false' }), err = el('div', { class: 'errline' });
    out.push(el('div', { class: 'sec' }, el('h3', {}, 'Request a validation'), el('div', { class: 'vform' }, el('p', {}, 'This only creates a pending approval. Nothing runs until you approve it with a reason and the target typed back. The only method is a module check.'), mod,
      el('button', { class: 'btn sm', type: 'button', on: { click: async () => { try { await api(`/api/assessments/${S.id}/validate`, { json: { finding_id: p.finding, module: mod.value.trim() } }); await poll(); if (innerWidth <= 1100) showProof(false); } catch (e) { err.textContent = e.message; } } } }, 'Request validation'), err)));
  } else out.push(el('div', { class: 'sec' }, el('h3', {}, 'Validation'), el('div', { class: 'src' }, 'This scope does not permit validation requests.')));
  out.push(el('div', { class: 'sec' }, el('h3', {}, `Risk ${p.risk.score.toFixed(1)} of 100`, el('small', {}, cap(p.risk.priority))), el('div', { class: 'fac' }, (p.risk.factors || []).flatMap((f) => [el('span', {}, `${f.name} (${f.source})`), el('b', {}, f.value.toFixed(2))])), el('div', { class: 'src', style: 'margin-top:10px' }, 'Computed in code from CVSS or nominal severity, exposure, tool-reported exploitability, asset criticality and confidence. A model never sets it.')));
  out.push(el('button', { class: 'btn sm', type: 'button', on: { click: () => { $('cmd').value = `Explain ${p.finding} and what I should check next`; autosize(); $('cmd').focus(); if (innerWidth <= 1100) showProof(false); } } }, 'Ask about ' + p.finding));
  return out;
}

// ------------------------------------------------------------------ account dialog
function note(id, text, good) { const e = $(id); e.textContent = text || ''; e.hidden = !text; e.classList.toggle('good', !!good); }
async function acctCall(path, body) {
  const r = await fetch(path, { method: body ? 'POST' : 'GET', headers: { 'content-type': 'application/json', 'X-VAPT-Token': S.token }, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (r.status === 401) sessionEnded();
  return { ok: r.ok, d };
}
function openAcct() {
  if (!S.user) return;
  $('ac-who').textContent = `Signed in as ${who()}, role ${S.user.role}.`;
  note('ac-msg', ''); note('ac-pmsg', ''); $('ac-old').value = ''; $('ac-new').value = '';
  $('ac-people').hidden = S.user.role !== 'admin';
  $('acct').hidden = false; setLocked(true); $('ac-old').focus();
  if (S.user.role === 'admin') loadPeople();
}
function closeAcct() { if ($('acct').hidden) return; $('acct').hidden = true; setLocked(!$('gate').hidden); }
$('ac-x').addEventListener('click', closeAcct);
$('acct').addEventListener('mousedown', (e) => { if (e.target === $('acct')) closeAcct(); });
$('ac-pw').addEventListener('submit', async (e) => {
  e.preventDefault();
  const { ok, d } = await acctCall('/api/auth/password', { old: $('ac-old').value, new: $('ac-new').value });
  if (ok) { $('ac-old').value = ''; $('ac-new').value = ''; note('ac-msg', 'Password changed. Your other sessions were signed out.', true); } else note('ac-msg', d.error || 'Could not change the password.');
});
async function loadPeople() {
  const list = $('ac-list'), { ok, d } = await acctCall('/api/auth/users');
  list.replaceChildren();
  if (!ok) { list.append(el('p', { class: 'm-fine' }, d.error || 'Could not load people.')); return; }
  const act = async (path, body) => { const r = await acctCall(path, body); note('ac-pmsg', r.ok ? '' : (r.d.error || 'That did not work.')); if (r.ok) loadPeople(); };
  d.users.forEach((u) => {
    const me = u.name === who(), pw = el('input', { type: 'password', placeholder: 'New password', autocomplete: 'new-password', maxlength: '256' });
    const setRow = el('div', { class: 'm-reset' }, pw, el('button', { class: 'btn sm', type: 'button', on: { click: () => act(`/api/auth/users/${u.name}/password`, { password: pw.value }) } }, 'Set'));
    setRow.hidden = true;
    const seen = u.last_login && !u.last_login.startsWith('0001') ? 'last sign-in ' + new Date(u.last_login).toLocaleString() : 'never signed in';
    list.append(el('div', { class: 'm-item' + (u.disabled ? ' off' : '') },
      el('span', { class: 'av', 'aria-hidden': 'true' }, (u.display || u.name).slice(0, 1).toUpperCase()),
      el('div', { class: 'm-id' }, el('b', {}, u.display || u.name), el('span', {}, `${u.name}, ${seen}`)),
      el('span', { class: 'tag' }, u.disabled ? 'disabled' : u.role),
      me ? el('span', { class: 'm-fine' }, 'you') : el('div', { class: 'm-act' },
        el('button', { class: 'lnk', type: 'button', on: { click: () => { setRow.hidden = !setRow.hidden; if (!setRow.hidden) pw.focus(); } } }, 'Reset password'),
        el('button', { class: 'lnk', type: 'button', on: { click: () => act(`/api/auth/users/${u.name}/${u.disabled ? 'enable' : 'disable'}`, {}) } }, u.disabled ? 'Enable' : 'Disable')),
      setRow));
  });
  const a = await acctCall('/api/auth/audit');
  $('ac-log').textContent = a.ok ? `Account log: ${a.d.status}, ${a.d.count} entries, hash-chained like the assessment logs.` : '';
}
$('ac-add').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = $('ac-un').value.trim(), { ok, d } = await acctCall('/api/auth/users', { name, display: $('ac-dn').value.trim(), password: $('ac-up').value, role: $('ac-ur').value });
  if (!ok) { note('ac-pmsg', d.error || 'Could not add that person.'); return; }
  ['ac-un', 'ac-dn', 'ac-up'].forEach((i) => { $(i).value = ''; }); note('ac-pmsg', `Added ${name}. They can sign in now.`, true); loadPeople();
});

// ------------------------------------------------------------------ command palette
const P = { items: [], i: 0 }, palEl = $('pal');
const looksAddr = (q) => /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z0-9-]+(:\d{1,5})?(\/\S*)?$/i.test(q) || /^\d{1,3}(\.\d{1,3}){3}(:\d{1,5})?(\/\d{1,2})?$/.test(q) || /^localhost(:\d+)?$/i.test(q);
function palItems(q) {
  const a = S.snap && S.snap.assessment, it = [];
  if (q && looksAddr(q)) it.push({ t: `Check ${q} against the scope`, s: 'dry run, no traffic', run: () => guardCheck(q) });
  it.push({ t: 'New assessment', s: 'start a fresh conversation', run: newAssessment }, { t: 'Focus the message box', s: '/', run: () => $('cmd').focus() }, { t: 'Toggle light or dark mode', s: 'theme', run: () => document.querySelector('#top [data-theme-toggle]').click() });
  if (a) {
    [...(a.findings || [])].sort((x, y) => (y.risk && y.risk.score || 0) - (x.risk && x.risk.score || 0)).forEach((f) => it.push({ t: `Proof: ${f.id} ${f.title}`, s: `${f.severity} Â· ${pct(f.confidence)}%`, run: () => openProof(f.id) }));
    it.push({ t: 'Re-verify the audit chain', s: 'the server recomputes every link', run: reverify });
    if ((a.findings || []).length) it.push({ t: 'Download the PDF report', s: '.pdf', run: () => { location.href = `/api/assessments/${S.id}/report.pdf`; } });
    if (a.phase === 'running') it.push({ t: 'Stop the run', s: 'cancels running steps', run: () => api(`/api/assessments/${S.id}/stop`, { method: 'POST' }).then(poll) });
  }
  it.push({ t: 'Open the workbench', s: 'tiling view with 3D surface', run: () => { location.href = '/workbench'; } }, { t: 'Account and password', s: who() + ' Â· ' + (S.user ? S.user.role : ''), run: openAcct }, { t: 'Sign out', s: 'ends this session', run: signOut });
  const lq = (q || '').toLowerCase();
  return it.filter((x) => !lq || (looksAddr(q) && x.t.startsWith('Check ')) || x.t.toLowerCase().includes(lq) || (x.s || '').toLowerCase().includes(lq));
}
function palRender() {
  const list = $('p-list'); list.replaceChildren();
  if (!P.items.length) list.append(el('div', { class: 'p-empty' }, 'Nothing matches.'));
  P.items.forEach((x, k) => list.append(el('div', { class: 'pi' + (k === P.i ? ' on' : ''), role: 'option', on: { click: () => palRun(k), mousemove: () => { if (P.i !== k) { P.i = k; palRender(); } } } }, x.t, el('small', {}, x.s || ''))));
  const on = list.querySelector('.on'); if (on) on.scrollIntoView({ block: 'nearest' });
}
function palOpen() { palEl.classList.add('on'); palEl.setAttribute('aria-hidden', 'false'); $('p-q').value = ''; P.i = 0; P.items = palItems(''); palRender(); $('p-q').focus(); }
function palClose() { palEl.classList.remove('on'); palEl.setAttribute('aria-hidden', 'true'); }
function palRun(k) { const x = P.items[k]; palClose(); if (x) x.run(); }
$('p-q').addEventListener('input', () => { P.i = 0; P.items = palItems($('p-q').value.trim()); palRender(); });
$('p-q').addEventListener('keydown', (e) => {
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); const n = P.items.length || 1; P.i = (P.i + (e.key === 'ArrowDown' ? 1 : n - 1)) % n; palRender(); }
  else if (e.key === 'Enter') { e.preventDefault(); palRun(P.i); } else if (e.key === 'Escape') { e.stopPropagation(); palClose(); }
});
palEl.addEventListener('mousedown', (e) => { if (e.target === palEl) palClose(); });
$('b-pal').addEventListener('click', palOpen);
async function guardCheck(target) {
  try {
    let r;
    if (S.id) r = await api('/api/guard-check', { json: { assessment_id: S.id, check: [target] } });
    else { const f = form(); r = await api('/api/guard-check', { json: { name: f.name, authorization: f.auth, targets: csv(f.targets), exclusions: csv(f.excl), authorized_domains: csv(f.authdom), allow_active: f.active, check: [target] } }); }
    if (r.scope_error) throw new Error(r.scope_error);
    (r.verdicts || []).forEach((v) => local({ kind: 'guard', target: v.target, allowed: v.allowed, reason: v.reason, logged: !!S.id }));
    if (S.id) poll();
  } catch (e) { local({ kind: 'error', text: e.message }); }
}
function resetState() { clearTimeout(S.timer); S.fresh = true; S.snap = null; S.locals = []; S.extra.clear(); S.auditN = -1; S.pending = null; S.asking = false; S.showAll = false; S.open.clear(); S.recentSig = ''; resetThread(); showProof(false); }
function newAssessment() {
  resetState(); S.id = ''; store.del('vapt-chat-aid');
  $('r-chain').hidden = true; $('ribbon').replaceChildren(); $('l-report').hidden = true;
  showBatchReports([]); $('thinking').hidden = true;
  scopeBtn.classList.remove('locked'); scopeSum(); showEmpty(true); $('cmd').focus(); labCheck(); loadRecent();
}
async function openAssessment(id) {
  if (id === S.id) return;
  resetState(); S.id = id; store.set('vapt-chat-aid', id); await poll(); schedule();
}
$('new').addEventListener('click', newAssessment); $('new-top').addEventListener('click', newAssessment);
$('w-out').addEventListener('click', signOut); $('w-acct').addEventListener('click', openAcct);

// ------------------------------------------------------------------ keys and menu
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); palEl.classList.contains('on') ? palClose() : palOpen(); return; }
  if (e.key === 'Escape') { if (!$('acct').hidden) closeAcct(); else if (palEl.classList.contains('on')) palClose(); else if (!$('scope-pop').hidden) scopePop(false); else if (!$('proof').hidden) showProof(false); return; }
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || '');
  if (e.key === '/' && !typing && !e.ctrlKey && !e.metaKey) { e.preventDefault(); $('cmd').focus(); }
}, true);
initMenu({
  button: $('menu'),
  items: [{ label: 'Console', run: () => $('cmd').focus() }, { label: 'Workbench', href: '/workbench' }, { label: 'About KAVACH', href: '/' }, { label: 'Sample report (PDF)', href: 'sample/sample-vapt-report.pdf' }],
  preview: (it, i) => [['Talk to the agent. Plans, approvals, findings and proof appear as cards in the conversation.', '', 'Everything it states about your target comes from stored tool evidence.'], ['The tiling view: scope form, 3D surface, audit tab and tools matrix.'], ['KAVACH, the story.', '', 'It replays a recorded sample run.'], ['The report generated from the recorded sample run.']][i] || [],
  sideTitle: 'sample run Â· recorded audit block',
  footer: [{ kbd: 'm' }, ' toggle  ', { kbd: 'â†‘' }, { kbd: 'â†“' }, ' move  ', { kbd: 'esc' }, ' close'],
});
boot().catch((e) => { document.body.append(el('pre', { style: 'padding:20px;color:#a31d2b' }, 'Could not reach the agent: ' + e.message)); });

