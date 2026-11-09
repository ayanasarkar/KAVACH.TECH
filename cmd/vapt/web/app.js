// Console logic. All dynamic text is inserted with textContent / text nodes:
// tool output and banners are untrusted data.
import { Surface, hostOf } from './scene.js';

const $ = (id) => document.getElementById(id);
const S = {
  token: '', id: '', snap: null, tab: 'scope', sel: 0, hostFilter: '', sevFilter: '', cfg: null,
  auditEntries: [], auditCount: -1, timer: null, logN: 0, booted: false, openId: '',
};
const TABS = [['scope', 'scope'], ['plan', 'plan'], ['findings', 'findings'], ['approvals', 'approvals'], ['audit', 'audit'], ['tools', 'tools']];

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
const clear = (n) => { n.replaceChildren(); return n; };
const csv = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
const fmtT = (t) => (t ? new Date(t).toLocaleTimeString([], { hour12: false }) : '--:--:--');
const analyst = () => 'analyst';

async function api(path, opts = {}) {
  const o = Object.assign({ headers: {} }, opts);
  o.headers['X-VAPT-Token'] = S.token;
  if (o.json) { o.headers['content-type'] = 'application/json'; o.body = JSON.stringify(o.json); o.method = o.method || 'POST'; }
  const r = await fetch(path, o); const t = await r.text(); let d; try { d = JSON.parse(t); } catch { d = { raw: t }; }
  if (r.status === 401) { location.replace('/console'); throw new Error('Your session ended. Sign in on the console.'); }
  if (!r.ok) throw new Error(d.error || r.statusText);
  return d;
}

// ---------- 3D surface ----------
const surface = new Surface($('stage'), $('labels'), $('tip'));
if (!surface.ok) { $('nogl').hidden = false; console.warn('WebGL unavailable', surface.err); }
surface.onPick = (p) => {
  if (p.type === 'finding') openFinding(p.id);
  else if (p.type === 'host') { S.hostFilter = hostOf(p.host); go('findings'); surface.focus('host', p.host); }
  else if (p.type === 'audit') { go('audit'); }
};

// ---------- log ----------
function logLine(cls, lv, text, ts) {
  const box = $('log'); const near = box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
  box.append(el('div', { class: 'ln ' + cls }, el('span', { class: 'ts' }, (ts || fmtT(Date.now())) + ' '), el('span', { class: 'lv' }, lv), ' ' + text));
  while (box.childElementCount > 400) box.firstChild.remove();
  if (near) box.scrollTop = box.scrollHeight;
}
function sys(text) { logLine('sys', '[sys]', text); }

async function boot() {
  const cr = await fetch('/api/config'); if (cr.status === 401) { location.replace('/console'); return; } // sign in first
  const c = S.cfg = await cr.json(); S.token = c.token;
  $('b-model').textContent = String(c.model).replace(' (no LLM configured)', '');
  const lines = [['boot', '[  OK  ]', 'scope guard armed: deny by default'], ['boot', '[  OK  ]', 'audit log: append-only, hash-chained'],
    [/rules-only/.test(c.model) ? 'boot' : 'boot', /rules-only/.test(c.model) ? '[ INFO ]' : '[  OK  ]', 'planner: ' + c.model]];
  for (const m of c.matrix) lines.push(m.available_now ? ['boot', '[  OK  ]', `${m.tool.toLowerCase()} (${m.status.toLowerCase()}): ${m.note || 'ready'}`] : ['boot na', '[ N/A  ]', `${m.tool.toLowerCase()} (${m.status.toLowerCase()}): not installed here, optional. ${m.note}`]);
  lines.push(['boot', '[ INFO ]', 'type "help" for commands; 1-6 switch workspace']);
  S.matrix = c.matrix;
  renderFetch(c);
  let i = 0; await new Promise((res) => { const iv = setInterval(() => { const l = lines[i++]; if (!l) { clearInterval(iv); res(); return; } logLine(l[0], l[1], l[2]); }, 70); });
  S.booted = true; scopePreview();
}

function renderFetch(c) {
  const up = c.matrix.filter((m) => m.available_now).map((m) => m.tool.toLowerCase()).join(', ');
  const down = c.matrix.filter((m) => !m.available_now).map((m) => m.tool.toLowerCase()).join(', ');
  const f = $('fetch'); f.replaceChildren();
  const rows = [['vapt-agent', 'evidence-driven pentest agent'], ['model', c.model], ['scope', 'deny by default, lab-only'], ['tools up', up || 'none'], ['tools down', down || 'none']];
  rows.forEach(([k, v]) => f.append(el('b', {}, k.padEnd(11)), v + '\n'));
}

// ---------- workspaces ----------
function renderBar() {
  const a = S.snap && S.snap.assessment, nav = clear($('ws'));
  const pend = a ? (a.approvals || []).filter((x) => x.status === 'pending').length : 0;
  TABS.forEach(([k, label], i) => {
    const nf = a ? (a.findings || []).length : 0, na = S.snap ? S.snap.audit_count : 0;
    const extra = (k === 'approvals' && pend) ? el('span', { class: 'n' }, pend) : (k === 'plan' && a && a.phase === 'awaiting_approval') ? el('span', { class: 'n' }, '!') : (k === 'findings' && nf) ? el('span', { class: 'c' }, nf) : (k === 'audit' && na) ? el('span', { class: 'c' }, na) : null;
    nav.append(el('button', { class: S.tab === k ? 'on' : '', on: { click: () => go(k) } }, el('b', {}, i + 1), label, extra));
  });
}
function go(tab) {
  S.tab = tab;
  for (const [k] of TABS) $('v-' + k).hidden = k !== tab;
  $('ws-title').textContent = (TABS.findIndex((t) => t[0] === tab) + 1) + ':' + tab;
  renderBar(); renderTab(tab);
  if (tab === 'audit') loadAudit(true);
}
function renderTab(t) {
  const a = S.snap && S.snap.assessment; if (!a && t !== 'scope' && t !== 'tools') { clear($('v-' + t)).append(el('p', { class: 'dim' }, 'no assessment yet. configure scope in 1:scope and launch.')); return; }
  ({ plan: renderPlan, findings: renderFindings, approvals: renderApprovals, audit: renderAudit, tools: renderTools }[t] || (() => {}))(a);
}

// ---------- scope form + live guard preview ----------
function formScope() {
  const crit = {}; $('f-crit').value.split('\n').forEach((l) => { const [h, v] = l.split('='); if (h && v) crit[h.trim()] = v.trim(); });
  return {
    name: $('f-name').value, authorization: $('f-auth').value, request: $('f-request').value, targets: csv($('f-targets').value), exclusions: csv($('f-excl').value), authorized_domains: csv($('f-authdom').value),
    hosts: csv($('f-hosts').value), ports: csv($('f-ports').value).map(Number).filter(Boolean), max_req_per_sec: Number($('f-rate').value) || 0,
    allow_active: $('f-active').checked, allow_exploit: $('f-exploit').checked, auto_approve: $('f-auto').checked, allow_non_lab: $('f-nonlab').checked, criticality: crit,
  };
}
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/g, URL_RE = /https?:\/\/[^\s,;"')]+/g;
let previewTimer;
function scopePreview() { clearTimeout(previewTimer); previewTimer = setTimeout(runPreview, 350); }
async function runPreview() {
  if (!S.token || S.id) return;
  const f = formScope(); const mentioned = new Set(f.hosts);
  (f.request.match(URL_RE) || []).forEach((u) => mentioned.add(u.replace(/[.]+$/, '')));
  (f.request.replace(URL_RE, ' ').match(IP_RE) || []).forEach((i) => mentioned.add(i));
  const out = clear($('guard-out'));
  try {
    const r = await api('/api/guard-check', { json: Object.assign({}, f, { check: [...mentioned] }) });
    if (r.scope_error) { out.append(el('div', { class: 'no' }, 'scope rejected: ' + r.scope_error)); surface.setPreview({ allowed: [], refused: [] }); return; }
    out.append(el('div', { class: 'dim' }, '# guard dry run (nothing is sent to any target)'));
    r.verdicts.forEach((v) => out.append(el('div', { class: v.allowed ? 'ok' : 'no' }, v.target + ' ', el('span', { class: 'why' }, v.reason))));
    surface.setPreview({ allowed: r.verdicts.filter((v) => v.allowed).map((v) => v.target), refused: r.verdicts.filter((v) => !v.allowed) });
  } catch (e) { out.append(el('div', { class: 'no' }, e.message)); }
}
$('scope-form').addEventListener('input', scopePreview);
$('scope-form').addEventListener('change', scopePreview);

$('scope-form').addEventListener('submit', async (e) => {
  e.preventDefault(); $('setup-err').textContent = '';
  try {
    const r = await api('/api/assessments', { json: formScope() }); S.id = r.id;
    sys('assessment ' + S.id + ' created; scope validated');
    for (const t of ['nessus', 'openvas', 'burp']) { const f = $('i-' + t).files[0]; if (f) { const fd = new FormData(); fd.append('tool', t); fd.append('file', f); await api(`/api/assessments/${S.id}/import`, { method: 'POST', body: fd }); sys(`import ${t}: ${f.name}`); } }
    await api(`/api/assessments/${S.id}/start`, { method: 'POST' });
    $('bar-mid').textContent = 'assessment ' + S.id; go('plan'); poll(); clearInterval(S.timer); S.timer = setInterval(poll, 1200);
  } catch (x) { $('setup-err').textContent = x.message; }
});

// ---------- polling ----------
const PHASE = { planning: 'planning', awaiting_approval: 'awaiting approval', running: 'running', analysing: 'analysing', review: 'review', done: 'stopped' };
async function poll() {
  if (!S.id) return;
  try { S.snap = await api(`/api/assessments/${S.id}`); } catch (e) { return; }
  const a = S.snap.assessment;
  $('b-phase').textContent = PHASE[a.phase] || a.phase;
  const ab = $('b-audit'); const ok = S.snap.audit_status === 'verified';
  ab.textContent = ok ? `audit ${S.snap.audit_count} verified` : `audit BROKEN at ${S.snap.audit_count}`; ab.className = ok ? 'ok' : 'bad';
  $('st-left').textContent = `${S.id}  Â·  ${PHASE[a.phase] || a.phase}  Â·  ${(a.findings || []).length} findings  Â·  ${(a.evidence || []).length} evidence`;
  mergeLog(a);
  if (S.snap.audit_count !== S.auditCount) await loadAudit(false);
  surface.setData({ hosts: a.hosts || [], services: a.services || [], findings: a.findings || [], steps: a.steps || [], refused: refusedList(a),
    audit: { count: S.snap.audit_count, status: S.snap.audit_status, entries: S.auditEntries } });
  renderBar(); renderTab(S.tab); if (S.openId) openFinding(S.openId, true);
}
function refusedList(a) {
  const set = new Set();
  (a.events || []).forEach((e) => { let m = /REFUSED target (\S+?):/.exec(e.text) || /Scope probe (\S+?): REFUSED/.exec(e.text); if (m) set.add(m[1]); });
  return [...set];
}
async function loadAudit(force) {
  try { const d = await api(`/api/assessments/${S.id}/audit`); S.auditEntries = d.entries; S.auditCount = d.entries.length; if (S.tab === 'audit') renderAudit(); } catch (e) { /* ignore */ }
}
function mergeLog(a) {
  const items = [];
  (a.messages || []).forEach((m) => items.push({ t: m.time, cls: m.role, lv: m.role === 'analyst' ? 'analyst>' : 'agent:', text: m.text }));
  (a.events || []).forEach((e) => items.push({ t: e.time, cls: e.level, lv: `[${e.level}]`, text: e.text }));
  items.sort((x, y) => new Date(x.t) - new Date(y.t));
  const mark = S.id + ':' + items.length; if (S.logMark === mark) return;
  if (S.logId !== S.id) { S.logId = S.id; S.logN = 0; }
  items.slice(S.logN).forEach((i) => logLine(i.cls, i.lv, i.text, fmtT(i.t))); S.logN = items.length; S.logMark = mark;
}

// ---------- plan ----------
let spin = 0;
function bar(st) {
  const W = 10; const full = (c) => c.repeat(W);
  if (st === 'done') return `[${full('#')}]`; if (st === 'failed') return `[${full('!')}]`; if (st === 'blocked') return `[${'-'.repeat(3)}BLOCKED${'-'.repeat(0)}]`.padEnd(W + 2, '-').replace(/-\]$/, ']');
  if (st === 'skipped') return `[${full('~')}]`; if (st === 'declined') return `[${full('x')}]`;
  if (st === 'running') { const n = (spin % (W + 1)); return `[${'#'.repeat(n)}${'.'.repeat(W - n)}]`; }
  if (st === 'approved') return `[${'#'.repeat(1)}${'.'.repeat(W - 1)}]`;
  return `[${full('.')}]`;
}
const VERB = { portscan: 'Run a port scan on', webcheck: 'Run web checks on', nmap: 'Run nmap on', nikto: 'Run nikto on', zap: 'Run a ZAP scan on' };
const hostShort = (t) => String(t).replace(/^https?:\/\//, '');
function guardChecks(a, steps) {
  const sc = a.scope || {}; const out = [];
  const tg = (sc.targets || []).join(', ');
  if (steps.every((s) => s.guard && s.guard.allowed !== false)) out.push('in scope' + (tg ? ': ' + tg : ''));
  if ((sc.exclusions || []).length) out.push('not excluded (' + sc.exclusions.join(', ') + ')'); else out.push('no exclusions hit');
  if (steps.some((s) => /active/.test((s.guard && s.guard.reason) || ''))) out.push('active scan permitted'); else out.push('passive only');
  return out;
}
let holdT = 0, holdRaf = 0, holdEl = null;
function holdStart() {
  if (holdT || !S.snap || S.snap.assessment.phase !== 'awaiting_approval') return;
  holdT = performance.now(); holdEl = document.getElementById('hold-btn');
  const tick = () => {
    const p = Math.min(1, (performance.now() - holdT) / 1000);
    if (holdEl) holdEl.style.setProperty('--p', p);
    if (p >= 1) { holdStop(); approvePlan(); return; }
    holdRaf = requestAnimationFrame(tick);
  };
  tick();
}
function holdStop() { holdT = 0; cancelAnimationFrame(holdRaf); if (holdEl) holdEl.style.setProperty('--p', 0); }
let denyArm = 0;
async function denyPlan() {
  if (!S.snap || S.snap.assessment.phase !== 'awaiting_approval') return;
  const b = document.getElementById('deny-btn');
  if (!denyArm) { denyArm = setTimeout(() => { denyArm = 0; if (b) b.firstChild.textContent = 'Deny '; }, 3500); if (b) b.firstChild.textContent = 'Confirm deny '; return; }
  clearTimeout(denyArm); denyArm = 0;
  try { await api(`/api/assessments/${S.id}/deny`, { json: { analyst: analyst(), reason: 'denied in console' } }); sys('plan denied by ' + analyst() + '; nothing from it will run'); poll(); } catch (e) { logLine('error', '[error]', e.message); }
}
function renderPlan(a) {
  const v = $('v-plan');
  const sig = JSON.stringify([a.phase, a.round, (a.steps || []).map((s) => [s.id, s.status, s.summary, s.error, s.ended]), (a.limitations || []).length]);
  if (sig === S.planSig && v.childElementCount) return;
  S.planSig = sig; clear(v); holdStop();
  const steps = a.steps || [], waiting = a.phase === 'awaiting_approval';
  const prop = steps.filter((s) => s.status === 'proposed');
  v.append(el('h1', { class: 'hd' }, waiting ? 'Nothing runs until you approve.' : a.phase === 'review' ? 'Run complete.' : 'The plan.'),
    el('p', { class: 'sub' }, `Round ${a.round} Â· up to 4 rounds. Every step below was checked against the scope guard first.`));
  if (waiting && prop.length) {
    const one = prop.length === 1 ? prop[0] : null;
    const head = one ? `${VERB[one.tool] || 'Run ' + one.tool + ' on'} ${hostShort(one.target)}` : `Run ${prop.length} steps (${[...new Set(prop.map((s) => s.tool))].join(', ')})`;
    const hold = el('button', { class: 'hold', id: 'hold-btn', type: 'button', 'aria-label': 'Hold for one second to approve the plan' }, el('span', { class: 'lab' }, el('span', {}, 'Hold to approve'), el('kbd', {}, 'A')), el('span', { class: 'lab inv', 'aria-hidden': 'true' }, el('span', {}, 'Hold to approve'), el('kbd', {}, 'A')));
    hold.addEventListener('pointerdown', (e) => { e.preventDefault(); holdStart(); });
    ['pointerup', 'pointerleave', 'pointercancel', 'blur'].forEach((n) => hold.addEventListener(n, holdStop));
    hold.addEventListener('keydown', (e) => { if ((e.key === ' ' || e.key === 'Enter') && !e.repeat) { e.preventDefault(); holdStart(); } });
    hold.addEventListener('keyup', holdStop);
    const deny = el('button', { class: 'deny', id: 'deny-btn', type: 'button', on: { click: denyPlan } }, 'Deny ', el('kbd', {}, 'D'));
    v.append(el('section', { class: 'apv' },
      el('div', { class: 'k' }, `Approval required Â· round ${a.round} Â· ${prop.length} step${prop.length === 1 ? '' : 's'}`),
      el('h2', {}, head),
      ...prop.map((s) => el('div', { class: 'cmdl' }, `${s.tool}  ${hostShort(s.target)}  ${s.options && Object.keys(s.options).length ? JSON.stringify(s.options) : ''}`)),
      el('div', { class: 'chks' }, ...guardChecks(a, prop).map((t) => el('span', {}, 'âœ“ ' + t))),
      el('div', { class: 'acts' }, hold, deny, el('span', { class: 'rel' }, 'Release early to cancel.'))));
  } else if (['running', 'planning', 'analysing'].includes(a.phase)) {
    v.append(el('div', { class: 'acts run' }, el('button', { class: 'deny', type: 'button', on: { click: () => api(`/api/assessments/${S.id}/stop`, { method: 'POST' }) } }, 'Stop'), el('span', { class: 'rel' }, PHASE[a.phase] + '...')));
  }
  if (steps.length) {
    const T = el('div', { class: 'tbl', role: 'table' }, el('div', { class: 'th', role: 'row' }, ...['ID', 'Tool', 'Target', 'Guard', 'Status'].map((h) => el('span', { role: 'columnheader' }, h))));
    steps.forEach((s) => {
      const dur = s.ended && s.started && s.status !== 'running' ? ` ${Math.max(0, new Date(s.ended) - new Date(s.started))}ms` : '';
      const g = s.guard ? (s.guard.allowed === false ? 'refused' : 'allowed') : '-';
      T.append(...[el('div', { class: 'tr', role: 'row' },
        el('span', { class: 'id' }, s.id), el('span', { class: 'tool' }, s.tool), el('span', { class: 'tgt' }, hostShort(s.target)),
        el('span', { class: g === 'allowed' ? 'c-green' : 'c-red' }, g),
        el('span', { class: 'st-' + s.status }, s.status.replace(/_/g, ' ') + dur)),
        el('div', { class: 'why' }, s.rationale || ''),
        el('div', { class: 'meta' }, `guard: ${s.guard && s.guard.reason || '-'} Â· by ${s.proposed_by} Â· round ${s.round}` + (s.trigger_evidence ? ' Â· because ' + s.trigger_evidence.join(',') : '')),
        s.summary ? el('div', { class: 'meta' }, s.summary + (s.raw_file ? ' Â· ' : ''), s.raw_file ? el('a', { href: `/api/assessments/${S.id}/raw/${s.raw_file.split('/').pop()}`, target: '_blank', rel: 'noopener' }, 'raw') : null, s.raw_sha256 ? ' sha256:' + s.raw_sha256.slice(0, 10) : '') : null,
        s.error ? el('div', { class: 'err' }, s.error) : null].filter(Boolean));
    });
    v.append(T);
  }
  if ((a.limitations || []).length) { v.append(el('h3', { class: 'sec' }, 'limitations')); a.limitations.forEach((l) => v.append(el('div', { class: 'lim' }, '! ' + l))); }
}
setInterval(() => { spin++; if (S.tab === 'plan' && S.snap && S.snap.assessment.phase === 'running') document.querySelectorAll('.bar.running').forEach((b) => { b.textContent = bar('running'); }); }, 160);
async function approvePlan() { try { await api(`/api/assessments/${S.id}/approve`, { json: { analyst: analyst() } }); sys('plan approved by ' + analyst()); poll(); } catch (e) { logLine('error', '[error]', e.message); } }

// ---------- findings ----------
function visibleFindings() {
  const a = S.snap && S.snap.assessment; if (!a) return [];
  return (a.findings || []).filter((f) => (!S.hostFilter || (f.assets || []).some((x) => x.host === S.hostFilter)) && (!S.sevFilter || f.severity === S.sevFilter));
}
function renderFindings(a) {
  const v = clear($('v-findings')); const fs = visibleFindings();
  if (a.summary) v.append(el('div', { class: 'box ai' }, el('span', { class: 'lbl ai' }, `[${a.summary_by === 'rules' ? 'rules' : 'ai'}] summary `), a.summary));
  const flt = el('div', { class: 'flt' }, el('span', { class: 'dim' }, 'filter'));
  ['critical', 'high', 'medium', 'low', 'info'].forEach((s) => flt.append(el('button', { class: 'chip ' + (S.sevFilter === s ? 'on' : ''), on: { click: () => { S.sevFilter = S.sevFilter === s ? '' : s; S.sel = 0; renderFindings(a); } } }, s)));
  if (S.hostFilter) flt.append(el('button', { class: 'chip on', on: { click: () => { S.hostFilter = ''; S.sel = 0; renderFindings(a); } } }, 'host:' + S.hostFilter + ' Ã—'));
  v.append(flt);
  if (!fs.length) { v.append(el('p', { class: 'dim' }, (a.findings || []).length ? 'no findings match the filter' : 'no findings yet')); return; }
  S.sel = Math.min(S.sel, fs.length - 1);
  v.append(el('div', { class: 'frow fhead' }, el('span'), el('span', {}, 'id'), el('span', {}, 'pri'), el('span', {}, 'risk'), el('span', {}, 'sev'), el('span', {}, 'finding / assets / status')));
  fs.forEach((f, i) => {
    const row = el('div', { class: 'frow' + (i === S.sel ? ' sel' : ''), 'data-i': i, on: { click: () => { S.sel = i; openFinding(f.id); } } },
      el('span', { class: 'cur' }, i === S.sel ? 'â–Œ' : ''), el('span', { class: 'dim' }, f.id), el('span', { class: f.risk.priority === 'P1' ? 'c-crit' : 'dim' }, f.risk.priority), el('span', {}, f.risk.score.toFixed(0)),
      el('span', { class: 'sev-' + f.severity }, { critical: 'crit', medium: 'med' }[f.severity] || f.severity), el('span', { class: 'ttl' }, f.title));
    v.append(row, el('div', { class: 'frow', on: { click: () => { S.sel = i; openFinding(f.id); } } }, el('span'), el('span'), el('span'), el('span'), el('span'),
      el('span', { class: 'sub' }, (f.assets || []).map((x) => x.host + ':' + x.port).join(', ') + ' Â· ', el('span', { class: 'st-' + f.status }, f.status.replace(/_/g, ' ')), ' Â· ' + f.confidence_label + ' ' + Math.round(f.confidence * 100) + '% Â· ' + (f.tools || []).join('+'))));
  });
}

// ---------- evidence drawer ----------
function rawLink(ref) { const m = /raw\/([A-Za-z0-9._-]+)/.exec(ref || ''); return m ? el('a', { href: `/api/assessments/${S.id}/raw/${m[1]}`, target: '_blank', rel: 'noopener' }, ref) : el('span', { class: 'dim' }, ref); }
function openFinding(id, silent) {
  const a = S.snap && S.snap.assessment; const f = a && (a.findings || []).find((x) => x.id === id); if (!f) return;
  S.openId = id; const ev = Object.fromEntries((a.evidence || []).map((e) => [e.id, e]));
  $('drawer-title').textContent = `${f.id} :: ${f.title.length > 60 ? f.title.slice(0, 59) + 'â€¦' : f.title}`;
  const b = clear($('drawer-body'));
  b.append(el('div', {}, el('span', { class: 'sev-' + f.severity }, f.severity.toUpperCase()), `  priority ${f.risk.priority}  risk ${f.risk.score.toFixed(1)}/100  `, el('span', { class: 'st-' + f.status }, f.status.replace(/_/g, ' ')), `  confidence ${f.confidence_label} ${Math.round(f.confidence * 100)}%`),
    el('div', { class: 'box obs' }, el('div', { class: 'lbl obs' }, '[obs] observed, from tool output'), el('div', {}, f.description),
      el('dl', { class: 'kvl' }, el('dt', {}, 'cvss'), el('dd', {}, f.cvss != null ? `${f.cvss.toFixed(1)} (reported by ${f.cvss_source})` : 'not reported by any tool'), el('dt', {}, 'cve'), el('dd', {}, (f.cves || []).join(', ') || '-'), el('dt', {}, 'cwe'), el('dd', {}, (f.cwes || []).join(', ') || '-'), el('dt', {}, 'owasp'), el('dd', {}, f.owasp || '-'), el('dt', {}, 'basis'), el('dd', {}, f.basis)),
      el('div', { class: 'dim' }, 'assets'), (f.assets || []).map((x) => el('div', {}, `${x.host}:${x.port} ${x.service || ''}  via ${x.tools.join(', ')}  ${x.evidence.join(' ')}`)),
      el('div', { class: 'dim', style: 'margin-top:6px' }, 'evidence'),
      (f.evidence || []).map((i) => { const e = ev[i]; return e ? el('div', {}, el('b', {}, e.id), ` ${e.tool} ${fmtT(e.time)} `, rawLink(e.raw_ref), el('pre', {}, e.excerpt)) : null; })),
    (f.inferences || []).length ? el('div', { class: 'box ai' }, el('div', { class: 'lbl ai' }, '[ai] inference, reasoning rather than observation'), f.inferences.map((i) => el('div', {}, i.text, el('div', { class: 'dim' }, `by ${i.by}; cites ${i.cites.join(', ')}`)))) : null,
    el('div', { class: 'box' }, el('div', { class: 'lbl' }, 'correlation and triage (computed by code)'), (f.notes || []).length ? f.notes.map((n) => el('div', {}, '- ' + n)) : el('div', { class: 'dim' }, 'single source; no triage flags')),
    el('div', { class: 'box' }, el('div', { class: 'lbl' }, 'risk score (never set by the model)'), f.risk.factors.map((x) => el('div', {}, `${x.name} = ${x.value}  `, el('span', { class: 'dim' }, '<- ' + x.source)))),
    el('div', { class: 'box' }, el('div', { class: 'lbl' }, 'remediation'), el('div', {}, f.remediation || 'none supplied by the tools')),
    el('div', { class: 'box' }, el('div', { class: 'lbl' }, 'human-approved validation'), el('div', { class: 'dim' }, `lab-only module check; nothing runs until approved in 4:approvals. state: ${f.validation.replace(/_/g, ' ')}`),
      el('div', { class: 'row' }, el('input', { id: 'val-mod', placeholder: 'auxiliary/scanner/...' }), el('button', { class: 'btn sm', on: { click: async () => { try { await api(`/api/assessments/${S.id}/validate`, { json: { finding_id: f.id, module: $('val-mod').value.trim(), analyst: analyst() } }); sys('validation requested for ' + f.id + '; nothing executed'); go('approvals'); poll(); } catch (x) { logLine('error', '[error]', x.message); } } } }, 'request'))));
  if (!silent) { $('drawer').hidden = false; surface.focus('finding', id); }
}
function closeDrawer() { $('drawer').hidden = true; S.openId = ''; }
$('drawer-x').addEventListener('click', closeDrawer);

// ---------- approvals / audit / tools ----------
function renderApprovals(a) {
  const v = clear($('v-approvals')); const aps = a.approvals || [];
  v.append(el('h3', { class: 'sec' }, 'approvals'), el('p', { class: 'note' }, 'Active validation is never autonomous. Approving needs your name, a reason, and the target typed back. Everything lands in the audit chain.'));
  if (!aps.length) v.append(el('p', { class: 'dim' }, 'no validation requested.'));
  aps.forEach((p) => {
    const box = el('div', { class: 'box' }, el('b', {}, `${p.id} ${p.finding_id} ${p.module}`), el('div', {}, 'target ' + p.target), el('div', {}, 'state ', el('span', { class: 'st-' + p.status }, p.status), p.analyst ? ` by ${p.analyst}: ${p.reason}` : ''), p.outcome ? el('div', { class: 'dim' }, 'outcome: ' + p.outcome) : null);
    if (p.status === 'pending') {
      const who = el('input', { placeholder: 'your name', value: '' }), reason = el('input', { placeholder: 'reason (required)' }), conf = el('input', { placeholder: 'type ' + p.target + ' to confirm' });
      const decide = (ok) => async () => { try { await api(`/api/assessments/${S.id}/decide`, { json: { approval_id: p.id, approve: ok, analyst: who.value, reason: reason.value, confirm_target: conf.value } }); sys(`${p.id} ${ok ? 'approved' : 'declined'}`); poll(); } catch (x) { logLine('error', '[error]', x.message); } };
      box.append(el('div', { class: 'kv' }, el('span', {}, 'name'), who), el('div', { class: 'kv' }, el('span', {}, 'reason'), reason), el('div', { class: 'kv' }, el('span', {}, 'confirm'), conf), el('div', { class: 'row' }, el('button', { class: 'btn pri', on: { click: decide(true) } }, 'approve + run check'), el('button', { class: 'btn', on: { click: decide(false) } }, 'decline')));
    }
    v.append(box);
  });
}
function renderAudit() {
  const v = clear($('v-audit')); const st = S.snap ? S.snap.audit_status : '';
  v.append(el('h3', { class: 'sec' }, 'audit trace'), el('p', { class: 'note' }, 'sha256(entry + previous hash). Edit or delete any line in audit.jsonl and the chain breaks: ', el('span', { class: st === 'verified' ? 'c-green' : 'c-crit' }, st || '-')));
  const t = el('table', {}, el('thead', {}, el('tr', {}, ['#', 'time', 'actor', 'type', 'summary', 'hash'].map((h) => el('th', {}, h)))));
  const tb = el('tbody'); S.auditEntries.forEach((e) => tb.append(el('tr', {}, el('td', { class: 'dim' }, e.seq), el('td', { class: 'dim' }, fmtT(e.time)), el('td', {}, e.actor), el('td', { class: 'c-cyan' }, e.type), el('td', {}, e.summary), el('td', { class: 'hash' }, e.hash.slice(0, 8)))));
  t.append(tb); v.append(t);
}
function renderTools() {
  const v = clear($('v-tools')); const m = (S.snap && S.snap.matrix) || S.matrix || [];
  v.append(el('h3', { class: 'sec' }, 'integrations'), el('p', { class: 'note' }, 'Truthful status for this machine. Import-only means the tool is never contacted: you supply its export.'));
  const t = el('table', {}, el('thead', {}, el('tr', {}, ['tool', 'mode', 'here', 'notes'].map((h) => el('th', {}, h)))));
  const tb = el('tbody'); m.forEach((x) => tb.append(el('tr', {}, el('td', {}, el('b', {}, x.tool), el('div', { class: 'dim' }, x.method)), el('td', {}, x.status), el('td', { class: x.available_now ? 'c-green' : 'c-red' }, x.available_now ? 'up' : 'down', el('div', { class: 'dim' }, x.note)), el('td', { class: 'dim' }, x.limitations))));
  t.append(tb); v.append(t);
}

// ---------- prompt ----------
const HELP = ['commands:', '  <anything>        ask the agent ("why S-02?", "explain F-001", name another host)', '  check <target>    dry-run the scope guard on a target and watch it hit the shield (audited, runs nothing)',
  '  approve           approve the waiting plan', '  open <F-001>      open a findingâ€™s evidence', '  goto <ws>         scope | plan | findings | approvals | audit | tools', '  pdf               download the report', '  clear             clear this log'];
$('prompt').addEventListener('submit', async (e) => {
  e.preventDefault(); const raw = $('cmd').value.trim(); if (!raw) return; $('cmd').value = '';
  const [c, ...rest] = raw.split(/\s+/), arg = rest.join(' ');
  hist.unshift(raw); hi = -1;
  if (c === 'help' || c === '?') return HELP.forEach((l) => logLine('sys', '', l));
  if (c === 'clear') return clear($('log'));
  if (c === 'goto') { const t = TABS.find((x) => x[0].startsWith(arg)); return t ? go(t[0]) : logLine('error', '[error]', 'unknown workspace'); }
  if (c === 'pdf') { if (!S.id) return logLine('error', '[error]', 'no assessment'); window.open(`/api/assessments/${S.id}/report.pdf`); return; }
  if (!S.id && (c === 'check')) return logLine('warn', '[warn]', 'launch an assessment first; before that, the form shows the guard dry run live');
  if (!S.id) return logLine('warn', '[warn]', 'no assessment yet: fill in 1:scope and launch');
  if (c === 'approve') return approvePlan();
  if (c === 'open') { const f = (S.snap.assessment.findings || []).find((x) => x.id.toLowerCase() === arg.toLowerCase()); return f ? openFinding(f.id) : logLine('error', '[error]', 'no such finding'); }
  if (c === 'check') {
    if (!arg) return logLine('warn', '[warn]', 'usage: check <host|ip|url>');
    try { const r = await api('/api/guard-check', { json: { assessment_id: S.id, analyst: analyst(), check: csv(arg.replace(/\s+/g, ',')) } }); r.verdicts.forEach((v) => surface.probe(hostOf(v.target) || v.target, v.allowed)); poll(); } catch (x) { logLine('error', '[error]', x.message); }
    return;
  }
  try { await api(`/api/assessments/${S.id}/chat`, { json: { message: raw } }); poll(); } catch (x) { logLine('error', '[error]', x.message); }
});
const hist = []; let hi = -1;
$('cmd').addEventListener('keydown', (e) => {
  if (e.key === 'ArrowUp') { hi = Math.min(hist.length - 1, hi + 1); $('cmd').value = hist[hi] || ''; e.preventDefault(); }
  else if (e.key === 'ArrowDown') { hi = Math.max(-1, hi - 1); $('cmd').value = hist[hi] || ''; e.preventDefault(); }
  else if (e.key === 'Escape') { $('cmd').blur(); }
});

// ---------- keyboard (vim-ish) ----------
document.addEventListener('keydown', (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
  if (e.key === 'Escape') { if (!$('drawer').hidden) closeDrawer(); else document.activeElement.blur && document.activeElement.blur(); return; }
  if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === '/' || e.key === ':') { e.preventDefault(); $('cmd').focus(); return; }
  if (/^[1-6]$/.test(e.key)) { go(TABS[+e.key - 1][0]); return; }
  if (e.key === 'a' && !e.repeat && S.snap && S.snap.assessment.phase === 'awaiting_approval') { if (S.tab !== 'plan') go('plan'); holdStart(); return; }
  if (e.key === 'd' && S.snap && S.snap.assessment.phase === 'awaiting_approval') { if (S.tab !== 'plan') go('plan'); denyPlan(); return; }
  if (S.tab === 'findings') {
    const fs = visibleFindings();
    if (e.key === 'j' || e.key === 'ArrowDown') { S.sel = Math.min(fs.length - 1, S.sel + 1); renderFindings(S.snap.assessment); keepSel(); e.preventDefault(); }
    else if (e.key === 'k' || e.key === 'ArrowUp') { S.sel = Math.max(0, S.sel - 1); renderFindings(S.snap.assessment); keepSel(); e.preventDefault(); }
    else if (e.key === 'Enter' && fs[S.sel]) openFinding(fs[S.sel].id);
  }
});
document.addEventListener('keyup', (e) => { if (e.key === 'a') holdStop(); });
function keepSel() { const r = document.querySelector('.frow.sel'); if (r) r.scrollIntoView({ block: 'nearest' }); }

setInterval(() => { const d = new Date(); $('b-clock').textContent = d.toLocaleTimeString([], { hour12: false }); }, 1000);
$('b-clock').textContent = new Date().toLocaleTimeString([], { hour12: false });

renderBar(); go('scope'); boot();
