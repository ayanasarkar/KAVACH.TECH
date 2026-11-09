// First-run help for the console: a three-step quick start, a live "is the lab up?" hint, and a plain note when
// no AI planner is configured. Additive: it only reads /api/config and the page; app.js state is untouched.
const $ = (id) => document.getElementById(id);
const mk = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };

// Whether the lab is up comes from /api/lab-status: the server makes plain loopback TCP connects (no data sent).
// Doing it server-side keeps the browser console free of "connection refused" noise.
const card = mk('div', 'qs');
card.setAttribute('role', 'note');
const step = (n, ...parts) => { const d = mk('div', 'st'); d.append(mk('i', '', n)); const s = mk('span'); s.append(...parts); d.append(s); return d; };
const labState = mk('span', 'dm', 'checking…');
const planner = mk('span', 'dm');
card.append(
  mk('b', 't', 'quick start'),
  step('1', 'start the lab in another terminal: ', mk('code', '', 'go run ./cmd/lab'), '  ', labState),
  step('2', 'the scope below already matches the lab. Anything outside it is refused.'),
  step('3', 'press ', mk('code', '', 'launch'), ', read the plan and its reasons, then approve it.'),
  step('•', planner),
);
const host = $('fetch');
if (host && host.parentNode) host.parentNode.insertBefore(card, host);

async function labCheck() {
  const hosts = ($('f-hosts') && $('f-hosts').value) || '';
  if (!/127\.0\.0\.1|localhost/.test(hosts)) { labState.className = 'dm'; labState.textContent = '(hosts is not the local lab)'; return; }
  try {
    const res = await fetch('/api/lab-status', { cache: 'no-store' }); if (!res.ok) return;
    const r = await res.json();
    const n = (r.web || []).length + (r.ftp || []).length + (r.telnet || []).length;
    if (n) {
      labState.className = 'ok';
      labState.textContent = '\u2713 up: web ' + ((r.web || []).join(', ') || 'none') + ' \u00b7 ftp ' + ((r.ftp || []).join(', ') || 'none') + ' \u00b7 telnet ' + ((r.telnet || []).join(', ') || 'none');
    } else { labState.className = 'no'; labState.textContent = 'not running yet: nothing is listening on the lab ports'; }
  } catch (e) { labState.className = 'dm'; labState.textContent = ''; }
}
labCheck();
setInterval(() => { if (!document.hidden && !$('v-scope').hidden) labCheck(); }, 6000);
if ($('f-hosts')) $('f-hosts').addEventListener('change', labCheck);

fetch('/api/config').then((r) => (r.ok ? r.json() : Promise.reject(new Error('signed out')))).then((c) => {
  if (/rules-only/.test(c.model)) {
    planner.className = 'dm';
    planner.textContent = 'planner: rules-only. For the model-driven planner set ANTHROPIC_API_KEY (or OLLAMA_MODEL) and restart.';
  } else { planner.className = 'ok'; planner.textContent = 'planner: ' + c.model; }
}).catch(() => { planner.textContent = ''; });
