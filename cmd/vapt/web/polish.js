// Additive polish: scope chip, live regions, toasts, shortcut help. Never touches app.js state.
const $ = (id) => document.getElementById(id);
const wrap = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const sc = () => { $('b-scope').textContent = 'scope ' + ($('f-targets').value || 'none') + ($('f-excl').value ? ' \u2212 ' + $('f-excl').value : ''); };
$('scope-form').addEventListener('input', sc); sc();
$('bar-right').setAttribute('aria-live', 'polite'); $('guard-out').setAttribute('aria-live', 'polite');
$('setup-err').setAttribute('role', 'alert'); $('log').setAttribute('role', 'log'); $('log').setAttribute('aria-relevant', 'additions');
$('stage').setAttribute('role', 'img'); $('stage').setAttribute('aria-label', 'Live 3D model of hosts, services and findings. All data is also in the workspaces.');

const tbox = wrap('div'); tbox.id = 'toasts'; tbox.setAttribute('role', 'status'); tbox.setAttribute('aria-live', 'polite'); document.body.append(tbox);
function toast(kind, text) { const t = wrap('div', 'toast ' + kind, text); tbox.append(t); while (tbox.children.length > 4) tbox.firstChild.remove(); setTimeout(() => t.remove(), kind === 'error' ? 7000 : 3800); }
new MutationObserver((ms) => ms.forEach((m) => m.addedNodes.forEach((n) => {
  if (!n.classList || !n.classList.contains('ln')) return;
  const txt = n.textContent.slice(9).trim();
  if (n.classList.contains('error')) toast('error', txt);
  else if (n.classList.contains('warn')) toast('warn', txt);
  else if (n.classList.contains('sys') && /created|approved|declined|requested/.test(txt)) toast('ok', txt);
}))).observe($('log'), { childList: true });

let helpEl = null, back = null;
function closeHelp() { if (helpEl) { helpEl.remove(); helpEl = null; if (back && back.focus) back.focus(); } }
function openHelp() {
  back = document.activeElement; helpEl = wrap('div'); helpEl.id = 'help'; helpEl.setAttribute('role', 'dialog'); helpEl.setAttribute('aria-modal', 'true'); helpEl.setAttribute('aria-label', 'Keyboard shortcuts');
  const box = wrap('div'), dl = wrap('dl'); box.append(wrap('h2', '', 'keyboard shortcuts'));
  [['1-6', 'switch workspace'], ['/', 'focus the prompt'], ['j / k', 'move in findings'], ['Enter', 'open finding evidence'], ['a', 'approve the waiting plan'], ['Esc', 'close drawer or this help'], ['?', 'toggle this help']].forEach(([k, v]) => dl.append(wrap('dt', '', k), wrap('dd', '', v)));
  const x = wrap('button', 'btn', 'close'); x.addEventListener('click', closeHelp); box.append(dl, x); helpEl.append(box); helpEl.addEventListener('click', (e) => { if (e.target === helpEl) closeHelp(); }); document.body.append(helpEl); x.focus();
}
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && helpEl) { closeHelp(); e.stopPropagation(); return; }
  if (e.key === '?' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) { helpEl ? closeHelp() : openHelp(); e.preventDefault(); }
}, true);
$('st-right').textContent = '1-6 workspace   / prompt   j k move   a approve plan   ? help   esc close';
// hold-to-approve: hold the button or the A key for one second; releasing early cancels.
(() => {
  const HOLD = 1000; let raf = 0, t0 = 0;
  const btn = () => document.querySelector('#v-plan .btn.pri');
  const stop = () => { cancelAnimationFrame(raf); raf = 0; const b = btn(); if (b) b.style.setProperty('--p', 0); };
  const start = () => { if (raf || !btn()) return; t0 = performance.now(); const tick = (n) => { const b = btn(); if (!b) { raf = 0; return; } const p = Math.min(1, (n - t0) / HOLD); b.style.setProperty('--p', p); if (p >= 1) { raf = 0; b.dataset.held = '1'; b.click(); delete b.dataset.held; return; } raf = requestAnimationFrame(tick); }; raf = requestAnimationFrame(tick); };
  document.addEventListener('click', (e) => { const b = e.target.closest && e.target.closest('#v-plan .btn.pri'); if (b && !b.dataset.held) { e.stopImmediatePropagation(); e.preventDefault(); } }, true);
  document.addEventListener('pointerdown', (e) => { if (e.target.closest && e.target.closest('#v-plan .btn.pri')) start(); }, true);
  addEventListener('pointerup', stop); addEventListener('pointercancel', stop);
  document.addEventListener('keydown', (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName), onBtn = e.target.matches && e.target.matches('#v-plan .btn.pri');
    if (e.ctrlKey || e.metaKey || e.altKey || !btn() || !((e.key === 'a' && !typing) || (onBtn && (e.key === 'Enter' || e.key === ' ')))) return;
    e.stopImmediatePropagation(); e.preventDefault(); if (!e.repeat) start();
  }, true);
  document.addEventListener('keyup', (e) => { if (['a', 'Enter', ' '].includes(e.key)) stop(); }, true);
})();
