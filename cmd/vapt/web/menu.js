// Chain menu. A hamburger that opens a full-screen index where every entry is a block of the REAL audit chain
// (hashes are read from the recorded sample log, nothing here is invented). Used by the landing page and the console.
//   initMenu({ button, items, preview, footer }) -> { open, close, setCurrent(i) }
//   items:   [{ label, run?(), href?, hint?(ctx) }]       ctx = { rows, state }  (either may be null if the files are missing)
//   preview: (item, index, ctx) -> array of lines, each a string or [string, 'ok'|'no'|'b']
const RM = matchMedia('(prefers-reduced-motion: reduce)').matches;
const mk = (tag, attrs = {}, text) => {
  const e = document.createElement(tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (text != null) e.textContent = text;
  return e;
};
const GLYPH = '0123456789abcdef';

let ctxP = null;
function loadCtx() {
  if (!ctxP) {
    const j = (u) => fetch(u).then((r) => (r.ok ? r.text() : Promise.reject(r.status)));
    ctxP = Promise.all([
      j('kavach-audit.jsonl').then((t) => t.split(/\r?\n/).filter((l) => l.trim()).map((l) => JSON.parse(l))).catch(() => null),
      j('kavach-state.json').then((t) => JSON.parse(t)).catch(() => null),
    ]).then(([rows, state]) => ({ rows: rows && rows.length ? rows : null, state }));
  }
  return ctxP;
}

// Resolve a hash label from random hex to the real value, left to right.
function resolve(el, final) {
  if (RM || !final) { el.textContent = final || ''; return; }
  let i = 0;
  const t = setInterval(() => {
    let s = final.slice(0, i);
    for (let k = i; k < final.length; k++) s += GLYPH[(Math.random() * 16) | 0];
    el.textContent = s;
    if ((i += 2) > final.length) { clearInterval(t); el.textContent = final; }
  }, 22);
  el._t = t;
}

export function initMenu({ button, items, preview, footer, sideTitle = 'recorded block' }) {
  const root = mk('div', { id: 'mn', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Site index' });
  const list = mk('ul', { id: 'mn-list' });
  const side = mk('div', { id: 'mn-side' });
  const pvTitle = mk('h3', {}, sideTitle);
  const pv = mk('pre', { id: 'mn-pv', 'aria-live': 'polite' });
  const ft = mk('p', { id: 'mn-ft' });
  const close = mk('button', { id: 'mn-x', type: 'button' }, 'Close');
  side.append(pvTitle, pv, ft);
  root.append(close, list, side);
  document.body.append(root);

  const lis = items.map((it, i) => {
    const li = mk('li', { class: 'mn-i', style: '--n:' + i });
    const ctl = it.href ? mk('a', { href: it.href }) : mk('button', { type: 'button' });
    ctl.append(mk('span', { class: 'mn-k' }, String(i + 1).padStart(2, '0')), mk('span', { class: 'mn-t' }, it.label), mk('span', { class: 'mn-h' }));
    li.append(ctl);
    list.append(li);
    const act = () => setActive(i);
    ctl.addEventListener('pointerenter', act);
    ctl.addEventListener('focus', act);
    ctl.addEventListener('click', (e) => {
      if (it.href) { if (e.metaKey || e.ctrlKey) return; }
      e.preventDefault();
      shut(false);
      setTimeout(() => (it.href ? (location.href = it.href) : it.run && it.run()), RM ? 0 : 160);
    });
    return { li, ctl, hint: ctl.querySelector('.mn-h') };
  });

  let ctx = { rows: null, state: null }, active = 0, cur = -1, opener = null, isOpen = false;
  const blockFor = (i) => {
    if (!ctx.rows) return null;
    const n = ctx.rows.length;
    return ctx.rows[Math.round((i * (n - 1)) / Math.max(1, items.length - 1))];
  };

  function paintHints(animate) {
    items.forEach((it, i) => {
      const h = lis[i].hint, b = blockFor(i);
      h.replaceChildren();
      if (!b) { h.textContent = (it.hint && it.hint(ctx)) || ''; return; }
      h.append('block ' + b.seq + ' of ' + ctx.rows.length + '  ');
      const hs = mk('b', {});
      h.append(hs);
      const full = String(b.hash || '');
      if (animate) { clearInterval(hs._t); resolve(hs, full.slice(0, 16) + (full.length > 16 ? '…' : '')); }
      else hs.textContent = full.slice(0, 16) + (full.length > 16 ? '…' : '');
    });
  }

  function setActive(i) {
    active = i;
    lis.forEach((x, k) => x.li.classList.toggle('act', k === i));
    const lines = (preview && preview(items[i], i, ctx)) || [];
    const b = blockFor(i);
    const all = lines.slice();
    if (b) {
      all.push('', ['block ' + b.seq + ' · ' + b.type + ' · by ' + b.actor, 'b']);
      const two = (k, h) => { h = String(h); all.push(k + '  ' + h.slice(0, 32)); if (h.length > 32) all.push(' '.repeat(k.length + 2) + h.slice(32)); };
      two('prev', b.prev_hash || '(genesis)');
      two('hash', b.hash || '');
    }
    pv.replaceChildren();
    all.forEach((ln) => {
      const [txt, cls] = Array.isArray(ln) ? ln : [ln, ''];
      pv.append(cls ? mk('span', { class: cls }, txt) : document.createTextNode(txt), '\n');
    });
  }

  function setCurrent(i) {
    cur = i;
    lis.forEach((x, k) => x.li.classList.toggle('mn-cur', k === i));
  }

  const others = () => [...document.body.children].filter((e) => e !== root && e.tagName !== 'SCRIPT');
  function openMenu() {
    if (isOpen) return;
    isOpen = true;
    opener = document.activeElement;
    root.classList.add('open');
    button.setAttribute('aria-expanded', 'true');
    others().forEach((e) => { e.inert = true; });
    paintHints(false);
    setActive(cur >= 0 ? cur : 0);
    loadCtx().then((c) => { ctx = c; if (isOpen) { paintHints(true); setActive(active); } });
    setTimeout(() => (lis[cur >= 0 ? cur : 0].ctl).focus(), RM ? 0 : 60);
  }
  function shut(restore = true) {
    if (!isOpen) return;
    isOpen = false;
    root.classList.remove('open');
    button.setAttribute('aria-expanded', 'false');
    others().forEach((e) => { e.inert = false; });
    if (restore && opener && opener.focus) opener.focus();
  }

  button.setAttribute('aria-haspopup', 'dialog');
  button.setAttribute('aria-expanded', 'false');
  button.addEventListener('click', () => (isOpen ? shut() : openMenu()));
  close.addEventListener('click', () => shut());
  root.addEventListener('click', (e) => { if (e.target === root || e.target === side || e.target === list) shut(); });

  const focusables = () => [close, ...lis.map((x) => x.ctl)];
  document.addEventListener('keydown', (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || '');
    if (!isOpen) {
      if ((e.key === 'm' || e.key === 'M') && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) { e.preventDefault(); e.stopPropagation(); openMenu(); }
      return;
    }
    e.stopPropagation();
    if (e.key === 'Escape' || e.key === 'm' || e.key === 'M') { e.preventDefault(); shut(); return; }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const n = lis.length, k = (active + (e.key === 'ArrowDown' ? 1 : n - 1)) % n;
      lis[k].ctl.focus();
      return;
    }
    if (/^[1-9]$/.test(e.key) && +e.key <= items.length && !e.ctrlKey && !e.metaKey) { e.preventDefault(); lis[+e.key - 1].ctl.click(); return; }
    if (e.key === 'Tab') {
      const f = focusables(), i = f.indexOf(document.activeElement);
      e.preventDefault();
      f[(i + (e.shiftKey ? f.length - 1 : 1)) % f.length].focus();
    }
  }, true);

  if (footer) ft.replaceChildren(...footer.map((x) => (typeof x === 'string' ? document.createTextNode(x) : mk('kbd', {}, x.kbd))));
  return { open: openMenu, close: shut, setCurrent };
}
