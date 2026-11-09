// The "surface": a live 3D model of the assessment. Everything drawn comes from
// real assessment data (hosts, open services, findings, running steps, audit
// entries, scope refusals). Nothing here is decorative data.
import * as THREE from 'three';
import { OrbitControls } from './vendor/OrbitControls.js';

const C = {
  bg: 0x1a0f10, fg: 0xf6ebe9, dim: 0x52333a, blue: 0xe8707e, cyan: 0xc9afb0,
  green: 0x8fe0b5, yellow: 0xf2cc7a, red: 0xe5606e, crit: 0xff9aa3, mag: 0xf6ebe9,
};
const SEV = { critical: C.crit, high: C.red, medium: C.yellow, low: C.cyan, info: 0xc9afb0 };
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SHIELD_R = 9;

export function hostOf(t) {
  if (!t) return '';
  let h = String(t).replace(/^[a-z]+:\/\//i, '').split('/')[0];
  if (h.startsWith('[')) return h.slice(1, h.indexOf(']'));
  if ((h.match(/:/g) || []).length === 1) h = h.split(':')[0];
  return h;
}

function hash(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
function rnd(seed) { let a = seed; return () => { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }

function solid(geo, edgeColor, fillColor, edgeOpacity = 1) {
  const g = new THREE.Group();
  const fill = new THREE.Mesh(geo, new THREE.MeshBasicMaterial({ color: fillColor, polygonOffset: true, polygonOffsetFactor: 1, polygonOffsetUnits: 1 }));
  const lines = new THREE.LineSegments(new THREE.EdgesGeometry(geo), new THREE.LineBasicMaterial({ color: edgeColor, transparent: edgeOpacity < 1, opacity: edgeOpacity }));
  g.add(fill, lines);
  g.userData.fill = fill; g.userData.lines = lines;
  return g;
}
function mix(a, b, t) { return new THREE.Color(a).lerp(new THREE.Color(b), t); }

export class Surface {
  constructor(container, labelLayer, tip) {
    this.el = container; this.labels = labelLayer; this.tip = tip;
    this.onPick = () => {}; this.ok = false;
    this.hosts = new Map(); this.shards = new Map(); this.pulses = new Map(); this.refusedMarks = new Map();
    this.ripples = []; this.flights = []; this.auditBlocks = []; this.auditKey = '';
    this.pickables = []; this.model = null; this.preview = null; this.hover = null; this.t0 = performance.now();
    this.lbl = new Map();
    this.auditAnchor = new THREE.Object3D(); this.auditAnchor.position.set(0, -5.3, 0);
    try { this._init(); this.ok = true; } catch (e) { this.err = e; }
  }

  _init() {
    const r = this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'high-performance' });
    r.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    r.setClearColor(C.bg, 1);
    this.el.prepend(r.domElement);
    r.domElement.style.display = 'block';
    this.scene = new THREE.Scene();
    this.cam = new THREE.PerspectiveCamera(48, 1, 0.1, 200);
    this.cam.position.set(0, 6.5, 21.5);
    const oc = this.controls = new OrbitControls(this.cam, r.domElement);
    oc.enableDamping = true; oc.dampingFactor = 0.07; oc.autoRotate = true; oc.autoRotateSpeed = 0.35;
    oc.minDistance = 6; oc.maxDistance = 32; oc.maxPolarAngle = Math.PI * 0.62; oc.enablePan = false;
    let resume;
    oc.addEventListener('start', () => { oc.autoRotate = false; clearTimeout(resume); });
    oc.addEventListener('end', () => { resume = setTimeout(() => { oc.autoRotate = true; }, 9000); });

    this.root = new THREE.Group(); this.scene.add(this.root); this.root.add(this.auditAnchor);

    // agent core
    this.core = new THREE.Group();
    this.core.add(solid(new THREE.IcosahedronGeometry(0.85, 1), C.blue, C.bg));
    const inner = new THREE.Mesh(new THREE.OctahedronGeometry(0.32), new THREE.MeshBasicMaterial({ color: C.blue }));
    this.core.add(inner); this.coreInner = inner;
    this.root.add(this.core);
    this._label('core', 'vapt-agent', 'core', this.core, 1.9);

    // scope shield
    const sg = new THREE.IcosahedronGeometry(SHIELD_R, 2);
    this.shieldMat = new THREE.LineBasicMaterial({ color: C.blue, transparent: true, opacity: 0.2 });
    this.shield = new THREE.LineSegments(new THREE.WireframeGeometry(sg), this.shieldMat);
    this.root.add(this.shield);
    this.shieldFlash = 0; this.shieldFlashColor = new THREE.Color(C.red);

    // polar floor grid
    const grid = new THREE.Group();
    const gm = new THREE.LineBasicMaterial({ color: C.dim, transparent: true, opacity: 0.22 });
    for (const rr of [3, 6, 9, 12]) {
      const pts = []; for (let i = 0; i <= 96; i++) { const a = i / 96 * Math.PI * 2; pts.push(new THREE.Vector3(Math.cos(a) * rr, 0, Math.sin(a) * rr)); }
      grid.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), gm));
    }
    for (let i = 0; i < 24; i++) { const a = i / 24 * Math.PI * 2; grid.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(Math.cos(a) * 3, 0, Math.sin(a) * 3), new THREE.Vector3(Math.cos(a) * 12, 0, Math.sin(a) * 12)]), gm)); }
    grid.position.y = -4.7; this.root.add(grid);

    this.ray = new THREE.Raycaster(); this.ptr = new THREE.Vector2(); this.ptrIn = false; this.down = null;
    const dom = r.domElement;
    dom.addEventListener('pointermove', (e) => { const b = dom.getBoundingClientRect(); this.ptr.set((e.clientX - b.left) / b.width * 2 - 1, -((e.clientY - b.top) / b.height) * 2 + 1); this.ptrIn = true; this.px = e.clientX - b.left; this.py = e.clientY - b.top; });
    dom.addEventListener('pointerleave', () => { this.ptrIn = false; this._setHover(null); });
    dom.addEventListener('pointerdown', (e) => { this.down = [e.clientX, e.clientY]; });
    dom.addEventListener('pointerup', (e) => {
      if (!this.down) return; const d = Math.hypot(e.clientX - this.down[0], e.clientY - this.down[1]); this.down = null;
      if (d < 5 && this.hover) this.onPick(this.hover);
    });
    new ResizeObserver(() => this._resize()).observe(this.el);
    this._resize();
    this._loop = this._loop.bind(this);
    requestAnimationFrame(this._loop);
  }

  _resize() {
    const w = this.el.clientWidth, h = this.el.clientHeight; if (!w || !h) return;
    this.renderer.setSize(w, h, false); this.renderer.domElement.style.width = w + 'px'; this.renderer.domElement.style.height = h + 'px';
    this.cam.aspect = w / h; this.cam.updateProjectionMatrix(); this.w = w; this.h = h;
  }

  // ---------- DOM labels that follow 3D points ----------
  _label(key, text, cls, anchor, lift = 0.9, sub) {
    let l = this.lbl.get(key);
    if (!l) {
      const el = document.createElement('div'); el.className = 'tag3d ' + cls;
      const a = document.createElement('span'); a.className = 'l1'; el.append(a);
      const b = document.createElement('span'); b.className = 'l2'; el.append(b);
      this.labels.append(el); l = { el, a, b, anchor, lift }; this.lbl.set(key, l);
    }
    l.anchor = anchor; l.a.textContent = text; l.b.textContent = sub || ''; l.b.style.display = sub ? '' : 'none';
    return l;
  }
  _dropLabel(key) { const l = this.lbl.get(key); if (l) { l.el.remove(); this.lbl.delete(key); } }

  // ---------- data sync ----------
  setPreview(p) { this.preview = p; this._sync(); }
  setData(m) { this.model = m; this._sync(); }

  _hostList() {
    const m = this.model, set = new Set();
    if (m) {
      (m.hosts || []).forEach((h) => set.add(hostOf(h)));
      (m.services || []).forEach((s) => set.add(s.host));
      (m.findings || []).forEach((f) => (f.assets || []).forEach((a) => set.add(a.host)));
    }
    let ghost = false;
    if (!set.size && this.preview) { (this.preview.allowed || []).forEach((h) => set.add(hostOf(h))); ghost = set.size > 0; }
    return { list: [...set].filter(Boolean).sort(), ghost };
  }

  _hostPos(i, n) {
    const a = (n === 1 ? 0.5 : i / n) * Math.PI * 2 + 0.4;
    const rad = n === 1 ? 5.4 : 5.6 + (n > 4 ? 0.6 : 0);
    return new THREE.Vector3(Math.cos(a) * rad, (i % 2 ? 0.7 : -0.5), Math.sin(a) * rad);
  }

  _sync() {
    if (!this.ok) return;
    const { list, ghost } = this._hostList(), m = this.model || {};
    const open = (m.services || []).filter((s) => s.state === 'open');
    // hosts
    for (const [h, o] of this.hosts) if (!list.includes(h)) { this._disposeHost(o); this.hosts.delete(h); this._dropLabel('h:' + h); }
    list.forEach((h, i) => {
      let o = this.hosts.get(h);
      if (!o) {
        const g = new THREE.Group();
        const body = solid(new THREE.OctahedronGeometry(0.62), C.blue, C.bg);
        body.userData.fill.userData.pick = { type: 'host', host: h };
        g.add(body); this.pickables.push(body.userData.fill);
        const link = new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(), new THREE.Vector3()]), new THREE.LineBasicMaterial({ color: C.blue, transparent: true, opacity: 0.35 }));
        this.root.add(g, link);
        o = { g, body, link, svc: new Map(), pos: new THREE.Vector3(), spawn: performance.now() };
        this.hosts.set(h, o);
      }
      o.pos.copy(this._hostPos(i, list.length)); o.g.position.copy(o.pos); o.ghost = ghost;
      o.link.geometry.setFromPoints([new THREE.Vector3(), o.pos]);
      // services
      const mine = open.filter((s) => s.host === h);
      const keep = new Set(mine.map((s) => s.port));
      for (const [p, sv] of o.svc) if (!keep.has(p)) { o.g.remove(sv.g); this.pickables = this.pickables.filter((x) => x !== sv.g.userData.fill); o.svc.delete(p); }
      mine.forEach((s, k) => {
        if (o.svc.has(s.port)) return;
        const clear = ['telnet', 'ftp'].includes(s.name);
        const web = /http/.test(s.name || '');
        const col = clear ? C.red : web ? C.blue : C.fg;
        const sg = solid(new THREE.BoxGeometry(0.26, 0.26, 0.26), col, C.bg);
        sg.userData.fill.userData.pick = { type: 'service', host: h, port: s.port, name: s.name, product: s.product, tool: s.tool };
        this.pickables.push(sg.userData.fill);
        o.g.add(sg);
        o.svc.set(s.port, { g: sg, r: 1.25 + (k % 3) * 0.28, ph: (hash(h + s.port) % 628) / 100, sp: 0.5 + (k % 3) * 0.15, tilt: (k % 2 ? 0.5 : -0.4) });
      });
      // label
      const fc = (m.findings || []).filter((f) => (f.assets || []).some((a) => a.host === h));
      const top = fc.reduce((b, f) => Math.max(b, SEV_RANK[f.severity] ?? 0), -1);
      const col = top < 0 ? C.blue : SEV[Object.keys(SEV_RANK).find((k) => SEV_RANK[k] === top)];
      o.body.userData.lines.material.color.setHex(col); o.body.userData.fill.material.color.copy(mix(C.bg, col, 0.16));
      o.body.userData.lines.material.transparent = ghost; o.body.userData.lines.material.opacity = ghost ? 0.45 : 1;
      this._label('h:' + h, h, 'host' + (ghost ? ' ghost' : ''), o.g, 1.2, ghost ? 'in scope (preview)' : `${mine.length} open · ${fc.length} finding${fc.length === 1 ? '' : 's'}`);
    });
    // finding shards
    const want = new Set();
    (m.findings || []).forEach((f) => (f.assets || []).forEach((a) => {
      const key = f.id + '@' + a.host; want.add(key);
      const o = this.hosts.get(a.host); if (!o) return;
      let s = this.shards.get(key);
      const size = 0.16 + Math.min(f.risk?.score || 0, 100) / 100 * 0.3;
      if (!s) {
        const sg = solid(new THREE.TetrahedronGeometry(1), SEV[f.severity] ?? C.dim, C.bg);
        sg.userData.fill.userData.pick = { type: 'finding', id: f.id };
        this.pickables.push(sg.userData.fill);
        const ln = new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(), new THREE.Vector3()]), new THREE.LineBasicMaterial({ color: SEV[f.severity] ?? C.dim, transparent: true, opacity: 0.4 }));
        this.root.add(sg, ln);
        s = { g: sg, ln, host: a.host, id: f.id, ph: (hash(key) % 628) / 100, spawn: performance.now(), p1: f.risk?.priority === 'P1' };
        this.shards.set(key, s);
      }
      s.size = size; s.sev = f.severity; s.p1 = f.risk?.priority === 'P1'; s.title = f.title; s.score = f.risk?.score || 0;
      const c = SEV[f.severity] ?? C.dim;
      s.g.userData.lines.material.color.setHex(c); s.g.userData.fill.material.color.copy(mix(C.bg, c, 0.3)); s.ln.material.color.setHex(c);
      s.g.userData.fill.userData.pick = { type: 'finding', id: f.id };
    }));
    for (const [k, s] of this.shards) if (!want.has(k)) { this.root.remove(s.g, s.ln); this.pickables = this.pickables.filter((x) => x !== s.g.userData.fill); this.shards.delete(k); }
    // shard slots per host
    const per = new Map(); for (const s of this.shards.values()) { const a = per.get(s.host) || []; a.push(s); per.set(s.host, a); }
    for (const a of per.values()) { a.sort((x, y) => y.score - x.score); a.forEach((s, i) => { s.slot = i; s.n = a.length; }); }

    // scan pulses
    const live = new Set();
    (m.steps || []).forEach((st) => {
      if (!['running', 'pending_approval', 'proposed'].includes(st.status)) return;
      const h = hostOf(st.target), o = this.hosts.get(h); if (!o) return;
      const key = st.id; live.add(key);
      let p = this.pulses.get(key);
      if (!p) {
        const n = 7, arr = new Float32Array(n * 3);
        const g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.BufferAttribute(arr, 3));
        const pts = new THREE.Points(g, new THREE.PointsMaterial({ color: C.cyan, size: 0.22, sizeAttenuation: true, transparent: true }));
        this.root.add(pts); p = { pts, h, n }; this.pulses.set(key, p);
      }
      p.state = st.status; p.h = h; p.pts.material.color.setHex(st.status === 'running' ? C.cyan : C.yellow); p.pts.material.opacity = st.status === 'running' ? 1 : 0.55;
    });
    for (const [k, p] of this.pulses) if (!live.has(k)) { this.root.remove(p.pts); this.pulses.delete(k); }

    // refused targets (persistent markers outside the shield)
    const refused = new Set(m.refused && m.refused.length ? m.refused : (this.preview ? (this.preview.refused || []).map((r) => r.target) : []));
    for (const [t, mk] of this.refusedMarks) if (!refused.has(t)) { this.root.remove(mk); this.refusedMarks.delete(t); this._dropLabel('r:' + t); }
    refused.forEach((t) => {
      if (this.refusedMarks.has(t)) return;
      const R = rnd(hash(t)), th = R() * Math.PI * 2, y = (R() - 0.5) * 6;
      const g = new THREE.Group();
      const x = new THREE.Group();
      for (const s of [1, -1]) { const l = new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(-0.3, -0.3 * s, 0), new THREE.Vector3(0.3, 0.3 * s, 0)]), new THREE.LineBasicMaterial({ color: C.red })); x.add(l); }
      g.add(x); g.position.set(Math.cos(th) * 10.4, y * 0.6, Math.sin(th) * 10.4); g.userData.spin = x;
      this.root.add(g); this.refusedMarks.set(t, g);
      this._label('r:' + t, t, 'refused', g, 0.7, 'refused by scope guard');
      if (!this._animated?.has(t)) { (this._animated ||= new Set()).add(t); this._fly(t, false, g.position.clone()); }
    });

    // audit ring
    const a = m.audit; if (a) this._syncAudit(a);
  }

  _disposeHost(o) { this.root.remove(o.g, o.link); this.pickables = this.pickables.filter((x) => x !== o.body.userData.fill && ![...o.svc.values()].some((s) => s.g.userData.fill === x)); }

  _syncAudit(a) {
    const es = (a.entries || []).slice(-80); const key = es.length + ':' + (es.length ? es[es.length - 1].hash : '') + a.status;
    if (key === this.auditKey) return; this.auditKey = key;
    for (const b of this.auditBlocks) { this.root.remove(b.mesh); this.pickables = this.pickables.filter((x) => x !== b.mesh.userData.fill); }
    if (this.auditLines) { this.root.remove(this.auditLines); this.auditLines.geometry.dispose(); }
    const bad = /entry (\d+)/.exec(a.status || ''); const badSeq = bad ? +bad[1] : 0;
    this.auditBlocks = []; const pts = []; const n = es.length;
    es.forEach((e, i) => {
      const th = Math.PI * 0.15 + (n < 2 ? 0 : i / (n - 1)) * Math.PI * 1.7;
      const pos = new THREE.Vector3(Math.cos(th) * 6.9, -4.4, Math.sin(th) * 6.9);
      const broken = badSeq && e.seq >= badSeq;
      let col = C.blue; if (e.type === 'approval' || e.type === 'approval_requested') col = C.green; else if (e.detail?.allowed === 'false') col = C.red; else if (/^run_/.test(e.type)) col = C.cyan; else if (e.type === 'plan' || e.type === 'plan_step') col = C.mag;
      if (broken) col = C.crit;
      const mesh = solid(new THREE.BoxGeometry(0.34, 0.14, 0.34), col, C.bg);
      mesh.userData.fill.userData.pick = { type: 'audit', entry: e };
      mesh.position.copy(pos); mesh.scale.setScalar(0.01);
      this.root.add(mesh); this.pickables.push(mesh.userData.fill);
      this.auditBlocks.push({ mesh, spawn: performance.now() + i * 18 }); pts.push(pos.clone(), i ? this.auditBlocks[i - 1].mesh.position.clone() : pos.clone());
    });
    const lg = new THREE.BufferGeometry().setFromPoints(pts);
    this.auditLines = new THREE.LineSegments(lg, new THREE.LineBasicMaterial({ color: badSeq ? C.crit : C.blue, transparent: true, opacity: 0.55 }));
    this.root.add(this.auditLines);
    const head = es[es.length - 1];
    if (head) { this._label('audit', `audit chain ${a.count ?? n} ${badSeq ? '✗ BROKEN' : '✓ verified'}`, 'audit' + (badSeq ? ' bad' : ''), this.auditAnchor, 0.3, 'head ' + head.hash.slice(0, 10)); }
  }

  // ---------- scope probe animation: flies a packet at the shield ----------
  probe(target, allowed) { if (!this.ok) return; if (!allowed) (this._animated ||= new Set()).add(target); this._fly(target, allowed); }
  _fly(target, allowed, from) {
    const R = rnd(hash(target + Date.now())); const th = R() * Math.PI * 2, y = (R() - 0.5) * 8;
    const start = from || new THREE.Vector3(Math.cos(th) * 22, y, Math.sin(th) * 22);
    const m = new THREE.Mesh(new THREE.OctahedronGeometry(0.22), new THREE.MeshBasicMaterial({ color: allowed ? C.green : C.red }));
    m.position.copy(start); this.root.add(m);
    const dir = start.clone().normalize(); const hit = dir.clone().multiplyScalar(SHIELD_R);
    this.flights.push({ m, start, hit, allowed, t0: performance.now(), dir, target });
    const key = 'f:' + target + this.flights.length; this._label(key, target, allowed ? 'probe ok' : 'probe bad', m, 0.5); this.flights[this.flights.length - 1].key = key;
  }
  _ripple(pos, color) {
    const m = new THREE.Mesh(new THREE.RingGeometry(0.2, 0.26, 48), new THREE.MeshBasicMaterial({ color, transparent: true, side: THREE.DoubleSide, depthWrite: false }));
    m.position.copy(pos); m.lookAt(0, 0, 0); this.root.add(m); this.ripples.push({ m, t0: performance.now() });
    this.shieldFlash = 1; this.shieldFlashColor.setHex(color);
  }

  focus(kind, id) {
    let target = null;
    if (kind === 'finding') { for (const s of this.shards.values()) if (s.id === id) target = s.g.getWorldPosition(new THREE.Vector3()); }
    else if (kind === 'host') { const o = this.hosts.get(id); if (o) target = o.g.position.clone(); }
    if (!target) return;
    this.flash = { id, kind, t0: performance.now() };
    const dir = target.clone().normalize(); this.camTween = { t0: performance.now(), from: this.cam.position.clone(), to: dir.multiplyScalar(target.length() + 10).setY(target.y + 4.2) };
    this.controls.autoRotate = false;
  }

  _setHover(h) {
    const key = h ? JSON.stringify(h, (k, v) => (k === 'entry' ? v.seq : v)) : '';
    if (key === this._hk) return; this._hk = key; this.hover = h;
    this.renderer.domElement.style.cursor = h ? 'pointer' : 'grab';
    if (!h) { this.tip.style.display = 'none'; return; }
    this.tip.replaceChildren();
    const add = (cls, t) => { const d = document.createElement('div'); d.className = cls; d.textContent = t; this.tip.append(d); };
    if (h.type === 'finding') { const s = [...this.shards.values()].find((x) => x.id === h.id); add('t1', `${h.id}  ${(s?.sev || '').toUpperCase()}`); add('t2', s?.title || ''); add('t3', `risk ${(s?.score || 0).toFixed(0)}/100 · click to open evidence`); }
    else if (h.type === 'host') { add('t1', h.host); add('t3', 'click to filter findings to this host'); }
    else if (h.type === 'service') { add('t1', `${h.host}:${h.port}/tcp  ${h.name || 'unknown'}`); if (h.product) add('t2', h.product); add('t3', `seen by ${h.tool}`); }
    else if (h.type === 'audit') { add('t1', `audit #${h.entry.seq} ${h.entry.type}`); add('t2', h.entry.summary); add('t3', `${h.entry.actor} · hash ${h.entry.hash.slice(0, 12)}`); }
    this.tip.style.display = 'block';
  }

  // ---------- frame loop ----------
  _loop() {
    requestAnimationFrame(this._loop);
    if (document.hidden || !this.w || this.el.getClientRects().length === 0) return;
    const now = performance.now(), t = (now - this.t0) / 1000;
    this.core.rotation.y = t * 0.4; this.core.rotation.x = Math.sin(t * 0.3) * 0.2; this.coreInner.scale.setScalar(1 + Math.sin(t * 2.2) * 0.18);
    this.shield.rotation.y = t * 0.02;
    const sf = this.shieldFlash; if (sf > 0) { this.shieldFlash = Math.max(0, sf - 0.02); this.shieldMat.color.copy(new THREE.Color(C.blue).lerp(this.shieldFlashColor, sf)); this.shieldMat.opacity = 0.13 + sf * 0.5; } else { this.shieldMat.color.setHex(C.blue); this.shieldMat.opacity = 0.13; }
    for (const o of this.hosts.values()) {
      const s = Math.min(1, (now - o.spawn) / 500); o.g.scale.setScalar(0.2 + 0.8 * (1 - Math.pow(1 - s, 3)));
      o.body.rotation.y = t * 0.25; o.g.position.y = o.pos.y + Math.sin(t * 0.9 + o.pos.x) * 0.12;
      if (o.ghost) o.body.userData.lines.material.opacity = 0.3 + Math.sin(t * 2) * 0.15;
      for (const sv of o.svc.values()) { const a = sv.ph + t * sv.sp; sv.g.position.set(Math.cos(a) * sv.r, Math.sin(a * 0.7) * sv.tilt, Math.sin(a) * sv.r); sv.g.rotation.set(t, t * 0.7, 0); }
      const pa = o.link.geometry.attributes.position; pa.setXYZ(1, o.g.position.x, o.g.position.y, o.g.position.z); pa.needsUpdate = true;
    }
    for (const s of this.shards.values()) {
      const o = this.hosts.get(s.host); if (!o) continue;
      const k = Math.min(1, (now - s.spawn) / 600), e = 1 - Math.pow(1 - k, 3);
      const a = s.ph + t * 0.35 + (s.slot || 0) * (Math.PI * 2 / Math.max(1, s.n || 1)), r = 2.2 + (s.slot || 0) * 0.25;
      const pulse = s.p1 ? 1 + Math.sin(t * 4 + s.ph) * 0.18 : 1;
      const fl = this.flash && this.flash.kind === 'finding' && this.flash.id === s.id && now - this.flash.t0 < 1800 ? 1 + Math.sin((now - this.flash.t0) / 70) * 0.5 : 1;
      s.g.position.set(o.g.position.x + Math.cos(a) * r, o.g.position.y + Math.sin(a * 1.3) * 0.7 + 0.3, o.g.position.z + Math.sin(a) * r);
      s.g.scale.setScalar(s.size * e * pulse * fl); s.g.rotation.set(t * 0.8, t * 0.6, 0);
      const pa = s.ln.geometry.attributes.position; pa.setXYZ(0, o.g.position.x, o.g.position.y, o.g.position.z); pa.setXYZ(1, s.g.position.x, s.g.position.y, s.g.position.z); pa.needsUpdate = true;
    }
    for (const p of this.pulses.values()) {
      const o = this.hosts.get(p.h); if (!o) continue; const arr = p.pts.geometry.attributes.position;
      const speed = p.state === 'running' ? 0.55 : 0.12;
      for (let i = 0; i < p.n; i++) { const u = ((t * speed + i / p.n) % 1); arr.setXYZ(i, o.g.position.x * u, o.g.position.y * u, o.g.position.z * u); }
      arr.needsUpdate = true;
      if (p.state !== 'running') p.pts.material.opacity = 0.35 + 0.3 * Math.sin(t * 3);
    }
    for (const mk of this.refusedMarks.values()) { mk.userData.spin.rotation.z = t * 0.8; mk.quaternion.copy(this.cam.quaternion); }
    for (const b of this.auditBlocks) { const k = Math.min(1, Math.max(0, (now - b.spawn) / 380)); b.mesh.scale.setScalar(0.01 + 0.99 * (1 - Math.pow(1 - k, 3))); }
    // ripples
    this.ripples = this.ripples.filter((r) => { const k = (now - r.t0) / 1300; if (k >= 1) { this.root.remove(r.m); return false; } r.m.scale.setScalar(1 + k * 9); r.m.material.opacity = 1 - k; return true; });
    // probe flights
    this.flights = this.flights.filter((f) => {
      const el = (now - f.t0) / 1000; const l = this.lbl.get(f.key);
      const total = f.start.distanceTo(f.hit); const dur = Math.max(0.6, total / 14);
      if (el < dur) { f.m.position.lerpVectors(f.start, f.hit, el / dur); f.m.rotation.y += 0.2; return true; }
      if (!f.hitDone) { f.hitDone = true; this._ripple(f.hit, f.allowed ? C.green : C.red); }
      const e2 = el - dur;
      if (f.allowed) {
        if (e2 < 0.9) { f.m.position.lerpVectors(f.hit, f.hit.clone().multiplyScalar(0.62), e2 / 0.9); return true; }
      } else if (e2 < 0.8) { f.m.position.copy(f.hit).add(f.dir.clone().multiplyScalar(e2 * 6)); f.m.material.opacity = 1; f.m.material.transparent = true; f.m.material.opacity = 1 - e2 / 0.8; return true; }
      this.root.remove(f.m); this._dropLabel(f.key); return false;
    });
    // camera tween
    if (this.camTween) { const k = Math.min(1, (now - this.camTween.t0) / (this.camTween.ms || 800)), e = 1 - Math.pow(1 - k, 3); this.cam.position.lerpVectors(this.camTween.from, this.camTween.to, e); if (k >= 1) this.camTween = null; }
    this.controls.update();
    // hover pick
    if (this.ptrIn && !this.down) {
      this.ray.setFromCamera(this.ptr, this.cam);
      const hit = this.ray.intersectObjects(this.pickables, false)[0];
      this._setHover(hit ? hit.object.userData.pick : null);
      if (hit) { const tb = this.el.getBoundingClientRect(); this.tip.style.left = Math.min(this.px + 14, tb.width - 270) + 'px'; this.tip.style.top = Math.min(this.py + 14, tb.height - 90) + 'px'; }
    }
    this.renderer.render(this.scene, this.cam);
    // labels
    const v = new THREE.Vector3();
    for (const l of this.lbl.values()) {
      l.anchor.getWorldPosition(v); v.y += l.lift * 0.45; v.project(this.cam);
      const vis = v.z < 1 && Math.abs(v.x) < 1.1 && Math.abs(v.y) < 1.1;
      l.el.style.display = vis ? '' : 'none';
      if (vis) l.el.style.transform = `translate(${((v.x + 1) / 2 * this.w).toFixed(1)}px,${((1 - v.y) / 2 * this.h).toFixed(1)}px) translate(-50%,-100%)`;
    }
  }
}
