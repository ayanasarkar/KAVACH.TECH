/* KAVACH landing: Hindi oil-paint opening, button polish and background music.
   Loaded first in <head> of landing.html:  <script src="/kavach-pro.js"></script>
   The opening plays once per browser tab; add ?intro=1 to the address to see it again. Click it to skip.
   It replaces the page's own #pre loader (hidden by kavach-pro.css) and waits until that loader's work is finished.
   Music: put your file at cmd/vapt/web/kavach-bg.mp3. It starts on the first click or Enter/Space (browsers block sound
   before that) by pressing the page's own "Sound" button for you, so the label, the bell/gong effects and the music
   always agree. Pressing "Sound" again turns everything off, and the choice is remembered. */
(function () {
  var d = document, h = d.documentElement, KEY = 'kv-intro-seen';
  var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  var force = /[?&]intro(=1)?(&|$)/.test(location.search);
  var seen = false;
  try { seen = sessionStorage.getItem(KEY) === '1'; } catch (e) {}

  h.classList.add('kv-pro');
  var css = d.createElement('link'); css.rel = 'stylesheet'; css.href = '/kavach-pro.css'; d.head.appendChild(css);
  // Listen straight away: waiting until DOMContentLoaded can miss the load event of a fast local file.
  var cssReady = new Promise(function (r) { css.addEventListener('load', r); css.addEventListener('error', r); });

  /* ---------------- background music ---------------- */
  function music() {
    var a = new Audio('/kavach-bg.mp3'), started = false, muted = false, timer = null;
    a.loop = true; a.preload = 'none'; a.volume = 0;
    try { muted = localStorage.getItem('kv-muted') === '1'; } catch (e) {}
    function btn() { return d.getElementById('snd'); }
    function pressed() { var b = btn(); return !!b && b.getAttribute('aria-pressed') === 'true'; }
    function fade(to, ms, done) {
      clearInterval(timer);
      var from = a.volume, t0 = Date.now();
      timer = setInterval(function () {
        var k = Math.min((Date.now() - t0) / ms, 1);
        a.volume = Math.max(0, Math.min(1, from + (to - from) * k));
        if (k >= 1) { clearInterval(timer); if (done) done(); }
      }, 40);
    }
    function play() {
      var p = a.play();
      if (p && p.then) p.then(function () { fade(0.35, 1500); }).catch(function (e) { console.warn('KAVACH music did not start:', e && e.message); });
    }
    function stop() { fade(0, 500, function () { a.pause(); }); }
    function remember(m) { muted = m; try { localStorage.setItem('kv-muted', m ? '1' : '0'); } catch (e) {} }

    // The page's own handler flips the button first (target phase); this runs after it, so aria-pressed is the truth.
    d.addEventListener('click', function (e) {
      if (!(e.target && e.target.closest && e.target.closest('#snd'))) return;
      if (pressed()) { remember(false); play(); } else { remember(true); stop(); }
    });
    // First click or Enter/Space anywhere: press the Sound button once, unless the person muted it before.
    function first(e) {
      if (started || muted) return;
      if (e.type === 'keydown' && e.key !== 'Enter' && e.key !== ' ') return;
      var b = btn();
      if (!b || typeof b.onclick !== 'function' || pressed()) return;   // page script not ready yet: try again later
      if (e.target && e.target.closest && e.target.closest('#snd')) return;
      started = true; b.click();
    }
    d.addEventListener('click', first, true);
    d.addEventListener('keydown', first, true);
    d.addEventListener('visibilitychange', function () {
      if (d.hidden) a.pause(); else if (pressed()) play();
    });
  }
  music();

  if (reduce || (seen && !force)) return;           // buttons and music still apply

  var boot = d.createElement('style');               // hides the page until the curtain is in place: no flash
  boot.id = 'kv-boot'; boot.textContent = 'html:not(.kv-go) body{visibility:hidden}html.kv-loading{background:#0d0a07}';
  d.head.appendChild(boot);
  h.classList.add('kv-loading');

  var failsafe = setTimeout(clean, 12000);           // if anything goes wrong the page still appears
  function clean() {
    var b = d.getElementById('kv-boot'), L = d.getElementById('kv-loader');
    if (b) b.remove();
    if (L) L.remove();
    h.classList.add('kv-go'); h.classList.remove('kv-loading'); h.style.overflow = '';
    clearTimeout(failsafe);
  }

  function start() {
    var L = d.createElement('div');
    L.id = 'kv-loader'; L.setAttribute('aria-hidden', 'true');
    if ((navigator.hardwareConcurrency || 8) <= 4) L.classList.add('kv-lite');   // skip the wet-edge filter on weak machines
    L.innerHTML =
      '<svg width="0" height="0" style="position:absolute" aria-hidden="true"><filter id="kv-paint" x="-10%" y="-10%" width="120%" height="120%">' +
      '<feTurbulence type="fractalNoise" baseFrequency="0.03" numOctaves="2" seed="7" result="n"/>' +
      '<feDisplacementMap in="SourceGraphic" in2="n" scale="12" xChannelSelector="R" yChannelSelector="G"/></filter></svg>' +
      '<div class="kv-word" lang="hi"><span class="kv-out">&#2325;&#2357;&#2330;</span>' +
      '<div class="kv-paint"><span class="kv-fill">&#2325;&#2357;&#2330;</span></div></div>' +
      '<div class="kv-meta"><b id="kv-pct">000</b><span>KAVACH // CONTAINMENT OS</span></div>';
    d.body.appendChild(L);
    h.classList.add('kv-go'); h.style.overflow = 'hidden';
    var F = L.querySelector('.kv-fill'), P = L.querySelector('#kv-pct'), t0 = null, D = 3200, skip = false;
    L.addEventListener('pointerdown', function () { skip = true; });
    function lift() {                                  // wait for the page's own loader to finish, then raise the curtain
      var w0 = Date.now();
      (function wait() {
        if (d.body.classList.contains('done') || Date.now() - w0 > 5000) {
          L.classList.add('kv-done'); h.style.overflow = '';
          try { sessionStorage.setItem(KEY, '1'); } catch (e) {}
          setTimeout(clean, 1300);
        } else setTimeout(wait, 80);
      })();
    }
    function step(ts) {
      if (t0 === null) t0 = ts;
      var k = skip ? 1 : Math.min((ts - t0) / D, 1), p = (1 - Math.pow(1 - k, 3)) * 100;
      F.style.setProperty('--kv-top', (100 - p) + '%');
      P.textContent = ('00' + Math.round(p)).slice(-3);
      if (k < 1) requestAnimationFrame(step); else setTimeout(lift, skip ? 0 : 500);
    }
    requestAnimationFrame(step);
  }
  function ready() {
    var font = d.fonts && d.fonts.load ? d.fonts.load('1em "Yatra One"', '\u0915\u0935\u091a').catch(function () {}) : Promise.resolve();
    var cap = new Promise(function (r) { setTimeout(r, 1500); });
    Promise.race([Promise.all([cssReady, font]), cap]).then(start);
  }
  if (d.readyState === 'loading') d.addEventListener('DOMContentLoaded', ready); else ready();
})();
