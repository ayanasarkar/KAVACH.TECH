// Theme: light, dark, or follow the system until the person chooses. Loaded in <head> (not a module) so the
// right theme is set before first paint. Storage may be blocked (private window), so every access is guarded.
(function () {
  var KEY = 'vapt-theme', root = document.documentElement;
  function get() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function put(v) { try { localStorage.setItem(KEY, v); } catch (e) { /* ignore */ } }
  var mq = window.matchMedia ? matchMedia('(prefers-color-scheme: dark)') : null;
  function cur() { var s = get(); return s === 'dark' || s === 'light' ? s : (mq && mq.matches ? 'dark' : 'light'); }
  function apply(t) { root.setAttribute('data-theme', t); var m = document.querySelector('meta[name=theme-color]'); if (m) m.setAttribute('content', t === 'dark' ? '#1a0f10' : '#fffaf9'); document.dispatchEvent(new CustomEvent('themechange', { detail: t })); }
  apply(cur());
  if (mq && mq.addEventListener) mq.addEventListener('change', function () { if (!get()) apply(cur()); });
  var SVG = '<svg class="i-moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z"/></svg>' +
    '<svg class="i-sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M5.3 18.7l1.6-1.6M17.1 6.9l1.6-1.6"/></svg>';
  function wire() {
    document.querySelectorAll('[data-theme-toggle]').forEach(function (b) {
      if (b.dataset.wired) return; b.dataset.wired = '1';
      b.classList.add('theme-btn'); b.innerHTML = SVG; b.setAttribute('type', 'button');
      var lab = function () { b.setAttribute('aria-label', cur() === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'); b.title = b.getAttribute('aria-label'); };
      lab(); document.addEventListener('themechange', lab);
      b.addEventListener('click', function () { var n = cur() === 'dark' ? 'light' : 'dark'; put(n); apply(n); });
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire); else wire();
  window.vaptTheme = { cur: cur, wire: wire };
})();
