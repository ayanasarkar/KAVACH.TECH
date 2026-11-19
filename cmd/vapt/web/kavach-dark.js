/* KAVACH landing: dark theme only. Load it first in <head>, before kavach-pro.js.
   It keeps data-theme="dark", hides the theme button, and answers any saved "theme" setting with "dark".
   To undo it, delete the <script src="/kavach-dark.js"> line from landing.html. */
(function () {
  var de = document.documentElement;
  try { var get = Storage.prototype.getItem; Storage.prototype.getItem = function (k) { return /theme/i.test(String(k)) ? 'dark' : get.call(this, k); }; } catch (e) {}
  function lock() { if (de.getAttribute('data-theme') !== 'dark') de.setAttribute('data-theme', 'dark'); if (de.classList.contains('light')) de.classList.remove('light'); }
  lock();
  new MutationObserver(lock).observe(de, { attributes: true, attributeFilter: ['data-theme', 'class'] });
  var s = document.createElement('style'); s.textContent = '[data-theme-toggle]{display:none!important}'; de.appendChild(s);
  addEventListener('click', function (e) { if (e.target.closest && e.target.closest('[data-theme-toggle]')) { e.stopImmediatePropagation(); e.preventDefault(); } }, true);
})();
