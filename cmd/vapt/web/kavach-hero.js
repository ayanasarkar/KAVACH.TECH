/* KAVACH painted hero + interlude. Load in <head> WITHOUT defer. Needs kavach-hero.css.
   1. Hero: a dark oil veil is dragged away in bristle strokes, and the wordmark resolves out of wet paint like a film title; vermilion powder floats up and flees the cursor.
   2. Interlude (before Act 04): your video, repainted live in WebGL as oil paint. It opens like a wet brush
      stroke as you scroll in; drag the mouse across it and the paint smears.
   3. Headings smear sideways while you scroll fast, then settle.
   4. Karna's armour: a pinned scroll scene (Indra, disguised, asks for the kavach) that maps the myth to prompt injection.
   Video: cmd/vapt/web/kavach-epic.mp4 (missing file = no interlude). Override: window.KV_VIDEO = 'x.mp4'.
   To undo: delete the kavach-hero.js <script> and the kavach-hero.css <link> from landing.html. */
(function () {
  var RM = matchMedia('(prefers-reduced-motion:reduce)').matches, de = document.documentElement;
  var lite = (navigator.hardwareConcurrency || 8) <= 4;
  var clamp = function (x, a, b) { return Math.max(a, Math.min(b, x)); };
  if (!RM) { de.classList.add('kv-write'); setTimeout(function () { de.classList.remove('kv-write'); }, 12000); }

  /* ================= vermilion powder (reusable) ================= */
  function makePowder(host, o) {
    var cv = document.createElement('canvas'), g = cv.getContext('2d'), D = Math.min(devicePixelRatio || 1, 1.5),
      W = 0, H = 0, P = [], mx = -999, my = -999, on = true, tk = 0, COL = ['200,55,74', '224,72,92', '224,122,31', '242,205,122'];
    cv.setAttribute('aria-hidden', 'true');
    cv.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;z-index:' + o.z + ';pointer-events:none';
    host.prepend(cv);
    function size() { var r = host.getBoundingClientRect(); W = r.width; H = r.height; cv.width = W * D; cv.height = H * D; g.setTransform(D, 0, 0, D, 0, 0); }
    size(); addEventListener('resize', size);
    if (window.ResizeObserver) new ResizeObserver(size).observe(host);
    host.addEventListener('pointermove', function (e) { var r = host.getBoundingClientRect(); mx = e.clientX - r.left; my = e.clientY - r.top; });
    new IntersectionObserver(function (es) { on = es[0].isIntersecting; }).observe(host);
    function spawn(x, y, burst) {
      var a = burst ? Math.random() * 6.283 : -1.57 + (Math.random() - .5) * 1.4, s = burst ? .5 + Math.random() * 2.4 : .12 + Math.random() * .4;
      P.push({ x: x, y: y, vx: Math.cos(a) * s, vy: Math.sin(a) * s, r: (burst ? 1 : .8) + Math.random() * 2, l: 0, m: burst ? 80 + Math.random() * 100 : 320 + Math.random() * 320, c: COL[Math.random() * 4 | 0], puff: Math.random() < .07 });
    }
    (function loop() {
      requestAnimationFrame(loop); if (!on || document.hidden) return; tk++;
      g.clearRect(0, 0, W, H); g.globalCompositeOperation = 'lighter';
      if (P.length < o.max && Math.random() < o.rate()) spawn(Math.random() * W, H * (o.low + Math.random() * (1 - o.low)), false);
      for (var i = P.length - 1; i >= 0; i--) {
        var p = P[i]; p.l++; if (p.l > p.m) { P.splice(i, 1); continue; }
        p.vx += Math.sin((p.y + tk) * .011 + p.x * .013) * .006; p.vy -= .0035; p.vx *= .988; p.vy *= .988;
        var dx = p.x - mx, dy = p.y - my, d = Math.hypot(dx, dy); if (d < 120 && d > 1) { p.vx += dx / d * .22; p.vy += dy / d * .22; }
        p.x += p.vx; p.y += p.vy;
        var al = Math.sin(Math.PI * p.l / p.m) * .85;
        if (p.puff) { var gr = g.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r * 16); gr.addColorStop(0, 'rgba(' + p.c + ',' + al * .16 + ')'); gr.addColorStop(1, 'rgba(' + p.c + ',0)'); g.fillStyle = gr; g.fillRect(p.x - p.r * 16, p.y - p.r * 16, p.r * 32, p.r * 32); }
        else { g.fillStyle = 'rgba(' + p.c + ',' + al + ')'; g.beginPath(); g.arc(p.x, p.y, p.r, 0, 6.283); g.fill(); }
      }
    })();
    return { spawn: spawn, dims: function () { return [W, H]; } };
  }

  /* ================= WebGL oil paint ================= */
  var VS = 'attribute vec2 p;varying vec2 uv;void main(){uv=vec2(p.x*.5+.5,.5-p.y*.5);gl_Position=vec4(p,0.,1.);}';
  var FS = [
    '#ifdef GL_FRAGMENT_PRECISION_HIGH', 'precision highp float;', '#else', 'precision mediump float;', '#endif',
    'varying vec2 uv;uniform sampler2D T;uniform vec2 px;uniform float t,rev,asp;uniform vec4 m[10];uniform float ms[10];',
    'float hash(vec2 p){return fract(sin(dot(p,vec2(127.1,311.7)))*43758.5453);}',
    'float noise(vec2 p){vec2 i=floor(p),f=fract(p);f=f*f*(3.-2.*f);return mix(mix(hash(i),hash(i+vec2(1.,0.)),f.x),mix(hash(i+vec2(0.,1.)),hash(i+vec2(1.,1.)),f.x),f.y);}',
    'float fbm(vec2 p){float a=.5,s=0.;for(int i=0;i<4;i++){s+=a*noise(p);p*=2.03;a*=.5;}return s;}',
    /* Kuwahara: four quadrants, keep the calmest one. This is what turns video into flat brush patches. */
    'void reg(vec2 q,vec2 o,out vec3 mean,out float v){vec3 s=vec3(0.),s2=vec3(0.);',
    ' for(int j=0;j<4;j++)for(int i=0;i<4;i++){vec3 c=texture2D(T,q+o*vec2(float(i),float(j))*px*1.7).rgb;s+=c;s2+=c*c;}',
    ' mean=s/16.;vec3 d=abs(s2/16.-mean*mean);v=d.r+d.g+d.b;}',
    'vec3 kuw(vec2 q){vec3 a,b,c,d;float va,vb,vc,vd;',
    ' reg(q,vec2(-1.,-1.),a,va);reg(q,vec2(1.,-1.),b,vb);reg(q,vec2(-1.,1.),c,vc);reg(q,vec2(1.,1.),d,vd);',
    ' vec3 r=a;float mv=va;if(vb<mv){mv=vb;r=b;}if(vc<mv){mv=vc;r=c;}if(vd<mv){r=d;}return r;}',
    'float hgt(vec2 p){return fbm(p)*.7+.3*noise(p*3.1);}',
    'void main(){',
    ' vec2 sp=vec2(uv.x*asp,uv.y);vec2 q=uv;',
    ' q+=(vec2(fbm(sp*3.+t*.04),fbm(sp*3.+9.-t*.04))-.5)*.010;',                       /* paint never quite sits still */
    ' for(int i=0;i<10;i++){vec2 d=(uv-m[i].xy)*vec2(asp,1.);q-=m[i].zw*exp(-dot(d,d)*55.)*ms[i]*1.7;}', /* mouse drags the paint */
    ' vec3 c=kuw(q);',
    ' float l=dot(c,vec3(.299,.587,.114));c=mix(vec3(l),c,1.3);c=(c-.5)*1.12+.5;c*=vec3(1.05,.98,.9);',
    ' mat2 R=mat2(.906,.423,-.423,.906);vec2 bq=R*sp*vec2(70.,9.);',                    /* bristle streaks */
    ' float h0=hgt(bq),hx=hgt(bq+vec2(.4,0.)),hy=hgt(bq+vec2(0.,.4));',
    ' vec3 n=normalize(vec3(h0-hx,h0-hy,.35));float df=dot(n,normalize(vec3(-.4,.6,.7)));',
    ' c*=.88+.24*df;c+=pow(max(df,0.),9.)*.05;c*=.965+.035*sin(sp.x*900.)*sin(sp.y*900.);', /* impasto light + canvas weave */
    ' vec2 e=min(uv,1.-uv)*vec2(asp,1.);float ed=min(e.x,e.y);',
    ' float rag=(fbm(sp*14.+3.)-.5)*.05+(fbm(sp*3.-t*.02)-.5)*.04;',
    ' float ee=ed+rag;float body=smoothstep(-.002,.007,ee);',
    ' float gold=smoothstep(.002,.010,ee)*(1.-smoothstep(.016,.034,ee));',        /* gold-leaf edge, ragged */
    ' c=mix(c,vec3(.95,.76,.36)*(.7+.55*fbm(sp*40.)),gold*.95);',
    ' vec2 cp=(uv-.5)*vec2(asp,1.);float rd=length(cp)/(.5*sqrt(asp*asp+1.));',
    ' float rr=rd+(fbm(sp*6.+1.7)-.5)*.4;',
    ' float a=1.-smoothstep(rev-.10,rev,rr);',
    ' float rim=smoothstep(rev-.20,rev-.07,rr)*(1.-smoothstep(rev-.07,rev,rr));',       /* vermilion rim while it opens */
    ' c=mix(c,vec3(.88,.28,.36),rim*.85);',
    ' float A=body*a;gl_FragColor=vec4(c*A,A);}'
  ].join('\n');

  function glPaint(cvs, video) {
    var gl = cvs.getContext('webgl', { alpha: true, premultipliedAlpha: true, antialias: false });
    if (!gl) return null;
    function sh(type, src) { var s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s); return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null; }
    var vs = sh(gl.VERTEX_SHADER, VS), fs = sh(gl.FRAGMENT_SHADER, FS); if (!vs || !fs) return null;
    var pr = gl.createProgram(); gl.attachShader(pr, vs); gl.attachShader(pr, fs); gl.linkProgram(pr);
    if (!gl.getProgramParameter(pr, gl.LINK_STATUS)) return null;
    gl.useProgram(pr);
    var buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    var pl = gl.getAttribLocation(pr, 'p'); gl.enableVertexAttribArray(pl); gl.vertexAttribPointer(pl, 2, gl.FLOAT, false, 0, 0);
    var tex = gl.createTexture(); gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE); gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR); gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    var U = {}; ['px', 't', 'rev', 'asp', 'T'].forEach(function (n) { U[n] = gl.getUniformLocation(pr, n); });
    U.m = gl.getUniformLocation(pr, 'm[0]') || gl.getUniformLocation(pr, 'm');
    U.ms = gl.getUniformLocation(pr, 'ms[0]') || gl.getUniformLocation(pr, 'ms');
    gl.uniform1i(U.T, 0);
    gl.enable(gl.BLEND); gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
    var sx = new Float32Array(40), ss = new Float32Array(10), si = 0, lx = null, ly = null, got = false;
    function smudgeAt(x, y) {
      if (lx !== null) {
        var vx = x - lx, vy = y - ly, L = Math.hypot(vx, vy);
        if (L > .002) { var k = Math.min(L, .05) / L; sx.set([x, y, vx * k, vy * k], si * 4); ss[si] = 1; si = (si + 1) % 10; }
      }
      lx = x; ly = y;
    }
    cvs.addEventListener('pointermove', function (e) { var r = cvs.getBoundingClientRect(); smudgeAt((e.clientX - r.left) / r.width, (e.clientY - r.top) / r.height); });
    cvs.addEventListener('pointerleave', function () { lx = null; });
    return {
      draw: function (time, rev, asp) {
        try { gl.bindTexture(gl.TEXTURE_2D, tex); gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, video); got = true; } catch (e) { if (!got) return; }
        gl.viewport(0, 0, cvs.width, cvs.height); gl.clearColor(0, 0, 0, 0); gl.clear(gl.COLOR_BUFFER_BIT);
        for (var i = 0; i < 10; i++) ss[i] *= .972;
        gl.uniform2f(U.px, 1 / cvs.width, 1 / cvs.height); gl.uniform1f(U.t, time / 1000); gl.uniform1f(U.rev, rev); gl.uniform1f(U.asp, asp);
        gl.uniform4fv(U.m, sx); gl.uniform1fv(U.ms, ss);
        gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      }
    };
  }

  /* ================= SVG helpers ================= */
  function defs() {
    document.body.insertAdjacentHTML('beforeend', '<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>' +
      '<filter id="kv-rough" x="-5%" y="-5%" width="110%" height="110%"><feTurbulence type="fractalNoise" baseFrequency=".03" numOctaves="2" seed="3" result="n"/><feDisplacementMap in="SourceGraphic" in2="n" scale="7" xChannelSelector="R" yChannelSelector="G"/></filter>' +
      '<filter id="kv-smear" x="-8%" y="-30%" width="116%" height="160%"><feTurbulence type="fractalNoise" baseFrequency=".003 .045" numOctaves="1" seed="11" result="n"/><feDisplacementMap id="kv-smear-d" in="SourceGraphic" in2="n" scale="0" xChannelSelector="R" yChannelSelector="G" result="d"/><feGaussianBlur in="d" stdDeviation=".5 .15"/></filter>' +
      '<filter id="kv-wet" x="-10%" y="-20%" width="120%" height="140%"><feTurbulence type="fractalNoise" baseFrequency=".008 .035" numOctaves="2" seed="8" result="n"/><feDisplacementMap id="kv-wet-d" in="SourceGraphic" in2="n" scale="0" xChannelSelector="R" yChannelSelector="G"/><feGaussianBlur id="kv-wet-b" stdDeviation="0"/></filter>' +
      '</defs></svg>');
  }

  /* ================= hero: wordmark written on + powder ================= */
  function heroPart(hero, wm) {
    if (RM) { de.classList.remove('kv-write'); return; }
    var pw = makePowder(hero, { z: -1, max: lite ? 70 : 150, rate: function () { return .3; }, low: .45 });
    function firstContent() { for (var n = wm.firstChild; n; n = n.nextSibling) { if (n.nodeType === 1 || (n.nodeType === 3 && n.nodeValue.trim())) return n; } return wm; }
    function start() {
      var rg = document.createRange(); rg.selectNodeContents(firstContent());
      var tr = rg.getBoundingClientRect(), el = wm.getBoundingClientRect(), hr = hero.getBoundingClientRect(), x0 = tr.left - el.left, tw = tr.width, t0 = performance.now(), DUR = 3400;
      veil(); wm.classList.add('kv-writing');
      (function step(now) {
        var k = Math.min(1, (now - t0) / DUR), p = k < .5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2, edge = x0 - 10 + p * (tw + 90);
        wm.style.setProperty('--w', edge + 'px');
        var wl = (1 - p) * (1 - p); document.getElementById('kv-wet-d').setAttribute('scale', (wl * 110).toFixed(1)); document.getElementById('kv-wet-b').setAttribute('stdDeviation', (wl * 9).toFixed(2) + ' ' + (wl * 2).toFixed(2));
        var ex = Math.min(x0 + tw, Math.max(x0, edge - 35)) + el.left - hr.left;
        for (var i = 0; i < 4; i++) pw.spawn(ex, tr.top - hr.top + Math.random() * tr.height, true);
        if (k < 1) requestAnimationFrame(step);
        else {
          for (var j = 0; j < 90; j++) pw.spawn(tr.left - hr.left + Math.random() * tw, tr.top - hr.top + Math.random() * tr.height, true);
          wm.style.setProperty('--w', '9999px'); de.classList.remove('kv-write');
          setTimeout(function () { wm.classList.remove('kv-writing'); wm.style.removeProperty('--w'); }, 900);
        }
      })(t0);
    }
    var w0 = performance.now();
    (function wait() { if ((document.body.classList.contains('done') && !de.classList.contains('kv-loading')) || performance.now() - w0 > 7000) start(); else requestAnimationFrame(wait); })();
  }

  /* ================= interlude: the painted window before Act 04 ================= */
  function interlude() {
    var src = window.KV_VIDEO || 'kavach-epic.mp4';
    var anchor = document.getElementById('ch') || document.querySelector('section[data-act="3"]');
    if (!anchor) return;
    fetch(src, { method: 'HEAD' }).then(function (r) {
      var ct = r.headers.get('content-type') || '';
      if (r.ok && (ct.indexOf('video') >= 0 || ct.indexOf('octet') >= 0 || !ct)) build();
    }).catch(function () { });

    function build() {
      var inter = document.createElement('div'); inter.className = 'kv-inter'; inter.id = 'kv-inter';
      inter.innerHTML = '<div class="kv-stage"><div class="kv-ghost" lang="hi" aria-hidden="true">अभेद्य</div>' +
        '<div class="kv-art"><canvas class="kv-gl"></canvas><video muted loop playsinline preload="none" disablepictureinpicture aria-label="Kavach in the Mahabharata, painted"></video>' +
        '<p class="kv-cap"><span class="kv-cap-hi" lang="hi">अभेद्य कवच</span><span class="kv-cap-en">The armour that could not be pierced.</span></p></div></div>';
      anchor.parentNode.insertBefore(inter, anchor);
      var stage = inter.firstChild, art = stage.querySelector('.kv-art'), cvs = art.querySelector('canvas'), v = art.querySelector('video'),
        ghost = stage.querySelector('.kv-ghost'), cap = stage.querySelector('.kv-cap-hi'), capEn = stage.querySelector('.kv-cap-en');
      v.muted = true;
      var painter = glPaint(cvs, v);
      if (!painter) { art.classList.add('nogl'); cvs.remove(); }
      var powder = RM ? null : makePowder(stage, { z: 3, max: lite ? 50 : 110, low: .3, rate: function () { return active ? .35 : 0; } });
      var active = false, vis = false, burst = false, asp = 16 / 9, tryT = 0;

      function layout() {
        asp = (v.videoWidth && v.videoHeight) ? v.videoWidth / v.videoHeight : 16 / 9;
        var small = innerWidth < 700, maxW = Math.min(1120, innerWidth * (small ? .94 : .84)), maxH = innerHeight * (small ? .52 : .64);
        var w = Math.min(maxW, maxH * asp), h = w / asp;
        art.style.width = w + 'px'; art.style.height = h + 'px';
        if (painter) { var s = lite ? .6 : Math.min(devicePixelRatio || 1, 1.25); cvs.width = Math.round(w * s); cvs.height = Math.round(h * s); }
      }
      layout(); addEventListener('resize', layout);
      v.addEventListener('loadedmetadata', layout);
      v.addEventListener('loadeddata', function () { if (RM) { try { v.currentTime = .5; } catch (e) { } } });

      /* load only when the reader is nearly there (the file can be large) */
      var loaded = false;
      new IntersectionObserver(function (es) { if (es[0].isIntersecting && !loaded) { loaded = true; v.src = src; v.load(); } }, { rootMargin: '150% 0px' }).observe(inter);
      new IntersectionObserver(function (es) {
        vis = es[0].isIntersecting;
        if (vis && !RM) { v.play().catch(function () { }); } else { v.pause(); }
      }).observe(inter);

      (function frame(now) {
        requestAnimationFrame(frame);
        if (!vis || document.hidden) return;
        if (!RM && v.paused && v.readyState >= 2 && now - tryT > 1200) { tryT = now; v.play().catch(function () { }); }
        var r = inter.getBoundingClientRect(), H = innerHeight;
        var q = RM ? 1 : clamp((H * .85 - r.top) / (H * .85), 0, 1);     /* 0 to 1 while it rises into view */
        var p = clamp(-r.top / (r.height - H), 0, 1);                   /* 0 to 1 while it is pinned */
        var e = q * q * (3 - 2 * q), rev = RM ? 2 : e * 1.55;
        active = q > .5;
        if (!burst && q > .62 && powder) { burst = true; var d = powder.dims(); for (var i = 0; i < 130; i++) powder.spawn(d[0] / 2 + (Math.random() - .5) * d[0] * .6, d[1] / 2 + (Math.random() - .5) * d[1] * .5, true); }
        if (!RM) {
          art.style.transform = 'scale(' + (.94 + .06 * e + .05 * p).toFixed(4) + ')';
          ghost.style.transform = 'translate3d(' + ((.5 - p) * 10).toFixed(2) + 'vw,0,0)';
          ghost.style.opacity = (.3 + .7 * e).toFixed(3);
        }
        var k = RM ? 112 : clamp((p - .06) / .22, 0, 1) * 112;
        cap.style.setProperty('--k', k.toFixed(1)); capEn.style.opacity = clamp((k - 90) / 22, 0, 1).toFixed(2);
        if (painter) { if (v.readyState >= 2) painter.draw(now, rev, asp); }
        else { art.style.setProperty('--rv', (rev * 62).toFixed(1)); }
      })(performance.now());
    }
  }

  /* ================= headings smear while scrolling fast ================= */
  function scrollSmear() {
    var disp = document.getElementById('kv-smear-d'), els = document.querySelectorAll('.pane h2, #home h1'), ly = scrollY, vel = 0, on = false;
    if (!disp || !els.length) return;
    (function f() {
      requestAnimationFrame(f);
      var y = scrollY, dv = Math.abs(y - ly); ly = y; vel += (dv - vel) * .25;
      var s = Math.min(vel * 1.1, 20);
      if (s > 1.4) { disp.setAttribute('scale', s.toFixed(1)); if (!on) { on = true; els.forEach(function (n) { n.classList.add('kv-smearing'); }); } }
      else if (on) { on = false; els.forEach(function (n) { n.classList.remove('kv-smearing'); }); }
    })();
  }

  /* ================= movie entry: oil veil dragged away in gold-edged bristle strokes ================= */
  function veil() {
    var cv = document.createElement('canvas'), g = cv.getContext('2d'), W = cv.width = innerWidth, H = cv.height = innerHeight, N = 12, B = [], t0 = performance.now();
    cv.setAttribute('aria-hidden', 'true'); cv.style.cssText = 'position:fixed;left:0;top:0;width:100vw;height:100vh;z-index:70;pointer-events:none'; document.body.appendChild(cv);
    g.fillStyle = '#0e0609'; g.fillRect(0, 0, W, H);
    for (var i = 0; i < N; i++) B.push({ y: (i + .5) * H / N, h: H / N, d: i * .045 + Math.random() * .25, x: -60 });
    (function f(now) {
      var k = (now - t0) / 2400;
      B.forEach(function (b) {
        var p = clamp((k - b.d) / .62, 0, 1), nx = -60 + (1 - Math.pow(1 - p, 3)) * (W + 220);
        if (nx <= b.x) return;
        g.globalCompositeOperation = 'destination-out'; g.lineCap = 'round';
        for (var j = 0; j < 7; j++) { var y = b.y + (j - 3) * b.h / 6.5 + (Math.random() - .5) * 5; g.lineWidth = b.h / 5 + Math.random() * 6; g.beginPath(); g.moveTo(b.x - 4, y); g.lineTo(nx, y + (Math.random() - .5) * 6); g.stroke(); }
        if (p < 1) { g.globalCompositeOperation = 'source-over'; g.strokeStyle = 'rgba(242,205,122,.85)'; g.lineWidth = 3; g.beginPath(); g.moveTo(nx + 3, b.y - b.h * .45); g.lineTo(nx + 3 + (Math.random() - .5) * 8, b.y + b.h * .45); g.stroke(); }
        b.x = nx;
      });
      if (k < 1.4) requestAnimationFrame(f); else cv.remove();
    })(t0);
  }

  /* ================= Karna's armour: the myth as a prompt-injection parable ================= */
  function karna() {
    var at = document.getElementById('guard'); if (!at) return;
    var s = document.createElement('section'), rays = '', i; s.className = 'kv-kn'; s.id = 'kv-karna'; s.setAttribute('aria-label', 'Karna and the armour');
    for (i = 0; i < 36; i++) rays += '<line x1="0" y1="-132" x2="0" y2="' + -(i % 3 ? 150 : 176) + '" transform="rotate(' + i * 10 + ')"/>';
    var T = [['कर्ण किसी याचक को मना नहीं करते थे।', 'Karna never turned away anyone who asked.'],
      ['इन्द्र ब्राह्मण का वेश धरकर आए और उनसे कवच माँग लिया।', 'Indra arrived disguised as a Brahmin and asked for the armour.'],
      ['जो हर माँग मान ले, वह कर्ण है। कवच माँग को परखता है।', 'An agent that obeys every request is Karna at the door. Kavach checks the request first.']];
    s.innerHTML = '<div class="kv-kn-stage"><svg class="kv-kn-art" viewBox="-200 -200 400 400" aria-hidden="true"><g id="kv-kn-rays">' + rays + '</g><circle id="kv-kn-r1" r="112" transform="rotate(-90)"/><circle id="kv-kn-r2" r="96" transform="rotate(-90)"/><text class="kv-kn-t" y="22" text-anchor="middle" lang="hi">कवच</text></svg><div class="kv-kn-txt">' +
      T.map(function (t) { return '<p class="kv-kn-p"><b lang="hi">' + t[0] + '</b><span>' + t[1] + '</span></p>'; }).join('') + '</div></div>';
    at.parentNode.insertBefore(s, at);
    if (RM) return;
    var P = s.querySelectorAll('.kv-kn-p'), R = s.querySelector('#kv-kn-rays'), A = [[s.querySelector('#kv-kn-r1'), 703.7], [s.querySelector('#kv-kn-r2'), 603.2]], X = s.querySelector('.kv-kn-t'), C = [.12, .5, .88], q = 0;
    function upd() {
      q = 0; var b = s.getBoundingClientRect(), p = clamp(-b.top / (b.height - innerHeight), 0, 1), gp = Math.sin(Math.PI * clamp((p - .3) / .4, 0, 1));
      P.forEach(function (n, i) { var d = p - C[i]; n.style.opacity = clamp(1.6 - Math.abs(d) * 6, 0, 1).toFixed(2); n.style.transform = 'translateY(' + (-d * 70).toFixed(1) + 'px)'; });
      R.setAttribute('transform', 'rotate(' + (p * 80).toFixed(1) + ') scale(' + (1 + gp * .3).toFixed(3) + ')'); R.style.opacity = (1 - gp * .85).toFixed(2);
      A.forEach(function (a) { a[0].setAttribute('stroke-dasharray', (a[1] * (1 - .55 * gp)).toFixed(1) + ' ' + a[1]); });
      X.style.opacity = (1 - gp * .9).toFixed(2);
    }
    addEventListener('scroll', function () { if (!q) { q = 1; requestAnimationFrame(upd); } }, { passive: true }); addEventListener('resize', upd); upd();
  }

  document.addEventListener('DOMContentLoaded', function () {
    defs();
    var hero = document.getElementById('home'), wm = hero && hero.querySelector('.wm');
    if (hero && wm) heroPart(hero, wm); else de.classList.remove('kv-write');
    karna();
    interlude();
    if (!RM) scrollSmear();
  });
})();
