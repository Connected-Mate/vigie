/* Vigie site. Every feature fails safe: no storage, no clipboard, no observer → the page still reads and works.
   No network call, no cookie, no tracker. */
(function () {
  'use strict';
  var doc = document;
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  function all(sel, root) { return Array.prototype.slice.call((root || doc).querySelectorAll(sel)); }

  // Remember an explicit language choice so the root redirect never fights the visitor.
  all('[data-lang][data-lang-key]').forEach(function (link) {
    link.addEventListener('click', function () {
      try { localStorage.setItem(link.getAttribute('data-lang-key'), link.getAttribute('data-lang')); } catch (e) {}
    });
  });

  // Copy-the-prompt buttons. The prompt text lives in data-copy and is never displayed.
  var live;
  function announce(msg) {
    if (!live) {
      live = doc.createElement('p');
      live.className = 'sr-only';
      live.setAttribute('role', 'status');
      live.setAttribute('aria-live', 'polite');
      doc.body.appendChild(live);
    }
    live.textContent = '';
    setTimeout(function () { live.textContent = msg; }, 60);
  }
  function legacyCopy(text) {
    try {
      var ta = doc.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0';
      doc.body.appendChild(ta);
      ta.select();
      var ok = doc.execCommand('copy');
      doc.body.removeChild(ta);
      return !!ok;
    } catch (e) { return false; }
  }
  all('[data-copy]').forEach(function (btn) {
    var label = btn.querySelector('[data-copy-label]') || btn;
    var original = label.textContent;
    var hint = btn.parentNode.parentNode.querySelector('[data-copy-hint]');
    var timer = null;
    // Nothing could copy (old browser, blocked clipboard): say so and hand over the guide link. Never the prompt itself.
    function failed() {
      var msg = btn.getAttribute('data-copy-fail'), url = btn.getAttribute('data-guide');
      if (!msg || !url) return;
      clearTimeout(timer);
      announce(msg + ' ' + url);
      if (!hint) return;
      hint.textContent = msg + ' ';
      var a = doc.createElement('a');
      a.href = url; a.rel = 'noopener'; a.textContent = url.replace(/^https?:\/\//, '');
      hint.appendChild(a);
      hint.removeAttribute('aria-hidden');
      hint.classList.add('is-on');
    }
    function done() {
      if (hint) hint.setAttribute('aria-hidden', 'true');
      announce(btn.getAttribute('data-copied'));
      btn.style.minWidth = btn.offsetWidth + 'px'; // the button keeps its size, its neighbours do not jump
      label.textContent = btn.getAttribute('data-copied-short') || btn.getAttribute('data-copied');
      btn.classList.add('is-copied');
      if (hint) { hint.textContent = btn.getAttribute('data-copied'); hint.classList.add('is-on'); }
      clearTimeout(timer);
      timer = setTimeout(function () {
        label.textContent = original; btn.classList.remove('is-copied');
        if (hint) hint.classList.remove('is-on');
      }, 3200);
    }
    function fallback(text) {
      var ok = legacyCopy(text);
      try { btn.focus(); } catch (e) {} // the helper field took the focus: give it back
      if (ok) done(); else failed();
    }
    btn.addEventListener('click', function () {
      var text = btn.getAttribute('data-copy');
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallback(text); });
      } else { fallback(text); }
    });
  });

  // Tabs (WAI-ARIA pattern: arrows move, Home/End jump, one tab stop).
  function tabs(list, onSelect) {
    var items = all('[role="tab"]', list);
    function select(tab, focus) {
      items.forEach(function (t) {
        var on = t === tab;
        t.setAttribute('aria-selected', on ? 'true' : 'false');
        t.tabIndex = on ? 0 : -1;
        var panel = doc.getElementById(t.getAttribute('aria-controls'));
        if (panel) panel.hidden = !on;
      });
      if (focus) tab.focus();
      if (onSelect) onSelect(tab);
    }
    items.forEach(function (tab, i) {
      tab.addEventListener('click', function () { select(tab, false); });
      tab.addEventListener('keydown', function (e) {
        var k = e.key, n = items.length, to = null;
        if (k === 'ArrowRight' || k === 'ArrowDown') to = items[(i + 1) % n];
        else if (k === 'ArrowLeft' || k === 'ArrowUp') to = items[(i - 1 + n) % n];
        else if (k === 'Home') to = items[0];
        else if (k === 'End') to = items[n - 1];
        if (to) { e.preventDefault(); select(to, true); }
      });
    });
    return { select: select, items: items };
  }
  all('[data-tabs]').forEach(function (box) {
    all('[data-tabhide]', box).forEach(function (p) { p.hidden = true; });
    tabs(box.querySelector('[role="tablist"]'));
  });

  // The watch: the lookout looks at each tree, smoke and fire appear, the real report comes in.
  var hero = doc.querySelector('[data-demo]');
  if (hero) {
    var slip = hero.querySelector('.slip');
    var gaze = hero.querySelector('.gaze');
    var reticle = hero.querySelector('.reticle');
    var pkgs = {};
    all('.pkg', hero).forEach(function (g) { pkgs[g.getAttribute('data-pkg')] = g; });
    var timers = [];
    var playing = false;
    function aim(id) {
      var g = pkgs[id];
      if (!g || !gaze) return;
      var x = g.getAttribute('data-x'), y = +g.getAttribute('data-top') + 34;
      gaze.setAttribute('x2', x); gaze.setAttribute('y2', y);
      reticle.setAttribute('cx', x); reticle.setAttribute('cy', y);
      hero.classList.add('is-looking');
      Object.keys(pkgs).forEach(function (k) { pkgs[k].classList.toggle('is-selected', k === id); });
    }
    function spot(id) {
      if (pkgs[id]) pkgs[id].classList.add('is-spotted');
      var t = doc.getElementById('tab-' + id);
      if (t) t.classList.add('is-spotted');
    }
    function finish() {
      timers.forEach(clearTimeout); timers = [];
      playing = false;
      Object.keys(pkgs).forEach(spot);
      slip.classList.remove('is-scanning');
      slip.classList.add('is-ready');
    }
    var tl = tabs(hero.querySelector('[role="tablist"]'), function (tab) {
      if (playing) finish();
      aim(tab.getAttribute('data-pkg'));
    });
    function tabOf(id) { return doc.getElementById('tab-' + id); }
    function play() {
      finish();
      if (reduce) { tl.select(tabOf('log4j'), false); return; }
      playing = true;
      hero.classList.add('demo-armed');
      all('.is-spotted', hero).forEach(function (el) { el.classList.remove('is-spotted'); });
      slip.classList.remove('is-ready');
      slip.classList.add('is-scanning');
      hero.classList.remove('is-looking');
      var order = ['leftpad', 'express', 'lodash', 'log4j'];
      order.forEach(function (id, i) {
        timers.push(setTimeout(function () { aim(id); }, 1500 + i * 950));
        timers.push(setTimeout(function () { spot(id); }, 1500 + i * 950 + 480));
      });
      timers.push(setTimeout(function () {
        playing = false;
        slip.classList.remove('is-scanning');
        slip.classList.add('is-ready');
        tl.select(tabOf('log4j'), false);
        playing = false;
      }, 1500 + order.length * 950 + 250));
    }
    Object.keys(pkgs).forEach(function (id) {
      pkgs[id].addEventListener('click', function () { tl.select(tabOf(id), false); });
    });
    var replay = hero.querySelector('[data-replay]');
    var freeze = hero.querySelector('[data-freeze]');
    function setFrozen(on) {
      hero.classList.toggle('is-frozen', on);
      if (!freeze) return;
      freeze.setAttribute('aria-pressed', on ? 'true' : 'false');
      freeze.querySelector('[data-freeze-label]').textContent = freeze.getAttribute(on ? 'data-on' : 'data-off');
    }
    if (freeze) {
      if (reduce) freeze.hidden = true;
      freeze.addEventListener('click', function () {
        var on = !hero.classList.contains('is-frozen');
        if (on && playing) finish();
        setFrozen(on);
      });
    }
    if (replay) replay.addEventListener('click', function () { setFrozen(false); play(); });
    play();
    // Nothing loops while the scene is out of sight.
    if ('IntersectionObserver' in window) {
      new IntersectionObserver(function (entries) { hero.classList.toggle('is-away', !entries[0].isIntersecting); }).observe(hero);
    }

    // Depth: the ridges slide a little on scroll and under the pointer. Transform only.
    var layers = all('.lay', hero).map(function (el) { return { el: el, d: parseFloat(el.getAttribute('data-depth')) || 0 }; });
    if (!reduce && layers.length && window.requestAnimationFrame) {
      var sy = 0, mx = 0, ticking = false;
      var fine = window.matchMedia && window.matchMedia('(hover: hover) and (pointer: fine)').matches;
      var draw = function () {
        ticking = false;
        layers.forEach(function (l) {
          l.el.style.transform = 'translate3d(' + (mx * l.d * -70).toFixed(2) + 'px,' + (sy * (l.d - .3) * .28).toFixed(2) + 'px,0)';
        });
      };
      var ask = function () { if (!ticking) { ticking = true; requestAnimationFrame(draw); } };
      window.addEventListener('scroll', function () {
        var y = window.pageYOffset || 0;
        if (y > hero.offsetHeight) return;
        sy = y; ask();
      }, { passive: true });
      if (fine) hero.addEventListener('pointermove', function (e) { mx = e.clientX / window.innerWidth - .5; ask(); });
    }
  }

  // Scroll reveal: sections glide in once. Skipped with reduced motion or without IntersectionObserver.
  var reveals = all('[data-reveal]');
  if (!reduce && 'IntersectionObserver' in window && reveals.length) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        e.target.classList.add('is-in');
        io.unobserve(e.target);
        setTimeout(function () { e.target.classList.add('is-done'); }, 1800);
      });
    }, { rootMargin: '0px 0px -4% 0px' });
    reveals.forEach(function (el) { el.classList.add('will-reveal'); io.observe(el); });
  }

  // Quick-nav capsule appears once the hero is scrolled past.
  var capsule = doc.querySelector('.capsule');
  if (capsule && hero && 'IntersectionObserver' in window) {
    new IntersectionObserver(function (entries) {
      capsule.classList.toggle('is-on', !entries[0].isIntersecting);
    }).observe(hero);
    var foot = doc.querySelector('.foot__in');
    if (foot) new IntersectionObserver(function (entries) {
      capsule.classList.toggle('is-end', entries[0].isIntersecting);
    }).observe(foot);
  }
})();
