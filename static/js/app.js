(function () {
  'use strict';

  var body = document.body;
  var toggle = document.getElementById('sidebar-toggle');
  var mobileMenu = document.getElementById('mobile-menu');
  var mobileClose = document.getElementById('sidebar-close');
  var backdrop = document.getElementById('sidebar-backdrop');
  var desktopQuery = window.matchMedia('(min-width: 993px)');
  var STORAGE_KEY = 'phishguard.sidebar.collapsed';
  var root = document.documentElement;
  var themeToggle = document.getElementById('theme-toggle');
  var themeMeta = document.getElementById('theme-color-meta');
  var THEME_STORAGE_KEY = 'drishti.theme';

  function readTheme() {
    return root.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  }

  function saveTheme(theme) {
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch (error) {
      /* localStorage may be unavailable; the theme still applies for this page. */
    }
  }

  function applyTheme(theme) {
    var isLight = theme === 'light';
    root.setAttribute('data-theme', isLight ? 'light' : 'dark');

    if (themeMeta) {
      themeMeta.setAttribute('content', isLight ? '#f3f7fb' : '#081426');
    }

    if (themeToggle) {
      themeToggle.setAttribute('aria-checked', String(isLight));
      themeToggle.setAttribute(
        'aria-label',
        isLight ? 'Switch to dark mode' : 'Switch to light mode'
      );
      themeToggle.setAttribute(
        'title',
        isLight ? 'Switch to dark mode' : 'Switch to light mode'
      );
    }
  }

  applyTheme(readTheme());

  if (themeToggle) {
    themeToggle.addEventListener('click', function () {
      var next = readTheme() === 'light' ? 'dark' : 'light';
      applyTheme(next);
      saveTheme(next);
    });
  }

  window.addEventListener('storage', function (event) {
    if (event.key !== THEME_STORAGE_KEY) {
      return;
    }
    if (event.newValue === 'light' || event.newValue === 'dark') {
      applyTheme(event.newValue);
    }
  });

  function isDesktop() {
    return desktopQuery.matches;
  }

  function readCollapsed() {
    try {
      return window.localStorage.getItem(STORAGE_KEY) === '1';
    } catch (error) {
      return false;
    }
  }

  function saveCollapsed(collapsed) {
    try {
      window.localStorage.setItem(STORAGE_KEY, collapsed ? '1' : '0');
    } catch (error) {
      /* localStorage may be unavailable; the UI still works for this page. */
    }
  }

  function applyCollapsed(collapsed) {
    var shouldCollapse = Boolean(collapsed) && isDesktop();
    body.classList.toggle('sidebar-collapsed', shouldCollapse);

    if (toggle) {
      toggle.setAttribute('aria-expanded', String(!shouldCollapse));
      toggle.setAttribute(
        'aria-label',
        shouldCollapse ? 'Expand sidebar' : 'Collapse sidebar'
      );
    }
  }

  function openMobile() {
    body.classList.add('sidebar-open');
    if (mobileMenu) {
      mobileMenu.setAttribute('aria-expanded', 'true');
    }
    if (backdrop) {
      backdrop.hidden = false;
    }
  }

  function closeMobile() {
    body.classList.remove('sidebar-open');
    if (mobileMenu) {
      mobileMenu.setAttribute('aria-expanded', 'false');
    }
    if (backdrop) {
      backdrop.hidden = true;
    }
  }

  if (isDesktop() && readCollapsed()) {
    applyCollapsed(true);
  } else {
    applyCollapsed(false);
  }

  if (toggle) {
    toggle.addEventListener('click', function () {
      if (isDesktop()) {
        var next = !body.classList.contains('sidebar-collapsed');
        applyCollapsed(next);
        saveCollapsed(next);
      } else {
        closeMobile();
      }
    });
  }

  if (mobileMenu) {
    mobileMenu.addEventListener('click', function () {
      if (body.classList.contains('sidebar-open')) {
        closeMobile();
      } else {
        openMobile();
      }
    });
  }

  if (mobileClose) {
    mobileClose.addEventListener('click', closeMobile);
  }

  if (backdrop) {
    backdrop.addEventListener('click', closeMobile);
  }

  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') {
      closeMobile();
    }
  });

  var navLinks = document.querySelectorAll('.nav-item');
  for (var i = 0; i < navLinks.length; i += 1) {
    navLinks[i].addEventListener('click', function () {
      if (!isDesktop()) {
        closeMobile();
      }
    });
  }

  function handleBreakpointChange() {
    if (isDesktop()) {
      closeMobile();
      applyCollapsed(readCollapsed());
    } else {
      body.classList.remove('sidebar-collapsed');
      if (toggle) {
        toggle.setAttribute('aria-expanded', 'false');
      }
    }
  }

  if (typeof desktopQuery.addEventListener === 'function') {
    desktopQuery.addEventListener('change', handleBreakpointChange);
  } else if (typeof desktopQuery.addListener === 'function') {
    desktopQuery.addListener(handleBreakpointChange);
  }
})();
