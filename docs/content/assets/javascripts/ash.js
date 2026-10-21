/* Progressive enhancements for the ASH documentation site. No runtime dependencies. */
(() => {
  "use strict";

  const root = document.documentElement;
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const menuButton = document.querySelector("[data-ash-menu]");
  const mobileMenu = document.getElementById("ash-mobile-menu");
  const searchToggle = document.getElementById("__search");
  const toast = document.querySelector("[data-ash-toast]");
  let toastTimer;
  let menuCloseTimer;
  let motionPaused = reducedMotion.matches;
  let demoRun = 0;

  const stored = (key) => {
    try { return localStorage.getItem(key); } catch { return null; }
  };
  const store = (key, value) => {
    try { localStorage.setItem(key, value); } catch { /* Storage is optional. */ }
  };
  if (stored("ash-motion") === "paused") motionPaused = true;

  // Keep Material's stored palette state behind a native, keyboard-accessible button.
  const palette = document.querySelector("[data-md-component='palette']");
  if (palette) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "md-header__button md-icon";
    palette.hidden = true;
    palette.after(button);
    const currentToggle = () => palette.querySelector("label[for]:not([hidden])");
    function updateThemeButton() {
      const label = currentToggle();
      button.hidden = !label;
      if (!label) return;
      button.title = label.title;
      button.setAttribute("aria-label", label.title);
      const themeIcons = document.querySelector("[data-ash-theme-icons]")?.content;
      const scheme = root.getAttribute("data-md-color-scheme")
        || document.body.getAttribute("data-md-color-scheme") || "slate";
      const glyph = themeIcons?.querySelector(`[data-color-scheme="${scheme === "slate" ? "default" : "slate"}"]`);
      button.replaceChildren(...[...(glyph || label).childNodes].map((child) => child.cloneNode(true)));
    }
    button.addEventListener("click", () => {
      const label = currentToggle();
      if (label) document.getElementById(label.htmlFor)?.click();
    });
    new MutationObserver(updateThemeButton).observe(palette, {
      subtree: true, attributes: true, attributeFilter: ["hidden"]
    });
    updateThemeButton();
  }

  function notify(message) {
    if (!toast) return;
    clearTimeout(toastTimer);
    toast.textContent = message;
    toast.classList.add("is-visible");
    toastTimer = setTimeout(() => toast.classList.remove("is-visible"), 2600);
  }

  function closeMenu(restoreFocus = false) {
    if (!mobileMenu || !menuButton) return;
    clearTimeout(menuCloseTimer);
    mobileMenu.classList.remove("is-open");
    menuButton.setAttribute("aria-expanded", "false");
    menuButton.setAttribute("aria-label", "Open navigation");
    const finish = () => {
      mobileMenu.close();
      mobileMenu.hidden = true;
      if (restoreFocus) menuButton.focus();
    };
    // Correctness is independent of transition events, including rapid toggles.
    if (!mobileMenu.open || reducedMotion.matches || motionPaused) finish();
    else menuCloseTimer = setTimeout(finish, 180);
  }

  function openMenu() {
    if (!mobileMenu || !menuButton) return;
    closeDrawer();
    clearTimeout(menuCloseTimer);
    mobileMenu.hidden = false;
    if (!mobileMenu.open) mobileMenu.showModal();
    menuButton.setAttribute("aria-expanded", "true");
    menuButton.setAttribute("aria-label", "Close navigation");
    requestAnimationFrame(() => {
      if (menuButton.getAttribute("aria-expanded") === "true") mobileMenu.classList.add("is-open");
    });
  }

  menuButton?.addEventListener("click", () => {
    if (menuButton.getAttribute("aria-expanded") === "true") closeMenu(true);
    else openMenu();
  });
  if (menuButton) menuButton.disabled = false;
  document.querySelector("[data-ash-menu-close]")?.addEventListener("click", () => closeMenu(true));
  mobileMenu?.addEventListener("cancel", (event) => {
    event.preventDefault();
    closeMenu(true);
  });
  mobileMenu?.addEventListener("click", (event) => {
    if (event.target !== mobileMenu) return;
    const rect = mobileMenu.getBoundingClientRect();
    if (event.clientX < rect.left || event.clientX > rect.right
      || event.clientY < rect.top || event.clientY > rect.bottom) closeMenu(true);
  });
  mobileMenu?.querySelectorAll("a").forEach((link) => link.addEventListener("click", () => closeMenu()));
  function openDrawer() {
    // The documentation drawer takes focus immediately.
    closeMenu();
    clearTimeout(menuCloseTimer);
    if (mobileMenu) {
      mobileMenu.close();
      mobileMenu.hidden = true;
    }
    if (drawer && !drawer.checked) drawer.click();
    updateDrawerState();
  }
  document.querySelector("[data-ash-drawer]")?.addEventListener("click", openDrawer);
  document.querySelector("[data-ash-handbook]")?.addEventListener("click", openDrawer);
  window.matchMedia("(min-width: 961px)").addEventListener("change", (event) => {
    if (event.matches) closeMenu();
  });

  const drawer = document.getElementById("__drawer");
  const handbook = document.querySelector(".md-sidebar--primary");
  const drawerMedia = window.matchMedia("(max-width: 1219px)");
  const drawerTrigger = document.querySelector("[data-ash-handbook]");
  const drawerBackground = [...document.querySelectorAll(
    ".ash-header, .ash-skip, .md-content, .md-sidebar--secondary, .ash-pagination, .ash-footer, .md-top"
  )];
  const drawerClose = document.createElement("button");
  drawerClose.type = "button";
  drawerClose.className = "ash-handbook-close";
  drawerClose.textContent = "Close contents";
  drawerClose.hidden = true;
  drawerClose.addEventListener("click", () => closeDrawer(true));
  if (handbook) {
    handbook.id = "ash-handbook";
    handbook.prepend(drawerClose);
  }
  function updateDrawerState() {
    const open = Boolean(drawer?.checked && drawerMedia.matches && handbook);
    root.classList.toggle("ash-drawer-open", open);
    drawerTrigger?.setAttribute("aria-expanded", String(open));
    drawerClose.hidden = !open;
    drawerBackground.forEach((element) => {
      element.inert = open || (Boolean(searchToggle?.checked) && !element.classList.contains("ash-header"));
    });
    if (handbook) {
      if (open) {
        handbook.setAttribute("role", "dialog");
        handbook.setAttribute("aria-modal", "true");
        handbook.setAttribute("aria-label", "Documentation contents");
        drawerClose.focus();
      } else {
        handbook.removeAttribute("role");
        handbook.removeAttribute("aria-modal");
        handbook.removeAttribute("aria-label");
      }
    }
  }
  function closeDrawer(restoreFocus = false) {
    if (!drawer?.checked) return;
    drawer.checked = false;
    drawer.dispatchEvent(new Event("change", { bubbles: true }));
    updateDrawerState();
    if (restoreFocus) {
      const trigger = drawerTrigger?.getClientRects().length ? drawerTrigger : menuButton;
      trigger?.focus();
    }
  }
  drawer?.addEventListener("change", updateDrawerState);
  handbook?.querySelectorAll("a[href]").forEach((link) => {
    link.addEventListener("click", () => closeDrawer());
  });
  drawerMedia.addEventListener("change", updateDrawerState);
  document.querySelector(".md-overlay[for='__drawer']")?.addEventListener("click", (event) => {
    event.preventDefault();
    closeDrawer(true);
  });
  updateDrawerState();
  document.querySelectorAll("[data-ash-handbook]").forEach((button) => {
    button.disabled = false;
  });

  function openSearch() {
    if (!searchToggle) return;
    closeDrawer();
    closeMenu();
    // A native navigation dialog must yield before another modal takes focus.
    clearTimeout(menuCloseTimer);
    if (mobileMenu) {
      mobileMenu.close();
      mobileMenu.hidden = true;
    }
    if (!searchToggle.checked) searchToggle.click();
    requestAnimationFrame(() => document.querySelector("[data-md-component='search-query']")?.focus());
  }
  const searchButton = document.querySelector("[data-ash-search]");
  searchButton?.addEventListener("click", openSearch);
  const searchDialog = document.querySelector(".md-search");
  if (searchDialog) searchDialog.id = "ash-search-dialog";
  searchDialog?.setAttribute("aria-label", "Search documentation");
  searchDialog?.setAttribute("aria-modal", "true");
  const searchBackground = [...document.querySelectorAll(
    ".md-container, .ash-skip, .ash-brand, .ash-header__links, .ash-header__actions, #ash-mobile-menu"
  )];
  function updateSearchState() {
    const open = Boolean(searchToggle?.checked);
    document.querySelector("[data-ash-search]")?.setAttribute("aria-expanded", String(open));
    searchBackground.forEach((element) => { element.inert = open; });
    if (!open && searchDialog?.contains(document.activeElement)) {
      document.querySelector("[data-ash-search]")?.focus();
    }
    searchDialog?.setAttribute("aria-hidden", String(!open));
  }
  searchToggle?.addEventListener("change", updateSearchState);
  updateSearchState();
  if (searchToggle && searchButton) searchButton.disabled = false;
  const searchQuery = document.querySelector("[data-md-component='search-query']");
  // Material listens for keyup. Also refresh when a query is pasted or autofilled.
  searchQuery?.addEventListener("input", () => {
    searchQuery.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));
  });
  const shortcut = document.querySelector("[data-ash-shortcut]");
  if (shortcut && !/Mac|iPhone|iPad/.test(navigator.platform)) shortcut.textContent = "Ctrl K";
  document.addEventListener("keydown", (event) => {
    if (event.key === "Tab" && mobileMenu?.open) {
      const controls = [...mobileMenu.querySelectorAll("a[href], button:not([disabled]), [tabindex]")]
        .filter((element) => element.tabIndex >= 0 && element.getClientRects().length);
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (first && (
        !mobileMenu.contains(document.activeElement)
        || (event.shiftKey && document.activeElement === first)
        || (!event.shiftKey && document.activeElement === last)
      )) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      }
    }
    if (event.key === "Tab" && drawer?.checked && drawerMedia.matches && handbook) {
      const controls = [...handbook.querySelectorAll("a[href], button, [tabindex]")]
        .filter((element) => element.tabIndex >= 0 && element.getClientRects().length);
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (first && (
        !handbook.contains(document.activeElement)
        || (event.shiftKey && document.activeElement === first)
        || (!event.shiftKey && document.activeElement === last)
      )) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      }
    }
    if (event.key === "Tab" && searchToggle?.checked && searchDialog) {
      // Material closes search on Tab. Preserve normal Tab navigation inside this dialog.
      event.stopPropagation();
      const controls = [...searchDialog.querySelectorAll(
        "a[href], button:not([disabled]), input:not([disabled]), [tabindex]"
      )].filter((element) => element.tabIndex >= 0 && element.getClientRects().length);
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (first && (
        !searchDialog.contains(document.activeElement)
        || (event.shiftKey && document.activeElement === first)
        || (!event.shiftKey && document.activeElement === last)
      )) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      }
    }
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openSearch();
    }
    if (event.key === "Escape") {
      if (searchToggle?.checked) {
        searchToggle.click();
        document.querySelector("[data-ash-search]")?.focus();
      } else if (!mobileMenu?.hidden) {
        closeMenu(true);
      } else if (drawer?.checked && drawerMedia.matches) {
        event.preventDefault();
        closeDrawer(true);
      }
    }
  }, true);

  async function copy(text, button) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const input = document.createElement("textarea");
        input.value = text;
        input.setAttribute("readonly", "");
        input.style.cssText = "position:fixed;left:-9999px;top:0";
        document.body.append(input);
        input.select();
        const copied = document.execCommand("copy");
        input.remove();
        button.focus();
        if (!copied) throw new Error("Clipboard unavailable");
      }
      button.classList.add("is-copied");
      notify("Command copied. Your terminal is next.");
      setTimeout(() => button.classList.remove("is-copied"), 2000);
    } catch {
      notify("Couldn’t copy automatically. Select the command to copy it.");
    }
  }
  document.querySelectorAll("[data-ash-copy]").forEach((button) => {
    button.addEventListener("click", () => copy(button.dataset.ashCopy, button));
  });
  document.querySelector("[data-ash-copy-scan]")?.addEventListener("click", (event) => {
    copy(document.querySelector("[data-ash-scan-command]").textContent, event.currentTarget);
  });

  // ARIA tabs support both pointer and the standard arrow/Home/End keyboard controls.
  const tabs = [...document.querySelectorAll("[data-ash-tab]")];
  function selectTab(tab, focus = false) {
    tabs.forEach((candidate) => {
      const selected = candidate === tab;
      candidate.setAttribute("aria-selected", String(selected));
      candidate.tabIndex = selected ? 0 : -1;
      document.getElementById(candidate.getAttribute("aria-controls")).hidden = !selected;
    });
    if (focus) tab.focus();
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => selectTab(tab));
    tab.addEventListener("keydown", (event) => {
      let next;
      if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
      if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
      if (event.key === "Home") next = 0;
      if (event.key === "End") next = tabs.length - 1;
      if (next !== undefined) {
        event.preventDefault();
        selectTab(tabs[next], true);
      }
    });
  });

  const modeNotes = {
    container: "Run enabled scanners in an isolated container. Requires an OCI-compatible runtime.",
    local: "Run on your machine. Some scanners need additional tools installed locally.",
    precommit: "A fast subset of scanners, designed for checks before you commit."
  };
  document.querySelectorAll("[data-ash-mode]").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll("[data-ash-mode]").forEach((candidate) => {
        candidate.setAttribute("aria-pressed", String(candidate === button));
      });
      document.querySelector("[data-ash-scan-command]").textContent = `ash --mode ${button.dataset.ashMode}`;
      document.querySelector("[data-ash-mode-note]").textContent = modeNotes[button.dataset.ashMode];
    });
  });

  const scanners = [...document.querySelectorAll("[data-ash-category]")];
  document.querySelectorAll("[data-ash-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      const category = button.dataset.ashFilter;
      let count = 0;
      document.querySelectorAll("[data-ash-filter]").forEach((candidate) => {
        candidate.setAttribute("aria-pressed", String(candidate === button));
      });
      scanners.forEach((scanner) => {
        scanner.hidden = category !== "all" && scanner.dataset.ashCategory !== category;
        if (!scanner.hidden) count++;
      });
      document.querySelector("[data-ash-filter-status]").textContent =
        category === "all" ? `Showing all ${count} scanners.` : `Showing ${count} ${category} ${count === 1 ? "scanner" : "scanners"}.`;
    });
  });

  function updateMotion() {
    root.classList.toggle("ash-motion-paused", motionPaused);
    document.querySelectorAll("[data-ash-motion]").forEach((button) => {
      button.setAttribute("aria-pressed", String(motionPaused));
      button.disabled = reducedMotion.matches;
      button.querySelector("span:last-child").textContent = reducedMotion.matches
        ? "Reduced motion"
        : motionPaused ? "Motion paused" : "Pause motion";
    });
    if (motionPaused) finishDemo();
    window.dispatchEvent(new CustomEvent("ash:motionchange", {
      detail: { paused: motionPaused, reduced: reducedMotion.matches }
    }));
  }
  document.querySelectorAll("[data-ash-motion]").forEach((button) => {
    button.addEventListener("click", () => {
      motionPaused = !motionPaused;
      store("ash-motion", motionPaused ? "paused" : "enabled");
      updateMotion();
    });
  });
  reducedMotion.addEventListener("change", (event) => {
    motionPaused = event.matches || stored("ash-motion") === "paused";
    updateMotion();
  });

  const demo = document.querySelector("[data-ash-demo]");
  const replay = document.querySelector("[data-ash-run]");
  function finishDemo() {
    demoRun++;
    demo?.closest(".ash-demo").classList.remove("is-running");
    demo?.querySelectorAll("div").forEach((line) => line.classList.add("is-done"));
    if (replay) replay.disabled = false;
  }
  async function runDemo() {
    if (!demo || motionPaused || reducedMotion.matches) {
      finishDemo();
      return;
    }
    const run = ++demoRun;
    demo.closest(".ash-demo").classList.add("is-running");
    const lines = [...demo.children];
    lines.forEach((line) => line.classList.remove("is-done"));
    replay.disabled = true;
    for (const line of lines) {
      await new Promise((resolve) => setTimeout(resolve, 650));
      if (run !== demoRun) return;
      line.classList.add("is-done");
    }
    replay.disabled = false;
    demo.closest(".ash-demo").classList.remove("is-running");
  }
  replay?.addEventListener("click", runDemo);
  updateMotion();

  // Give framework-generated navigation landmarks distinct, descriptive names.
  // Indexed sections use a chevron-only label, so their visible title is more useful.
  function labelNavigation() {
    document.querySelector(".md-path")?.setAttribute("aria-label", "Breadcrumb");
    document.querySelectorAll(".md-sidebar--primary nav").forEach((navigation) => {
      if (!navigation.matches(".md-nav--primary") && !navigation.hasAttribute("aria-labelledby")) return;
      const title = navigation.querySelector(":scope > .md-nav__title")?.textContent.trim();
      navigation.removeAttribute("aria-labelledby");
      navigation.setAttribute("aria-label", title ? `Documentation: ${title}` : "Documentation chapters");
    });
    document.querySelectorAll(".md-code__nav").forEach((navigation, index) => {
      navigation.setAttribute("aria-label", `Code example ${index + 1} controls`);
    });
    document.querySelectorAll("pre > code").forEach((code) => {
      if (code.scrollWidth > code.clientWidth || code.scrollHeight > code.clientHeight) {
        code.setAttribute("tabindex", "0");
      }
    });
  }
  labelNavigation();
  requestAnimationFrame(labelNavigation);
  // Material adds code controls and search snippets after the initial render.
  let labelsPending = false;
  const scheduleLabels = () => {
    if (labelsPending) return;
    labelsPending = true;
    requestAnimationFrame(() => {
      labelsPending = false;
      labelNavigation();
    });
  };
  new MutationObserver(scheduleLabels).observe(document.body, { childList: true, subtree: true });
  window.addEventListener("resize", scheduleLabels, { passive: true });

  if ("IntersectionObserver" in window && !reducedMotion.matches) {
    root.classList.add("ash-motion-ready");
    const reveals = new IntersectionObserver((entries, observer) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.08, rootMargin: "0px 0px -25px 0px" });
    document.querySelectorAll("[data-ash-reveal]").forEach((element) => reveals.observe(element));

    if (demo) {
      const demoObserver = new IntersectionObserver((entries, observer) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          runDemo();
          observer.disconnect();
        }
      }, { threshold: 0.5 });
      demoObserver.observe(demo);
    }
  }
})();
