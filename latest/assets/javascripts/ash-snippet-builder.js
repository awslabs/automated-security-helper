/* Home page snippet builder: shows the one snippet family that answers the picked
   (workflow, backend) pair. The snippets are rendered into the page by
   docs/overrides/partials/ash-snippet-builder.html with every family visible, so the
   page reads fully when this file is blocked or fails to load; the first render below
   hides the families that do not answer the default pick. The copy buttons are wired
   by ash.js through data-ash-copy. */
(function () {
  const host = document.querySelector("[data-ash-builder]");
  if (!host) return;

  const pickers = host.querySelector("[data-ash-builder-pickers]");
  const status = host.querySelector("[data-ash-builder-status]");
  const picks = [...host.querySelectorAll("[data-ash-pick]")];
  const backends = [...host.querySelectorAll("[data-ash-backend]")];
  const panels = [...host.querySelectorAll("[data-ash-panel]")];
  const state = {
    pick: picks.find((button) => button.getAttribute("aria-pressed") === "true")?.dataset.ashPick,
    backend: backends.find((button) => button.getAttribute("aria-pressed") === "true")?.dataset.ashBackend
  };

  function answers(panel) {
    return panel.dataset.ashPickFor === state.pick &&
      panel.dataset.ashBackendsFor.split(" ").includes(state.backend);
  }

  function render(announce) {
    let shown;
    panels.forEach((panel) => {
      const match = answers(panel);
      panel.hidden = !match;
      if (match) shown = panel;
    });
    picks.forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.ashPick === state.pick)));
    backends.forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.ashBackend === state.backend)));
    if (announce && shown && status) {
      status.textContent = [shown.dataset.ashTitle, shown.dataset.ashCaveat].filter(Boolean).join(". ");
    }
  }

  function choose(group, value) {
    state[group] = value;
    render(true);
  }

  picks.forEach((button) => button.addEventListener("click", () => choose("pick", button.dataset.ashPick)));
  backends.forEach((button) => button.addEventListener("click", () => choose("backend", button.dataset.ashBackend)));

  // Without this file the pickers stay hidden and every family stays visible.
  if (pickers) pickers.hidden = false;
  render(false);
})();
