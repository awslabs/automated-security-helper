/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 */
(() => {
  "use strict";
  document.documentElement.classList.add("has-js");
  const themeButton = document.getElementById("theme-toggle");
  const setTheme = (theme) => {
    document.documentElement.dataset.theme = theme;
    themeButton.textContent = theme === "dark" ? "Light theme" : "Dark theme";
    themeButton.setAttribute("aria-label", `Switch to ${theme === "dark" ? "light" : "dark"} theme`);
  };
  const preferredTheme = () =>
    window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  try {
    const stored = localStorage.getItem("ash-report-theme");
    setTheme(stored === "light" || stored === "dark" ? stored : preferredTheme());
  } catch (_) {
    setTheme(preferredTheme());
  }
  themeButton.addEventListener("click", () => {
    const theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    setTheme(theme);
    try { localStorage.setItem("ash-report-theme", theme); } catch (_) {}
  });
  const search = document.getElementById("finding-search");
  const scope = document.getElementById("finding-scope");
  const severity = document.getElementById("finding-severity");
  const scanner = document.getElementById("finding-scanner");
  const cards = [...document.querySelectorAll(".finding-card")];
  const count = document.getElementById("finding-count");
  const empty = document.getElementById("empty-findings");
  document.querySelector(".finding-controls").hidden = cards.length === 0;
  count.hidden = cards.length === 0;
  // Search the finding's own text: the title, scanner, rule, location and body,
  // not the buttons and labels around them ("Copy", "Finding details").
  const searchText = (card) => {
    const clone = card.cloneNode(true);
    clone.querySelectorAll("button, summary, strong, .pill, .finding-status").forEach((node) => node.remove());
    return [...clone.querySelectorAll("h3, .finding-scanner, .finding-meta code, .finding-body > *")]
      .map((node) => node.textContent).join("\n").toLocaleLowerCase();
  };
  const searchable = new Map(cards.map((card) => [card, searchText(card)]));
  const filter = () => {
    const query = search.value.trim().toLocaleLowerCase();
    let shown = 0;
    for (const card of cards) {
      const status = card.dataset.status;
      // A finding the project's outcome left out (a workspace policy scanner
      // whose policy does not gate) is shown by the default view, whatever its
      // severity: it is reported, not set aside as below the threshold.
      const matchesScope = scope.value === "all" || status === scope.value ||
        (scope.value === "actionable" && status === "policy-not-gating") ||
        (scope.value === "active" && status !== "suppressed");
      const matches = matchesScope &&
        (severity.value === "all" || card.dataset.severity === severity.value) &&
        (scanner.value === "" || card.dataset.scanner === scanner.value) &&
        (!query || searchable.get(card).includes(query));
      card.hidden = !matches;
      if (matches) shown += 1;
    }
    count.textContent = `Showing ${shown} of ${cards.length} findings`;
    empty.hidden = shown > 0 || cards.length === 0;
  };
  const reset = (showAll = false) => {
    search.value = "";
    scope.value = showAll ? "all" : "actionable";
    severity.value = "all";
    scanner.value = "";
    filter();
    search.focus();
  };
  search.addEventListener("input", filter);
  search.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && search.value) {
      event.preventDefault(); search.value = ""; filter();
    }
  });
  [scope, severity, scanner].forEach((control) => control.addEventListener("change", filter));
  document.getElementById("reset-filters").addEventListener("click", () => reset());
  document.getElementById("empty-reset").addEventListener("click", () => reset(true));
  const copyStatus = document.getElementById("copy-status");
  document.querySelectorAll("[data-copy-location]").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(button.dataset.copyLocation);
        button.textContent = "Copied";
        copyStatus.textContent = "Location copied.";
      } catch (_) {
        button.textContent = "Select path";
        const range = document.createRange();
        range.selectNodeContents(button.previousElementSibling);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        copyStatus.textContent = "Clipboard unavailable. The location is selected for copying.";
      }
      setTimeout(() => { button.textContent = "Copy"; }, 2000);
    });
  });
  let printStates = [];
  window.addEventListener("beforeprint", () => {
    printStates = [...document.querySelectorAll("details")].map((detail) => [detail, detail.open]);
    printStates.forEach(([detail]) => { detail.open = true; });
  });
  window.addEventListener("afterprint", () => {
    printStates.forEach(([detail, open]) => { detail.open = open; });
  });
  document.getElementById("print-report").addEventListener("click", () => window.print());
  filter();
})();
