// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;

async function expectAccessible(page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "best-practice"]).analyze();
  expect(results.violations).toEqual([]);
}

for (const width of [320, 390, 820, 1440]) {
  for (const theme of ["dark", "light"]) {
    test(`homepage at ${width}px in ${theme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 1000 });
      await page.emulateMedia({ colorScheme: theme });
      const errors = [];
      page.on("pageerror", error => errors.push(error.message));
      await page.goto("./");
      await expect(page.getByRole("heading", { level: 1 })).toContainText("Automated Security Helper");
      await expect(page.locator("body")).toHaveAttribute("data-md-color-scheme", theme === "dark" ? "slate" : "default");
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(width);
      await expectAccessible(page);
      expect(errors).toEqual([]);
    });
  }
}

for (const width of [390, 1440]) {
  test(`handbook navigation at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.goto("docs/quick-start-guide/");
    await expect(page.getByRole("heading", { level: 1 })).toContainText("Quick Start");
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(width);
    await expectAccessible(page);
    if (width < 760) {
      await page.getByRole("button", { name: "Open navigation" }).click();
      await page.getByRole("button", { name: "Browse all documentation" }).click();
      await expect(page.locator("#__drawer")).toBeChecked();
    }
  });
}

test("indexed search accepts pasted queries and returns focus on Escape", async ({ page }) => {
  await page.goto("./");
  const trigger = page.getByRole("button", { name: "Search documentation" });
  await trigger.click();
  const query = page.locator("[data-md-component='search-query']");
  await expect(query).toBeFocused();
  await query.fill("semgrep");
  await expect(page.locator(".md-search-result__link").first()).toBeVisible();
  await expect(page.locator(".md-search-result__meta")).toContainText("matching");
  await expectAccessible(page);
  await query.press("Escape");
  await expect(page.locator("#__search")).not.toBeChecked();
  await expect(trigger).toBeFocused();
  await page.keyboard.press("Control+k");
  await expect(query).toBeFocused();
});

test("search keeps keyboard focus in the dialog until closed", async ({ page }) => {
  await page.goto("./");
  await page.getByRole("button", { name: "Search documentation" }).click();
  const query = page.locator("[data-md-component='search-query']");
  await expect(query).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  expect(await page.evaluate(() => !!document.activeElement.closest(".md-search"))).toBe(true);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("button", { name: "Search documentation" })).toBeFocused();
});

test("installation tabs support the keyboard, scan modes update copied commands", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("./");
  const release = (await page.locator(".ash-hero__version").innerText()).trim();
  expect(release).toMatch(/^ASH v\d+\.\d+\.\d+$/);
  const version = release.slice(5);
  await page.getByRole("button", { name: "Copy pipx installation command" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
    `pipx install git+https://github.com/awslabs/automated-security-helper.git@v${version}`
  );
  const tabs = page.getByRole("tab");
  await tabs.first().focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("tab", { name: "uvx", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.locator("#panel-uvx")).toBeVisible();
  await page.keyboard.press("End");
  await expect(page.getByRole("tab", { name: "pip", exact: true })).toBeFocused();
  await page.getByRole("button", { name: "Local", exact: true }).click();
  await expect(page.locator("[data-ash-scan-command]")).toHaveText("ash --mode local");
  await page.locator("[data-ash-copy-scan]").click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("ash --mode local");
  await expect(page.locator("[data-ash-toast]")).toContainText("Command copied");
});

test("scanner filters announce results and FAQ answers expand", async ({ page }) => {
  await page.goto("./");
  await page.getByRole("button", { name: "Secrets", exact: true }).click();
  await expect(page.locator("[data-ash-category]:visible")).toHaveCount(1);
  await expect(page.locator("[data-ash-filter-status]")).toContainText("1 secrets scanner");
  await page.getByRole("button", { name: "All tools" }).click();
  await expect(page.locator("[data-ash-category]:visible")).toHaveCount(10);
  await page.getByText("Do I need an AWS account?", { exact: true }).click();
  await expect(page.getByText("Core ASH scanning runs locally", { exact: false })).toBeVisible();
});

test("motion can be paused and the preference survives reload", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.goto("./");
  await page.locator("[data-ash-motion]").click();
  await expect(page.locator("html")).toHaveClass(/ash-motion-paused/);
  await page.reload();
  await expect(page.locator("[data-ash-motion]")).toHaveAttribute("aria-pressed", "true");
});

test("a chosen theme survives reload and documentation navigation", async ({ page }) => {
  await page.goto("./");
  const toggle = page.getByRole("button", { name: "Switch to light mode" });
  await toggle.focus();
  await page.keyboard.press("Enter");
  await expect(page.locator("body")).toHaveAttribute("data-md-color-scheme", "default");
  await page.reload();
  await expect(page.locator("body")).toHaveAttribute("data-md-color-scheme", "default");
  await page.locator(".ash-header__links").getByRole("link", { name: "Documentation" }).click();
  await expect(page.locator("body")).toHaveAttribute("data-md-color-scheme", "default");
  await page.getByRole("button", { name: "Switch to dark mode" }).click();
  await expect(page.locator("body")).toHaveAttribute("data-md-color-scheme", "slate");
});

test("navigation controls wait for their handlers on a new documentation page", async ({ page }) => {
  await page.goto("./");
  let release;
  const loaded = new Promise(resolve => { release = resolve; });
  await page.route("**/assets/javascripts/ash.js", async route => {
    await loaded;
    await route.continue();
  });
  const navigation = page.locator(".ash-header__links").getByRole("link", { name: "Documentation" }).click();
  try {
    await expect(page.getByRole("heading", { level: 1 })).toContainText("Quick Start");
    await expect(page.getByRole("button", { name: "Search documentation" })).toBeDisabled();
  } finally {
    release();
  }
  await navigation;
  await page.getByRole("button", { name: "Search documentation" }).click();
  await expect(page.locator("[data-md-component='search-query']")).toBeFocused();
});

test("navigation and indexed search work under a GitHub Pages subpath", async ({ page, baseURL }) => {
  const prefix = new URL("automated-security-helper/", baseURL).href;
  await page.route(`${prefix}**`, async route => {
    const target = new URL(route.request().url().slice(prefix.length), baseURL);
    await route.fulfill({ response: await route.fetch({ url: target.href }) });
  });
  await page.goto(prefix);
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Automated Security Helper");
  await page.locator(".ash-header__links").getByRole("link", { name: "Documentation" }).click();
  await expect(page).toHaveURL(`${prefix}docs/quick-start-guide/`);
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Quick Start");
  await page.getByRole("button", { name: "Search documentation" }).click();
  await page.locator("[data-md-component='search-query']").fill("semgrep");
  const result = page.locator(".md-search-result__link").first();
  await expect(result).toBeVisible();
  await result.click();
  expect(page.url().startsWith(prefix)).toBe(true);
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await page.getByRole("navigation", { name: "Main navigation", exact: true })
    .getByRole("link", { name: "ASH home", exact: true }).click();
  await expect(page).toHaveURL(prefix);
  await page.goto(`${prefix}404.html`);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Page not found");
  await expectAccessible(page);
  await page.locator("#main-content").getByRole("link", { name: "Documentation", exact: true }).click();
  await expect(page).toHaveURL(`${prefix}docs/quick-start-guide/`);
});

test("reduced motion renders the complete illustration and demo", async ({ page }) => {
  await page.goto("./");
  await expect(page.locator("[data-ash-motion]")).toBeDisabled();
  for (const card of await page.locator(".ash-scan__file, .ash-scan__finding").all()) {
    expect(await card.evaluate(element => getComputedStyle(element).opacity)).toBe("1");
  }
  await expect(page.locator("[data-ash-demo] > div.is-done")).toHaveCount(4);
  await expect(page.locator("[data-ash-scan]")).toHaveAttribute("data-step", "3");
  await expect(page.locator("[data-scan-play]")).toBeDisabled();
  await expect(page.locator("[data-scan-state]")).toHaveText("Reports ready");
});

test("mobile navigation and installation work without JavaScript", async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  await page.goto("./");
  const navigation = page.getByRole("navigation", { name: "Site navigation" });
  await expect(navigation).toBeVisible();
  await expect(page.locator("#panel-pipx")).toBeVisible();
  await expect(page.locator("#panel-uvx")).toBeVisible();
  await expect(page.locator("#panel-pip")).toBeVisible();
  await navigation.getByRole("link", { name: "Documentation" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Quick Start");
  await context.close();
});

test("mobile navigation contains keyboard focus and returns it on dismissal", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("./");
  const trigger = page.getByRole("button", { name: "Open navigation", exact: true });
  await trigger.focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog", { name: "Site navigation" });
  await expect(dialog).toBeVisible();
  await expectAccessible(page);
  for (let index = 0; index < 9; index++) {
    await page.keyboard.press("Tab");
    expect(await dialog.evaluate(element => element.contains(document.activeElement))).toBe(true);
  }
  for (let index = 0; index < 9; index++) {
    await page.keyboard.press("Shift+Tab");
    expect(await dialog.evaluate(element => element.contains(document.activeElement))).toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(trigger).toBeFocused();
  await trigger.click();
  await dialog.getByRole("button", { name: "Close navigation", exact: true }).click();
  await expect(trigger).toBeFocused();
});

test("tablet documentation contents can be opened, explored, and closed with the keyboard", async ({ page }) => {
  await page.setViewportSize({ width: 1060, height: 900 });
  await page.goto("docs/quick-start-guide/");
  const trigger = page.getByRole("button", { name: "Browse all documentation" });
  await expect(trigger).toBeVisible();
  await trigger.focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog", { name: "Documentation contents" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Close contents" })).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  expect(await dialog.evaluate(element => element.contains(document.activeElement))).toBe(true);
  await expectAccessible(page);
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(trigger).toBeFocused();
});

test("task navigation reaches integrations and the full MCP reference", async ({ page }) => {
  await page.goto("./");
  await page.locator(".ash-header__links").getByRole("link", { name: "Integrations" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Integrations");
  await expect(page.locator(".ash-header__links").getByRole("link", { name: "Integrations" })).toHaveAttribute("aria-current", "true");
  const sidebar = page.locator(".md-sidebar--primary");
  await sidebar.getByText("AI assistants & MCP", { exact: true }).first().click();
  await sidebar.getByRole("link", { name: "MCP tool reference", exact: true }).click();
  await expect(page).toHaveURL(/docs\/MCP-TOOLS-REFERENCE\/$/);
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Tools Reference");
  await expect(page.locator(".ash-header__links").getByRole("link", { name: "Integrations" })).toHaveAttribute("aria-current", "true");
});

test("menu exits can be followed immediately by another open without stale state", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("./");
  const dialog = page.getByRole("dialog", { name: "Site navigation" });
  for (let index = 0; index < 3; index++) {
    await page.getByRole("button", { name: "Open navigation", exact: true }).click();
    await expect(dialog).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible();
  }
  await page.getByRole("button", { name: "Open navigation", exact: true }).click();
  await page.keyboard.press("Control+k");
  await expect(dialog).not.toBeVisible();
  await expect(page.locator("[data-md-component='search-query']")).toBeFocused();
});
