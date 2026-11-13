// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;
const { pathToFileURL } = require("node:url");
const path = require("node:path");
const previews = process.env.DOCS_UI_PREVIEWS || path.resolve(__dirname, "../.previews");
const reportUrl = (name) => pathToFileURL(path.join(previews, `${name}-report.html`)).href;

for (const name of ["review", "empty", "workspace"]) {
  for (const width of [390, 1440]) {
    test(`${name} report works offline at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 1000 });
      const errors = [];
      const requests = [];
      page.on("pageerror", error => errors.push(error.message));
      page.on("request", request => {
        if (!request.url().startsWith("file:")) requests.push(request.url());
      });
      await page.goto(reportUrl(name));
      const fonts = await page.evaluate(async () => {
        const faces = await Promise.all([
          document.fonts.load('400 16px "Open Sans"'),
          document.fonts.load('700 24px "Open Sans"'),
        ]);
        return faces.map(group => group.length > 0 && group.every(face => face.status === "loaded"));
      });
      expect(fonts).toEqual([true, true]);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(width);
      const results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa", "best-practice"]).analyze();
      expect(results.violations).toEqual([]);
      expect(errors).toEqual([]);
      expect(requests).toEqual([]);
      if (name === "empty") {
        await expect(page.getByRole("heading", { name: "No scanners completed" })).toBeVisible();
        await expect(page.locator(".finding-controls")).not.toBeVisible();
        await expect(page.locator("#empty-findings")).not.toBeVisible();
      }
      if (name === "workspace") {
        await expect(page.getByRole("link", { name: "Projects", exact: true })).toBeVisible();
        await expect(page.locator("#projects")).toContainText("docs");
      }
    });
  }
}

test("report filters combine, clear, and recover from no matches", async ({ page }) => {
  await page.goto(reportUrl("review"));
  const count = page.locator("#finding-count");
  await page.locator("#finding-severity").selectOption("high");
  await page.locator("#finding-scanner").selectOption("bandit");
  await expect(page.locator(".finding-card:visible")).toHaveCount(1);
  await page.locator("#finding-search").fill("does not exist");
  await expect(page.getByRole("heading", { name: "No findings match this view" })).toBeVisible();
  await page.getByRole("button", { name: "Show all findings" }).click();
  await expect(page.locator("#finding-search")).toBeFocused();
  await expect(page.locator("#finding-search")).toHaveValue("");
  await expect(page.locator("#finding-severity")).toHaveValue("all");
  await expect(page.locator("#finding-scope")).toHaveValue("all");
  await expect(count).toHaveText("Showing 11 of 11 findings");
  await page.locator("#finding-scope").selectOption("suppressed");
  await expect(page.locator(".finding-card:visible")).toHaveCount(1);
  await page.locator(".finding-card:visible summary").click();
  await expect(page.locator(".suppression-reason:visible")).toContainText("Fixture placeholder credential");
  await page.getByRole("button", { name: "Reset", exact: true }).click();
  await expect(count).toHaveText("Showing 6 of 11 findings");
});

test("the report skip link moves keyboard focus past the toolbar", async ({ page }) => {
  await page.goto(reportUrl("review"));
  await page.getByRole("link", { name: "Skip to report" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("main")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.locator(".section-nav").getByRole("link", { name: /^Findings/ })).toBeFocused();
});

test("long finding evidence can be scrolled with the keyboard", async ({ page }) => {
  await page.goto(reportUrl("review"));
  await page.locator("#finding-severity").selectOption("high");
  await page.locator("#finding-scanner").selectOption("bandit");
  await page.locator(".finding-card:visible summary").click();
  const snippet = page.getByRole("region", { name: /^Code snippet for finding/ }).first();
  // Extend the fixture's evidence to exercise the renderer's bounded scroll area.
  await snippet.locator("code").evaluate(element => {
    element.textContent += "\n" + Array.from({ length: 100 }, (_, index) => `example line ${index}`).join("\n");
  });
  await snippet.focus();
  await expect(snippet).toBeFocused();
  await page.keyboard.press("PageDown");
  await expect.poll(() => snippet.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
});

test("report supports both themes and preserves choices", async ({ page }) => {
  await page.goto(reportUrl("review"));
  await page.getByRole("button", { name: "Switch to light theme" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "best-practice"]).analyze();
  expect(results.violations).toEqual([]);
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
});

test("clipboard failure selects a location and announces the fallback", async ({ page }) => {
  await page.goto(reportUrl("review"));
  await page.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
  });
  await page.locator(".copy-location:visible").first().click();
  await expect(page.locator("#copy-status")).toContainText("selected for copying");
  expect(await page.evaluate(() => getSelection().toString())).not.toBe("");
});

test("printing includes filtered findings and expands details", async ({ page }) => {
  await page.goto(reportUrl("review"));
  await page.locator("#finding-search").fill("does not exist");
  await page.emulateMedia({ media: "print" });
  await page.evaluate(() => window.dispatchEvent(new Event("beforeprint")));
  expect(await page.locator(".finding-card:visible").count()).toBe(11);
  expect(await page.locator(".finding-card details[open]").count()).toBe(11);
  await page.evaluate(() => window.dispatchEvent(new Event("afterprint")));
  expect(await page.locator(".finding-card details[open]").count()).toBe(0);
});

test("report works without JavaScript", async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  await page.goto(reportUrl("review"));
  await expect(page.locator(".finding-card:visible")).toHaveCount(11);
  await expect(page.locator(".finding-controls")).not.toBeVisible();
  await page.locator(".finding-card summary").first().click();
  await expect(page.locator(".finding-body").first()).toBeVisible();
  await context.close();
});
