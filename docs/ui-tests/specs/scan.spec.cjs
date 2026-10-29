// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const { test, expect } = require("@playwright/test");

const scale = (page) => page.locator("[data-scan-progress]").evaluate(
  element => new DOMMatrixReadOnly(getComputedStyle(element).transform).a
);

test("file selection connects the matching scanners and finding without motion", async ({ page }) => {
  await page.goto("./");
  const example = page.locator("[data-ash-scan]");
  await expect(example).toHaveClass(/is-ready/);
  await example.locator('[data-scan-category="secrets"]').click();
  await expect(example).toHaveAttribute("data-category", "secrets");
  await expect(example.locator(".ash-scan__scanner.is-selected")).toHaveCount(1);
  await expect(example.locator(".ash-scan__scanner.is-selected")).toContainText("detect-secrets");
  await expect(example.locator(".ash-scan__finding.is-selected")).toContainText("Embedded credential");
  await expect(example.locator(".ash-scan__route.is-active")).toHaveCount(2);
  await expect(example.locator("[data-scan-finding]")).toHaveCount(4);
  await expect(example.locator("[data-scan-play]")).toBeDisabled();
  await expect(example.locator("[data-scan-announcement]")).toContainText(".env");
  await example.locator('[data-scan-step="1"]').click();
  await expect(example).toHaveAttribute("data-step", "1");
  await expect(example.locator("[data-scan-state]")).toHaveText("Running scanners");
  const check = example.locator(".ash-scan__scanner.is-selected .ash-scan__scanner-check");
  const reportLine = example.locator(".ash-scan__report-lines i").first();
  await expect(check).toHaveCSS("opacity", "0");
  expect(await reportLine.evaluate(
    element => new DOMMatrixReadOnly(getComputedStyle(element).transform).a
  )).toBeCloseTo(0, 4);
  await example.locator('[data-scan-step="2"]').click();
  await expect(check).toHaveCSS("opacity", "1");
  expect(await reportLine.evaluate(
    element => new DOMMatrixReadOnly(getComputedStyle(element).transform).a
  )).toBeCloseTo(0, 4);
  await example.locator('[data-scan-step="3"]').click();
  await expect(example.locator("[data-scan-state]")).toHaveText("Reports ready");
  expect(await reportLine.evaluate(
    element => new DOMMatrixReadOnly(getComputedStyle(element).transform).a
  )).toBeCloseTo(1, 4);
  await example.locator('[data-scan-category="all"]').click();
  await expect(example.locator(".ash-scan__route.is-active")).toHaveCount(8);
});

test("vector playback moves, pauses, resumes, and obeys the persistent motion setting", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.goto("./");
  const example = page.locator("[data-ash-scan]");
  await expect(example).toHaveClass(/is-ready/);
  await expect(example.locator("[data-scan-play]")).toHaveAccessibleName("Pause scan example");
  await expect.poll(() => scale(page)).toBeGreaterThan(.02);
  await example.locator("[data-scan-play]").click();
  await expect(example.locator("[data-scan-play]")).toHaveAccessibleName("Play scan example");
  const paused = await scale(page);
  await page.waitForTimeout(200);
  expect(await scale(page)).toBeCloseTo(paused, 4);
  await example.locator("[data-scan-play]").click();
  await expect.poll(() => scale(page)).toBeGreaterThan(paused + .01);
  await page.locator("[data-ash-motion]").click();
  await expect(example).toHaveAttribute("data-step", "3");
  await expect(example.locator("[data-scan-play]")).toBeDisabled();
  await expect(example.locator("[data-scan-state]")).toHaveText("Reports ready");
  await page.reload();
  await expect(page.locator("[data-scan-play]")).toBeDisabled();
  await expect(page.locator("[data-scan-state]")).toHaveText("Reports ready");
});

test("keyboard focus stops automatic playback and step buttons remain operable", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.goto("./");
  const example = page.locator("[data-ash-scan]");
  await expect(example.locator("[data-scan-play]")).toHaveAccessibleName("Pause scan example");
  await example.locator('[data-scan-category="code"]').focus();
  await expect(example.locator("[data-scan-play]")).toHaveAccessibleName("Play scan example");
  const paused = await scale(page);
  await page.waitForTimeout(200);
  expect(await scale(page)).toBeCloseTo(paused, 4);
  await example.locator('[data-scan-step="2"]').focus();
  await page.keyboard.press("Enter");
  await expect(example).toHaveAttribute("data-step", "2");
  await expect(example.locator('[data-scan-step="2"]')).toHaveAttribute("aria-pressed", "true");
});

test("vector routes adapt to mobile layout and a live reduced-motion change", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.goto("./");
  const example = page.locator("[data-ash-scan]");
  await expect(example).toHaveClass(/is-ready/);
  await example.locator('[data-scan-category="dependencies"]').click();
  await page.setViewportSize({ width: 390, height: 1000 });
  await expect.poll(() => example.locator("[data-scan-routes]").evaluate(
    svg => Math.round(svg.viewBox.baseVal.width) === Math.round(svg.parentElement.getBoundingClientRect().width)
  )).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
  await expect(example.locator(".ash-scan__scanner.is-selected")).toContainText("Grype");
  await page.emulateMedia({ reducedMotion: "reduce" });
  await expect(example.locator("[data-scan-play]")).toBeDisabled();
  await expect(example.locator("[data-scan-state]")).toHaveText("Reports ready");
  expect(await scale(page)).toBeCloseTo(1, 4);
});

test("the static example survives an unavailable animation module", async ({ page }) => {
  await page.route("**/assets/javascripts/ash-scan.js", route => route.abort());
  await page.goto("./");
  const example = page.locator("[data-ash-scan]");
  await expect(example.locator("[data-scan-source]")).toHaveCount(4);
  await expect(example.locator("[data-scan-finding]")).toHaveCount(4);
  await expect(example.locator("[data-scan-state]")).toHaveText("Reports ready");
  await expect(example.locator("[data-scan-play]")).toBeHidden();
  await expect(example.getByRole("link", { name: "HTML", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Start scanning", exact: true }).click();
  await expect(page.locator("#quickstart")).toBeInViewport();
});
