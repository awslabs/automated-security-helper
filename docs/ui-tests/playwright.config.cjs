// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const { defineConfig } = require("@playwright/test");
const path = require("node:path");
const siteBase = process.env.DOCS_UI_BASE_URL || "http://127.0.0.1:8849";
const siteUrl = siteBase.endsWith("/") ? siteBase : `${siteBase}/`;

module.exports = defineConfig({
  testDir: "./specs",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : 3,
  timeout: 30000,
  expect: { timeout: 8000 },
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: siteUrl,
    viewport: { width: 1440, height: 1000 },
    colorScheme: "dark",
    reducedMotion: "reduce",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    launchOptions: process.env.DOCS_UI_CHROME
      ? { executablePath: process.env.DOCS_UI_CHROME }
      : {},
  },
  webServer: process.env.DOCS_UI_BASE_URL ? undefined : {
    command: `${process.env.DOCS_UI_PYTHON || "python3"} -m http.server 8849 --bind 127.0.0.1 --directory public`,
    cwd: path.resolve(__dirname, "../.."),
    url: siteUrl,
    reuseExistingServer: !process.env.CI,
    timeout: 15000,
  },
});
