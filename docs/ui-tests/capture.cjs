// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Capture review images from the built site and fixture-generated interfaces.
const { chromium } = require("@playwright/test");
const { spawn } = require("node:child_process");
const { pathToFileURL } = require("node:url");
const fs = require("node:fs/promises");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");
const output = process.env.DOCS_UI_PREVIEWS || path.join(__dirname, ".previews");
let server;
let browser;

async function startServer() {
  if (process.env.DOCS_UI_BASE_URL) return process.env.DOCS_UI_BASE_URL;
  await fs.access(path.join(root, "public/index.html"));
  server = spawn(process.env.DOCS_UI_PYTHON || "python3", [
    "-u", "-m", "http.server", "0", "--bind", "127.0.0.1",
    "--directory", path.join(root, "public"),
  ], { stdio: ["ignore", "pipe", "ignore"] });
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Local preview server did not start")), 10000);
    server.once("error", error => { clearTimeout(timeout); reject(error); });
    server.once("exit", code => {
      clearTimeout(timeout);
      if (code) reject(new Error(`Local preview server exited with ${code}`));
    });
    server.stdout.on("data", data => {
      const port = data.toString().match(/port (\d+)/);
      if (port) {
        clearTimeout(timeout);
        resolve(`http://127.0.0.1:${port[1]}`);
      }
    });
  });
}

(async () => {
  await fs.mkdir(output, { recursive: true });
  const base = await startServer();
  const baseUrl = base.endsWith("/") ? base : `${base}/`;
  const siteUrl = relative => new URL(relative, baseUrl).href;
  browser = await chromium.launch({
    executablePath: process.env.DOCS_UI_CHROME || undefined,
    headless: true,
  });
  const images = [];
  async function capture(name, url, width, theme) {
    const context = await browser.newContext({
      viewport: { width, height: 1000 },
      colorScheme: theme,
      reducedMotion: "reduce",
    });
    try {
      const page = await context.newPage();
      if (!process.env.DOCS_UI_BASE_URL) {
        const prefix = new URL("automated-security-helper/", baseUrl).href;
        await page.route(`${prefix}**`, async route => {
          const target = new URL(route.request().url().slice(prefix.length), baseUrl);
          await route.fulfill({ response: await route.fetch({ url: target.href }) });
        });
      }
      await page.goto(url, { waitUntil: "networkidle" });
      await page.evaluate(() => document.fonts.ready);
      const filename = `${name}.png`;
      await page.screenshot({ path: path.join(output, filename), fullPage: true });
      images.push({ name, filename });
    } finally {
      await context.close();
    }
  }
  for (const theme of ["dark", "light"]) {
    for (const width of [390, 1440]) {
      await capture(`site-${width}-${theme}`, siteUrl("./"), width, theme);
      await capture(`report-${width}-${theme}`, pathToFileURL(path.join(output, "review-report.html")).href, width, theme);
    }
  }
  await capture("handbook-desktop", siteUrl("docs/quick-start-guide/"), 1440, "dark");
  await capture("handbook-mobile", siteUrl("docs/quick-start-guide/"), 390, "dark");
  await capture("not-found", siteUrl("404.html"), 1440, "dark");
  for (const name of ["review", "empty", "workspace"]) {
    await capture(`comment-${name}`, pathToFileURL(path.join(output, `${name}-comment.html`)).href, 920, "dark");
    if (name !== "review") {
      await capture(`report-${name}`, pathToFileURL(path.join(output, `${name}-report.html`)).href, 1440, "dark");
    }
  }
  for (const filename of (await fs.readdir(output)).filter(name => name.endsWith(".svg"))) {
    const page = await browser.newPage();
    try {
      await page.goto(pathToFileURL(path.join(output, filename)).href);
      const size = await page.evaluate(() => ({
        width: Math.ceil(document.documentElement.viewBox.baseVal.width),
        height: Math.ceil(document.documentElement.viewBox.baseVal.height),
      }));
      await page.setViewportSize(size);
      const image = filename.replace(/\.svg$/, ".png");
      await page.screenshot({ path: path.join(output, image) });
      images.push({ name: filename.replace(/\.svg$/, ""), filename: image });
    } finally {
      await page.close();
    }
  }
  if (process.argv.includes("--readme")) {
    const assets = path.join(root, "docs/assets/readme");
    await fs.mkdir(assets, { recursive: true });
    for (const theme of ["dark", "light"]) {
      const context = await browser.newContext({
        viewport: { width: 1200, height: 1120 }, colorScheme: theme, reducedMotion: "reduce",
      });
      try {
        const page = await context.newPage();
        await page.goto(pathToFileURL(path.join(output, "review-report.html")).href);
        await page.evaluate(() => document.fonts.ready);
        await page.screenshot({ path: path.join(assets, `report-${theme}.png`) });
      } finally {
        await context.close();
      }
    }
    await fs.copyFile(path.join(output, "tui-80.png"), path.join(assets, "findings-terminal.png"));
    console.log(`Updated README fixture images: ${assets}`);
  }
  let motion = "";
  if (process.argv.includes("--motion")) {
    const context = await browser.newContext({
      viewport: { width: 1440, height: 1000 },
      colorScheme: "dark",
      reducedMotion: "no-preference",
      recordVideo: { dir: output, size: { width: 1440, height: 1000 } },
    });
    const page = await context.newPage();
    try {
      await page.goto(siteUrl("./"));
      await page.locator("[data-ash-scan].is-ready").waitFor();
      await page.locator('[data-scan-category="secrets"]').click();
      await page.waitForTimeout(11000);
      await page.locator('[data-scan-category="all"]').click();
      await page.waitForTimeout(11000);
      await page.screenshot({ path: path.join(output, "scan-example-poster.png") });
    } finally {
      const video = page.video();
      await context.close();
      await video.saveAs(path.join(output, "scan-example.webm"));
      await fs.unlink(await video.path());
    }
    motion = '<h2>Scan example</h2><video controls muted playsinline preload="metadata" poster="scan-example-poster.png" src="scan-example.webm"></video>';
  }
  const font = await fs.readFile(path.join(root, "docs/content/assets/fonts/open-sans.woff2"));
  const fontLicense = await fs.readFile(path.join(root, "docs/content/assets/fonts/open-sans-OFL.txt"), "utf8");
  const cards = images.map(({ name, filename }) =>
    `<a href="${filename}"><img src="${filename}" alt="${name.replaceAll("-", " ")}" loading="lazy"><span>${name}</span></a>`
  ).join("\n");
  await fs.writeFile(path.join(output, "gallery.html"), `<!DOCTYPE html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ASH interface gallery</title>
<style>/* ${fontLicense} */
@font-face{font-family:"Open Sans";font-style:normal;font-weight:300 800;font-display:swap;src:url("data:font/woff2;base64,${font.toString("base64")}") format("woff2")}
*{box-sizing:border-box}body{margin:0;background:#0f141a;color:#dedee3;font:16px/1.5 "Open Sans",Helvetica,Arial,sans-serif}main{max-width:1500px;padding:32px 24px;margin:auto}h1{font-size:24px;font-weight:700}h2{font-size:20px;margin-top:32px}p{color:#b4b4bb}a{color:#42b4ff}section{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:24px}section a{display:block;background:#161d26;border:1px solid #424650;border-radius:16px;overflow:hidden;text-decoration:none}img{display:block;width:100%;height:280px;object-fit:cover;object-position:top}span{display:block;padding:12px 16px}video{display:block;width:100%;max-width:1200px;border:1px solid #424650;border-radius:16px}:focus-visible{outline:2px solid #42b4ff;outline-offset:4px}footer{margin-top:32px;padding-top:16px;border-top:1px solid #424650;font-size:12px;color:#b4b4bb}</style>
<main><h1>ASH interface gallery</h1><p><a href="index.html">Reports and terminal previews</a></p><section>${cards}</section>${motion}<footer>Build with &lt;3 at Amazon Web Services</footer></main></html>`);
  console.log(`Review gallery: ${path.join(output, "gallery.html")}`);
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
}).finally(async () => {
  if (browser) await browser.close();
  if (server) server.kill();
});
