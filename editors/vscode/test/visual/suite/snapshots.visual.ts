// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The pixel snapshots. Each test drives the real workbench into one state through
 * the extension's own command and VS Code's commands, waits until the screen stops
 * changing, captures it, and compares the capture with its committed baseline at a
 * threshold of zero differing pixels.
 *
 * The tests run in order in one window, because the first depends on the PATH
 * run.ts set up (no `ashx`, so the fallback notice appears) and every later one
 * adds an `ashx`. Apart from that, each scene builds the state it shows, and a
 * teardown resets the workbench after every test, so a failure in one scene
 * cannot change what the next one captures.
 *
 * WHY "WAIT UNTIL IT STOPS CHANGING" AND NOT A FIXED DELAY
 *
 * A fixed delay is a guess about how long the workbench takes to lay out, and a
 * guess that is short on a slow runner captures a half-drawn frame. Instead the
 * screen is captured repeatedly until STABLE_FRAMES consecutive captures have the
 * same pixel signature. Something that never stops changing (a blinking caret, a
 * spinner) fails the test with a timeout rather than producing a baseline that
 * depends on when it was taken; the settings run.ts writes remove every such thing
 * the suite's states would otherwise show.
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { ScanReport } from '../../../src/extension';
import { VISUAL_SCENARIOS } from '../scenarios';
import { captureScreen, differingPixels, pixelSignature } from '../screens';

const DISPLAY = process.env.ASH_VISUAL_DISPLAY ?? '';
const WORKSPACE = process.env.ASH_VISUAL_WORKSPACE ?? '';
const ASHX_DIR = process.env.ASH_VISUAL_ASHX_DIR ?? '';
const ASHX_WRAPPER = process.env.ASH_VISUAL_ASHX_WRAPPER ?? '';
const BASELINES = process.env.ASH_VISUAL_BASELINES ?? '';
const ACTUAL = process.env.ASH_VISUAL_ACTUAL ?? '';
const UPDATE = process.env.ASH_VISUAL_UPDATE === '1';
const SCENARIO_FILE = process.env.ASH_STUB_SCENARIO_FILE ?? '';

/** Consecutive identical captures that count as "the screen has settled". */
const STABLE_FRAMES = 4;
const FRAME_INTERVAL_MS = 250;
const SETTLE_TIMEOUT_MS = 30_000;

const compared = new Set<string>();

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Captures until the screen holds still, and returns the last capture's path. */
async function settledCapture(name: string): Promise<string> {
  const started = Date.now();
  let previous = '';
  let streak = 0;
  let frame = 0;
  for (;;) {
    const file = path.join(ACTUAL, `${name}.frame${frame % 2}.png`);
    captureScreen(DISPLAY, file);
    const signature = pixelSignature(file);
    streak = signature === previous ? streak + 1 : 1;
    previous = signature;
    if (streak >= STABLE_FRAMES) {
      const settled = path.join(ACTUAL, `${name}.png`);
      fs.copyFileSync(file, settled);
      return settled;
    }
    if (Date.now() - started > SETTLE_TIMEOUT_MS) {
      throw new Error(`${name}: the screen was still changing after ${SETTLE_TIMEOUT_MS}ms`);
    }
    frame += 1;
    await sleep(FRAME_INTERVAL_MS);
  }
}

/** Captures the settled screen and holds it to the baseline, or writes the baseline. */
async function matchesBaseline(name: string): Promise<void> {
  const scenario = VISUAL_SCENARIOS.find((s) => s.name === name);
  assert.ok(scenario !== undefined, `${name} is not in test/visual/scenarios.ts`);
  compared.add(name);
  const actual = await settledCapture(name);
  const baseline = path.join(BASELINES, `${name}.png`);
  if (UPDATE) {
    fs.copyFileSync(actual, baseline);
    return;
  }
  assert.ok(
    fs.existsSync(baseline),
    `${baseline} does not exist. A new visual snapshot is written only by ` +
      '`npm run snapshots -- --snapshot-update visual`, and committed with a Snapshot-Update trailer.',
  );
  const diff = path.join(ACTUAL, `${name}.diff.png`);
  const count = differingPixels(baseline, actual, diff);
  assert.strictEqual(
    count,
    0,
    `${name} (${scenario.shows}) differs from its baseline in ${count} pixel(s). ` +
      `Actual: ${actual}; diff: ${diff}. If the change is intended, update the baseline ` +
      'and commit it with a Snapshot-Update trailer saying why.',
  );
}

async function scan(fixture: string): Promise<ScanReport> {
  fs.writeFileSync(SCENARIO_FILE, JSON.stringify({ fixture }));
  return vscode.commands.executeCommand<ScanReport>('ash.scanWorkspace');
}

async function clearNotifications(): Promise<void> {
  await vscode.commands.executeCommand('notifications.clearAll');
}

/**
 * Expands the toast that `notifications.focusToasts` focuses, the lowest one, so the
 * picture holds its whole message rather than the one line a collapsed toast
 * shows. The message is what these snapshots are about, and a change past its first
 * line would otherwise not move a pixel.
 *
 * The extension raises its notifications without awaiting them, so a toast can
 * still be on its way when the command that raised it returns. The screen is let
 * settle first, so the toast is there to focus.
 */
async function expandLowestToast(name: string): Promise<void> {
  await settledCapture(`${name}.before-expand`);
  await vscode.commands.executeCommand('notifications.focusToasts');
  await settledCapture(`${name}.focused`);
  await vscode.commands.executeCommand('notification.expand');
}

/**
 * Puts `ashx` on the PATH run.ts gave the extension host. Only the first scene runs
 * without it, to show the ashx -> ash fallback notice; every other scene installs it
 * itself, so none depends on the first one having got as far as installing it.
 */
function installAshx(): void {
  fs.writeFileSync(path.join(ASHX_DIR, 'ashx'), ASHX_WRAPPER, { mode: 0o755 });
}

/** Closes everything a scene can open: hover, editors, panel and notifications. */
async function resetWorkbench(): Promise<void> {
  await vscode.commands.executeCommand('editor.action.hideHover');
  await vscode.commands.executeCommand('workbench.action.closeAllEditors');
  await vscode.commands.executeCommand('workbench.action.closePanel');
  await clearNotifications();
}

suite('ASH visual snapshots', () => {
  suiteSetup(async () => {
    for (const [name, value] of Object.entries({ DISPLAY, WORKSPACE, ASHX_DIR, BASELINES, ACTUAL })) {
      assert.ok(value !== '', `${name} was not passed to the extension host`);
    }
  });

  // Every scene starts from the same empty workbench, whether the scene before it
  // passed or failed. The cleanup used to be the last lines of each test, after its
  // assertion, so one failed comparison left a hover and an open editor on screen
  // and the next scene failed by a whole screen for a reason that was not its own.
  teardown(resetWorkbench);

  test('fallback-notice', async () => {
    const report = await scan('clean');
    assert.strictEqual(report.status, 'ok', report.detail);
    assert.strictEqual(report.fallbackNotice, 'shown');
    // Two toasts: the scan's result above, and below it the fallback notice, which
    // was raised first.
    await expandLowestToast('fallback-notice');
    await matchesBaseline('fallback-notice');
  });

  test('problems-panel', async () => {
    installAshx();
    const report = await scan('findings');
    assert.strictEqual(report.status, 'ok', report.detail);
    assert.ok((report.summary?.diagnostics ?? 0) > 0, 'the findings scan published nothing');
    const document = await vscode.workspace.openTextDocument(path.join(WORKSPACE, 'planted_secret.py'));
    await vscode.window.showTextDocument(document, { preview: false });
    await vscode.commands.executeCommand('workbench.actions.view.problems');
    await clearNotifications();
    await matchesBaseline('problems-panel');
  });

  test('diagnostic-hover', async () => {
    installAshx();
    // The state the problems-panel scene leaves, rebuilt here rather than inherited,
    // so this scene does not depend on that one having run or passed.
    const report = await scan('findings');
    assert.strictEqual(report.status, 'ok', report.detail);
    const file = vscode.Uri.file(path.join(WORKSPACE, 'planted_secret.py'));
    await vscode.window.showTextDocument(file, { preview: false });
    await vscode.commands.executeCommand('workbench.actions.view.problems');
    await clearNotifications();
    const editor = await vscode.window.showTextDocument(file, { preview: false });
    const diagnostics = vscode.languages.getDiagnostics(editor.document.uri);
    assert.ok(diagnostics.length > 0, 'no diagnostics on planted_secret.py to hover over');
    const at = new vscode.Position(diagnostics[0].range.start.line, 4);
    editor.selection = new vscode.Selection(at, at);
    editor.revealRange(new vscode.Range(at, at), vscode.TextEditorRevealType.InCenter);
    await vscode.commands.executeCommand('editor.action.showHover');
    await matchesBaseline('diagnostic-hover');
  });

  test('incomplete-scan-notification', async () => {
    installAshx();
    // The Problems panel is in the picture because it shows the partial results the
    // warning is about.
    await vscode.commands.executeCommand('workbench.actions.view.problems');
    const report = await scan('incomplete');
    assert.strictEqual(report.status, 'incomplete', report.detail);
    assert.strictEqual(report.exitCode, 1);
    await expandLowestToast('incomplete-scan-notification');
    await matchesBaseline('incomplete-scan-notification');
  });

  test('every baseline was compared', () => {
    const baselines = fs
      .readdirSync(BASELINES)
      .filter((name) => name.endsWith('.png'))
      .map((name) => name.slice(0, -'.png'.length));
    const unused = baselines.filter((name) => !compared.has(name)).sort();
    assert.deepStrictEqual(
      unused,
      [],
      `baseline(s) no test captured: ${unused.join(', ')}. Delete them, or add the scenario back.`,
    );
    assert.deepStrictEqual(
      [...compared].sort(),
      VISUAL_SCENARIOS.map((s) => s.name).sort(),
      'the suite did not capture every scenario in test/visual/scenarios.ts',
    );
  });
});
