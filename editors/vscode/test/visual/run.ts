// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Renders the extension's UI in a real VS Code and compares it with the committed
 * PNG baselines in test/visual/__snapshots__/.
 *
 * Runs only inside the container test/visual/Dockerfile builds, which fixes
 * everything else a pixel depends on: the VS Code build, the fonts, fontconfig and
 * FreeType, and Xvfb. This file fixes the rest: the screen geometry and DPI, the
 * device scale factor, the theme, the editor font and size, and every setting that
 * would otherwise put something time-dependent on screen. The fixed paths matter
 * too: the workspace folder's name is in the window title, so it is the same
 * directory on every run.
 *
 *     npm run snapshots -- visual                      compare (what CI runs)
 *     npm run snapshots -- --snapshot-update visual    rewrite the baselines;
 *                                                      refused under CI
 *
 * The CLI behind every scan is test/integration/ash-stub.ts replaying a captured
 * scan, so the findings on screen are what a real ASH run wrote.
 */

import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { runTests } from '@vscode/test-electron';
import { UPDATE_ENV, updateAllowed } from '../update-policy';

/** The extension package root, from out-integration/test/visual at run time. */
const PACKAGE_ROOT = path.resolve(__dirname, '..', '..', '..');

/** Fixed, because the workspace folder's name and path are drawn on screen. */
const SCRATCH = '/tmp/ash-visual';
const WORKSPACE = path.join(SCRATCH, 'sample-project');

const DISPLAY = ':99';
/** The screen, and so the largest the window can be. */
const SCREEN = { width: 1280, height: 800, depth: 24, dpi: 96 };

/**
 * User settings for the run. Each one removes a source of variation between two
 * renders of the same state, or something that would draw over the extension's
 * own UI. The comments say which.
 */
const USER_SETTINGS: Readonly<Record<string, unknown>> = {
  // The look: one theme and one font, named rather than defaulted, because a
  // default can change between releases even at a pinned version's settings.
  'workbench.colorTheme': 'Default Dark Modern',
  'editor.fontFamily': 'DejaVu Sans Mono',
  'editor.fontSize': 14,
  'editor.lineHeight': 20,
  'window.zoomLevel': 0,
  'window.titleBarStyle': 'custom',
  'window.commandCenter': false,
  'workbench.layoutControl.enabled': false,
  // No blinking caret and no animation: either would make two captures of one
  // state differ by when they were taken.
  'editor.cursorBlinking': 'solid',
  'editor.cursorSmoothCaretAnimation': 'off',
  'editor.smoothScrolling': false,
  'workbench.reduceMotion': 'on',
  'workbench.list.smoothScrolling': false,
  // Nothing that opens on its own.
  'workbench.startupEditor': 'none',
  'workbench.tips.enabled': false,
  'workbench.welcomePage.walkthroughs.openOnInstall': false,
  'workbench.enableExperiments': false,
  'workbench.secondarySideBar.defaultVisibility': 'hidden',
  'chat.disableAIFeatures': true,
  'update.mode': 'none',
  'update.showReleaseNotes': false,
  'extensions.autoCheckUpdates': false,
  'extensions.autoUpdate': false,
  'extensions.ignoreRecommendations': true,
  'telemetry.telemetryLevel': 'off',
  'git.enabled': false,
  'scm.diffDecorations': 'none',
  'security.workspace.trust.enabled': false,
  'window.restoreWindows': 'none',
  'files.hotExit': 'off',
  // Content that depends on anything but the file and the findings.
  'editor.minimap.enabled': false,
  'editor.lightbulb.enabled': 'off',
  'editor.codeLens': false,
  'editor.inlayHints.enabled': 'off',
  'editor.occurrencesHighlight': 'off',
  'editor.selectionHighlight': false,
  'editor.renderLineHighlight': 'none',
  'editor.stickyScroll.enabled': false,
  'editor.hover.delay': 300,
  'breadcrumbs.enabled': false,
  'problems.showCurrentInStatus': false,
  'accessibility.signalOptions.volume': 0,
};

function wrapper(node: string, stub: string, invokedAs: string): string {
  return `#!/bin/sh\nASH_STUB_INVOKED_AS=${invokedAs} exec "${node}" "${stub}" "$@"\n`;
}

/** Refuses to render anywhere but the pinned container. */
function requireContainer(): string {
  const executable = process.env.ASH_VISUAL_VSCODE ?? '';
  if (executable === '' || !fs.existsSync(executable)) {
    throw new Error(
      'ASH_VISUAL_VSCODE is not set to an installed VS Code. The visual snapshots are ' +
        'rendered only inside the container test/visual/Dockerfile builds; see ' +
        'test/visual/README.md, "Running it". `npm run snapshots -- visual` builds and runs it.',
    );
  }
  return executable;
}

function startXvfb(): Promise<ChildProcess> {
  const socket = `/tmp/.X11-unix/X${DISPLAY.slice(1)}`;
  if (fs.existsSync(socket)) {
    throw new Error(`${socket} exists: another X server holds ${DISPLAY}`);
  }
  const xvfb = spawn(
    'Xvfb',
    [
      DISPLAY,
      '-screen',
      '0',
      `${SCREEN.width}x${SCREEN.height}x${SCREEN.depth}`,
      '-dpi',
      String(SCREEN.dpi),
      '-nolisten',
      'tcp',
      '-noreset',
    ],
    { stdio: ['ignore', 'ignore', 'inherit'] },
  );
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const poll = (): void => {
      if (xvfb.exitCode !== null) {
        reject(new Error(`Xvfb exited ${String(xvfb.exitCode)} before it was ready`));
      } else if (fs.existsSync(socket)) {
        resolve(xvfb);
      } else if (Date.now() - started > 10_000) {
        xvfb.kill();
        reject(new Error('Xvfb did not create its socket within 10s'));
      } else {
        setTimeout(poll, 50);
      }
    };
    poll();
  });
}

async function main(): Promise<void> {
  const vscodeExecutablePath = requireContainer();
  // Asked for by test/snapshots.ts; refused under CI whoever asked.
  const update = updateAllowed(process.env[UPDATE_ENV] === '1', process.env);

  fs.rmSync(SCRATCH, { recursive: true, force: true });
  const userData = path.join(SCRATCH, 'user-data');
  const ashxDir = path.join(SCRATCH, 'bin-ashx');
  const ashDir = path.join(SCRATCH, 'bin-ash');
  // The captures, and a diff image for each mismatch. CI mounts a directory here and
  // uploads it, so a failure can be looked at.
  const actualDir = process.env.ASH_VISUAL_ARTIFACTS || path.join(SCRATCH, 'actual');
  for (const dir of [WORKSPACE, path.join(userData, 'User'), path.join(SCRATCH, 'extensions'), ashxDir, ashDir, actualDir]) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify(USER_SETTINGS, null, 2));

  const fixtures = path.join(PACKAGE_ROOT, 'test', 'fixtures');
  const stub = path.join(PACKAGE_ROOT, 'out-integration', 'test', 'integration', 'ash-stub.js');
  fs.copyFileSync(path.join(fixtures, 'planted_secret.py'), path.join(WORKSPACE, 'planted_secret.py'));
  // Only `ash` at first: the first scenario is the ashx -> ash fallback notice.
  fs.writeFileSync(path.join(ashDir, 'ash'), wrapper(process.execPath, stub, 'ash'), { mode: 0o755 });
  const scenarioFile = path.join(SCRATCH, 'scenario.json');
  fs.writeFileSync(scenarioFile, JSON.stringify({ fixture: null, exitCode: 70 }));
  const resultsFile = path.join(SCRATCH, 'results.json');

  const xvfb = await startXvfb();
  try {
    await runTests({
      vscodeExecutablePath,
      extensionDevelopmentPath: PACKAGE_ROOT,
      extensionTestsPath: path.join(__dirname, 'suite', 'index'),
      extensionTestsEnv: {
        DISPLAY,
        ASH_VISUAL_DISPLAY: DISPLAY,
        ASH_VISUAL_WORKSPACE: WORKSPACE,
        ASH_VISUAL_ASHX_DIR: ashxDir,
        ASH_VISUAL_ASHX_WRAPPER: wrapper(process.execPath, stub, 'ashx'),
        ASH_VISUAL_BASELINES: path.join(PACKAGE_ROOT, 'test', 'visual', '__snapshots__'),
        ASH_VISUAL_ACTUAL: actualDir,
        ASH_VISUAL_UPDATE: update ? '1' : '',
        ASH_VISUAL_RESULTS_FILE: resultsFile,
        ASH_STUB_SCENARIO_FILE: scenarioFile,
        ASH_STUB_FIXTURES: fixtures,
        PATH: [ashxDir, ashDir, '/usr/local/bin', '/usr/bin', '/bin'].join(path.delimiter),
      },
      launchArgs: [
        WORKSPACE,
        // An empty extensions directory rather than --disable-extensions: the result
        // is the same (only built-in extensions and this one load), but
        // --disable-extensions announces itself in a toast that would sit in every
        // picture of the notification area.
        '--extensions-dir',
        path.join(SCRATCH, 'extensions'),
        '--disable-gpu',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-workspace-trust',
        '--force-disable-user-env',
        '--force-device-scale-factor=1',
        '--skip-welcome',
        '--skip-release-notes',
        '--disable-telemetry',
        '--disable-updates',
        '--locale=en',
        '--user-data-dir',
        userData,
      ],
    });
  } finally {
    xvfb.kill();
    if (fs.existsSync(resultsFile)) {
      process.stdout.write(`${fs.readFileSync(resultsFile, 'utf8')}\n`);
    }
  }
}

if (require.main === module) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.stack : error);
    process.exit(1);
  });
}
