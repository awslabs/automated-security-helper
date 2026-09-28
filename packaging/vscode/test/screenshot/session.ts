// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Not a test. Drives the extension into the state worth photographing and then
 * holds the window open so an external capture can fire.
 *
 * It exists because the assertions in test/suite prove behavior but produce no
 * artifact a person can look at, and VS Code exits the moment a test run
 * finishes. This loads through the same `extensionTestsPath` mechanism, so the
 * window it leaves on screen is a real extension host running the real
 * extension -- not a mock-up.
 *
 * Every step is asserted rather than assumed. A screenshot of a window where the
 * scan silently failed would be worse than no screenshot: it would look like
 * evidence.
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

import { SCAN_COMMAND, type ScanOutcome } from '../../src/extension';

const HOLD_MS = Number(process.env['ASH_SHOT_HOLD_MS'] ?? '45000');

function requireEnv(name: string): string {
  const value = process.env[name];
  assert.ok(value !== undefined && value.length > 0, `${name} was not set`);
  return value;
}

export async function run(): Promise<void> {
  const workspace = requireEnv('ASH_TEST_WORKSPACE');
  const scratch = requireEnv('ASH_TEST_SCRATCH');
  const sarifFixture = requireEnv('ASH_TEST_SARIF_FIXTURE');

  const binDir = path.join(scratch, 'stub-bin');
  fs.mkdirSync(binDir, { recursive: true });
  const stub = path.join(binDir, 'ash');
  fs.writeFileSync(
    stub,
    [
      '#!/bin/sh',
      'set -e',
      'out=""',
      'while [ $# -gt 0 ]; do',
      '  case "$1" in',
      '    --output-dir) out="$2"; shift 2 ;;',
      '    *) shift ;;',
      '  esac',
      'done',
      'mkdir -p "$out/reports"',
      `cp ${JSON.stringify(sarifFixture)} "$out/reports/ash.sarif"`,
      'exit 1',
      '',
    ].join('\n'),
    { mode: 0o755 },
  );

  // Global, not Workspace: `ash.executablePath` is machine-scoped so a repository
  // cannot name the program this extension runs, and VS Code refuses a
  // workspace-level write to it.
  await vscode.workspace
    .getConfiguration('ash')
    .update('executablePath', stub, vscode.ConfigurationTarget.Global);

  const outcome = await vscode.commands.executeCommand<ScanOutcome>(SCAN_COMMAND);
  assert.ok(outcome !== undefined, 'the scan command returned nothing');
  assert.strictEqual(
    outcome.ok,
    true,
    `scan failed, so there is nothing worth photographing: ${outcome.reason} ${outcome.message}`,
  );
  assert.strictEqual(outcome.diagnosticCount, 5);

  // Open the file with the three app.py findings so the squiggles and the gutter
  // marks are on screen, not just the panel listing.
  const document = await vscode.workspace.openTextDocument(
    vscode.Uri.file(path.join(workspace, 'src', 'app.py')),
  );
  await vscode.window.showTextDocument(document, { preview: false });

  // Confirm the editor really has diagnostics before holding the window: this is
  // the check that stops a blank-looking screenshot being presented as proof.
  const visible = vscode.languages.getDiagnostics(document.uri);
  assert.strictEqual(
    visible.length,
    3,
    `expected 3 diagnostics in the open editor, found ${visible.length}`,
  );

  // The Problems panel lists every finding with its severity icon, which is the
  // part of the screenshot that shows the level mapping actually took effect.
  await vscode.commands.executeCommand('workbench.actions.view.problems');

  console.log(
    `[screenshot-session] ready: ${outcome.diagnosticCount} diagnostics across ` +
      `${outcome.fileCount} files; holding the window for ${HOLD_MS}ms`,
  );

  await new Promise((resolve) => setTimeout(resolve, HOLD_MS));
  console.log('[screenshot-session] hold elapsed, closing');
}
