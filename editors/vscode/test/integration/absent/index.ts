// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Test entry point for an uninstalled extension, loaded by @vscode/test-electron
 * inside the extension host. It runs no mocha suite: it requires that the
 * extension named by ASH_IT_EXPECT_ABSENT_ID is not loaded and that none of the
 * commands it contributes is registered, in a VS Code started on the extensions
 * directory it was uninstalled from.
 *
 * Uninstalling through the CLI empties extensions.json but leaves the extension's
 * folder on disk (measured with VS Code 1.140.0), so the listing alone does not
 * show the code can no longer load. Starting VS Code on that directory does.
 *
 * What it found is written to ASH_IT_RESULTS_FILE, when set, before any verdict,
 * so the negative control in vsix-e2e.ts can require that a failing run failed
 * because the extension was loaded and not for some other reason.
 */

import * as fs from 'fs';
import * as vscode from 'vscode';

export async function run(): Promise<void> {
  const id = process.env.ASH_IT_EXPECT_ABSENT_ID ?? '';
  if (id === '') {
    throw new Error('ASH_IT_EXPECT_ABSENT_ID is not set');
  }
  const loaded = vscode.extensions.getExtension(id);
  const commands = (await vscode.commands.getCommands(true)).filter((command) => command.startsWith('ash.'));
  const resultsFile = process.env.ASH_IT_RESULTS_FILE ?? '';
  if (resultsFile !== '') {
    fs.writeFileSync(resultsFile, JSON.stringify({ loadedFrom: loaded?.extensionPath ?? null, commands }));
  }
  if (loaded !== undefined) {
    throw new Error(`${id} is still loaded after uninstalling, from ${loaded.extensionPath}`);
  }
  if (commands.length > 0) {
    throw new Error(`commands from ${id} are still registered: ${commands.join(', ')}`);
  }
  // The positive half: the same lookup does find an extension that is there, so an
  // undefined above is not the lookup failing.
  if (vscode.extensions.getExtension('ash-it.ash-it-host') === undefined) {
    throw new Error('the lookup did not find the host extension, so it cannot show anything absent');
  }
  console.log(`${id} is not loaded and registers no commands`);
}
