// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Runs the extension's snapshot suites, and is the only way to rewrite them.
 *
 *     npm run snapshots -- structural            jest snapshots, compare only
 *     npm run snapshots -- visual                pixel snapshots in the pinned container
 *     npm run snapshots -- all
 *     npm run snapshots -- --snapshot-update <structural|visual|all>
 *     npm run snapshots -- visual --artifacts <dir>   keep the captures and diffs
 *
 * `--snapshot-update` is refused when CI or GITHUB_ACTIONS is "true" (see
 * update-policy.ts), and test/snapshot-policy.test.ts fails if any workflow passes
 * it. After an update, read `git diff`, then commit with
 * `--trailer "Snapshot-Update: <why the output changed>"`; the editor-snapshots job
 * runs .github/scripts/check-snapshot-trailers.py and fails a changed
 * snapshot or PNG whose commit carries no such trailer.
 *
 * The visual suite builds test/visual/Dockerfile and runs test/visual/run.ts in it.
 * It needs `npm run compile && npm run compile:integration` first, which the
 * `snapshots` npm script does.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { UPDATE_ENV, UPDATE_FLAG, updateAllowed } from './update-policy';

/** The package root, from out-integration/test at run time. */
const PACKAGE_ROOT = path.resolve(__dirname, '..', '..');
const IMAGE = process.env.ASH_VISUAL_IMAGE ?? 'ash-vscode-visual:local';

function run(program: string, args: readonly string[]): void {
  process.stdout.write(`+ ${program} ${args.join(' ')}\n`);
  const result = spawnSync(program, args, { stdio: 'inherit', cwd: PACKAGE_ROOT });
  if (result.error !== undefined) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${program} exited ${String(result.status)}`);
  }
}

function structural(update: boolean): void {
  const jest = path.join(PACKAGE_ROOT, 'node_modules', 'jest', 'bin', 'jest.js');
  // The whole suite, so an update also removes snapshots no test asserts any more.
  run(process.execPath, update ? [jest, '--ci=false', '--updateSnapshot'] : [jest, '--ci']);
}

function visual(update: boolean, artifacts: string | undefined): void {
  run('docker', ['build', '--tag', IMAGE, path.join(PACKAGE_ROOT, 'test', 'visual')]);
  const args = ['run', '--rm', '--volume', `${PACKAGE_ROOT}:/ext`, '--workdir', '/ext', '--env', 'HOME=/tmp/home'];
  // The suite writes baselines and captures into the mounted tree, so it runs as the
  // invoking user rather than root, and leaves files that user owns.
  if (typeof process.getuid === 'function' && typeof process.getgid === 'function') {
    args.push('--user', `${process.getuid()}:${process.getgid()}`);
  }
  // Passed through so the refusal in run.ts sees CI too, not only this process.
  for (const name of ['CI', 'GITHUB_ACTIONS']) {
    if (process.env[name] !== undefined) {
      args.push('--env', `${name}=${process.env[name]}`);
    }
  }
  if (update) {
    args.push('--env', `${UPDATE_ENV}=1`);
  }
  if (artifacts !== undefined) {
    fs.mkdirSync(artifacts, { recursive: true });
    args.push('--volume', `${path.resolve(artifacts)}:/artifacts`, '--env', 'ASH_VISUAL_ARTIFACTS=/artifacts');
  }
  args.push(IMAGE, 'node', 'out-integration/test/visual/run.js');
  run('docker', args);
}

function main(argv: readonly string[]): void {
  const update = updateAllowed(argv.includes(UPDATE_FLAG), process.env);
  const artifactsAt = argv.indexOf('--artifacts');
  const artifacts = artifactsAt >= 0 ? argv[artifactsAt + 1] : undefined;
  if (artifactsAt >= 0 && (artifacts === undefined || artifacts.startsWith('--'))) {
    throw new Error('--artifacts needs a directory');
  }
  const known = new Set([UPDATE_FLAG, '--artifacts', artifacts]);
  const targets = argv.filter((a) => !known.has(a));
  if (targets.length !== 1 || !['structural', 'visual', 'all'].includes(targets[0])) {
    throw new Error(`usage: snapshots [${UPDATE_FLAG}] <structural|visual|all> [--artifacts <dir>]`);
  }
  if (targets[0] !== 'visual') {
    structural(update);
  }
  if (targets[0] !== 'structural') {
    visual(update, artifacts);
  }
}

try {
  main(process.argv.slice(2));
} catch (error: unknown) {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}
