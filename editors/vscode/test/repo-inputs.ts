// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The files outside editors/vscode that this package's jest suites read, and the
 * only way a suite may reach them.
 *
 * WHY THIS EXISTS
 *
 * The "ts (vscode)" job in .github/workflows/ash-typescript-ci.yml runs on push
 * and pull_request only when a path in its `paths:` filters changes. A suite that
 * reads a file outside editors/vscode depends on that file, so a change to the
 * file alone has to run the job; otherwise it can break the suite and nobody sees
 * it until something under editors/vscode changes. That is how the real ASH report
 * under tests/test_data came to be read by real-report.test.ts with no filter
 * entry.
 *
 * So every such read goes through `repoPath`, which refuses a path that is not
 * declared in REPO_INPUTS, and test/repo-inputs.test.ts checks two things: every
 * REPO_INPUTS entry is covered by both filters, and no suite climbs out of the
 * package except through this module.
 */

import * as path from 'path';

/** A repo-relative path or `<dir>/**` pattern, and why a suite reads it. */
export interface RepoInput {
  readonly pattern: string;
  readonly readBy: string;
}

export const REPO_INPUTS: readonly RepoInput[] = [
  {
    pattern: 'tests/test_data/outputs/ash_aggregated_results.json',
    readBy: 'real-report.test.ts parses it as the real multi-scanner report',
  },
  {
    pattern: '.github/**',
    readBy:
      'snapshot-policy.test.ts scans every file under .github/ for a snapshot update flag, and reads ' +
      'check-snapshot-trailers.py and ash-vscode-extension.yml by name',
  },
];

/** The repository root: test/ is two levels below editors/, which is one below the root. */
export const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');

/** `<dir>/**` matches the directory itself and everything under it; anything else matches exactly. */
export function patternMatches(pattern: string, relative: string): boolean {
  if (pattern.endsWith('/**')) {
    const dir = pattern.slice(0, -'/**'.length);
    return relative === dir || relative.startsWith(`${dir}/`);
  }
  return relative === pattern;
}

/**
 * The absolute path of a repo-relative file, refusing one that is not declared.
 * `relative` uses forward slashes.
 */
export function repoPath(relative: string, inputs: readonly RepoInput[] = REPO_INPUTS): string {
  if (!inputs.some((input) => patternMatches(input.pattern, relative))) {
    throw new Error(
      `${relative} is outside editors/vscode and not declared in test/repo-inputs.ts REPO_INPUTS. ` +
        'Declare it there and add it to the push and pull_request paths of ' +
        '.github/workflows/ash-typescript-ci.yml, so a change to it runs this suite.',
    );
  }
  return path.join(REPO_ROOT, ...relative.split('/'));
}

/**
 * The `paths:` entries under `on.<event>` of a workflow, read line by line.
 *
 * Not a YAML parser, and it does not need to be one: it reads one fixed shape
 * (`  <event>:` then `    paths:` then `      - "<entry>"`) and THROWS when that
 * shape is missing or empty, so a reformatted workflow fails here instead of
 * reading as "no filter entries".
 */
export function workflowPaths(workflow: string, event: string): string[] {
  const lines = workflow.split('\n');
  const isContent = (line: string): boolean => line.trim() !== '' && !line.trim().startsWith('#');
  const indentOf = (line: string): number => line.length - line.trimStart().length;

  const onIndex = lines.findIndex((line) => /^on:\s*$/.test(line));
  if (onIndex < 0) {
    throw new Error('the workflow has no top-level "on:" block');
  }
  let eventIndex = -1;
  for (let i = onIndex + 1; i < lines.length; i += 1) {
    if (isContent(lines[i]) && indentOf(lines[i]) === 0) {
      break;
    }
    if (new RegExp(`^  ${event}:\\s*$`).test(lines[i])) {
      eventIndex = i;
      break;
    }
  }
  if (eventIndex < 0) {
    throw new Error(`the workflow has no "on.${event}" block`);
  }
  let pathsIndex = -1;
  for (let i = eventIndex + 1; i < lines.length; i += 1) {
    if (isContent(lines[i]) && indentOf(lines[i]) <= 2) {
      break;
    }
    if (/^ {4}paths:\s*$/.test(lines[i])) {
      pathsIndex = i;
      break;
    }
  }
  if (pathsIndex < 0) {
    throw new Error(`"on.${event}" has no "paths:" filter`);
  }
  const entries: string[] = [];
  for (let i = pathsIndex + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (!isContent(line)) {
      continue;
    }
    if (indentOf(line) <= 4) {
      break;
    }
    const match = /^ {6}- (?:"([^"]*)"|'([^']*)'|(\S+))\s*(?:#.*)?$/.exec(line);
    if (match === null) {
      throw new Error(`cannot read the "on.${event}.paths" entry: ${line.trim()}`);
    }
    entries.push(match[1] ?? match[2] ?? match[3]);
  }
  if (entries.length === 0) {
    throw new Error(`"on.${event}.paths" is empty`);
  }
  return entries;
}

/** Whether a filter entry (`<dir>/**` or an exact path) runs the job for every file `pattern` names. */
export function filterCovers(filter: string, pattern: string): boolean {
  if (filter === pattern) {
    return true;
  }
  if (filter.endsWith('/**')) {
    const dir = filter.slice(0, -'/**'.length);
    const target = pattern.endsWith('/**') ? pattern.slice(0, -'/**'.length) : pattern;
    return target === dir || target.startsWith(`${dir}/`);
  }
  return false;
}

/** The REPO_INPUTS patterns no entry of `filters` covers. */
export function uncovered(inputs: readonly RepoInput[], filters: readonly string[]): string[] {
  return inputs
    .map((input) => input.pattern)
    .filter((pattern) => !filters.some((filter) => filterCovers(filter, pattern)));
}

/**
 * A `path.join(...)` or `path.resolve(...)` call that climbs out of the package:
 * two or more `'..'` levels, or any `'..'` from a base other than `__dirname`
 * (`PACKAGE_ROOT, '..'` is already outside). One level from `__dirname` is
 * test/ to the package root and stays inside. REPO_ROOT above is the one
 * legitimate escape, and this module is exempt from the scan.
 */
const ESCAPE = /path\.(?:join|resolve)\(([^()]*)\)/g;

/** The lines of `source` that climb out of the package without going through `repoPath`. */
export function packageEscapes(source: string): string[] {
  const out: string[] = [];
  for (const match of source.matchAll(ESCAPE)) {
    const ups = (match[1].match(/['"]\.\.['"]/g) ?? []).length;
    const slashedUps = (match[1].match(/\.\.\//g) ?? []).length;
    const fromDirname = /^\s*__dirname\s*,/.test(match[1]);
    if (ups + slashedUps >= 2 || (ups + slashedUps >= 1 && !fromDirname)) {
      out.push(match[0]);
    }
  }
  return out;
}
