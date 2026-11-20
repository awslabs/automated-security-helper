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
 * Two workflows run these suites: ash-typescript-ci.yml ("ts (vscode)") runs
 * jest with coverage, and ash-vscode-extension.yml's editor-snapshots job runs
 * `npm run snapshots -- structural`, which runs the whole jest suite
 * (test/snapshots.ts). Both are in GUARDED_WORKFLOWS. ash-vscode-extension.yml has
 * no paths filter (its jobs are required checks, so it runs on every push), and an
 * event with no filter covers every input; ash-typescript-ci.yml still filters.
 *
 * So every such read goes through `repoPath`, which refuses a path that is not
 * declared in REPO_INPUTS, and test/repo-inputs.test.ts checks that every entry is
 * covered by the push and pull_request triggers of every guarded workflow (by a
 * filter entry, by having no filter, or by an exemption from one, with the reason,
 * that still holds), and that no suite climbs out of the package except through
 * this module. The second check is a heuristic; see `packageEscapes`.
 */

import * as path from 'path';

/** The workflows that run this package's jest suites, and so must run when an input changes. */
export const TYPESCRIPT_CI = '.github/workflows/ash-typescript-ci.yml';
export const VSCODE_EXTENSION = '.github/workflows/ash-vscode-extension.yml';
export const GUARDED_WORKFLOWS: readonly string[] = [TYPESCRIPT_CI, VSCODE_EXTENSION];

/** A repo-relative path or `<dir>/**` pattern, and why a suite reads it. */
export interface RepoInput {
  readonly pattern: string;
  readonly readBy: string;
  /**
   * Guarded workflows that deliberately do not filter on this input, each with the
   * reason. The test fails if a workflow listed here starts covering the input,
   * so an exemption cannot outlive its reason unnoticed.
   */
  readonly exemptFrom?: Readonly<Record<string, string>>;
}

export const REPO_INPUTS: readonly RepoInput[] = [
  {
    pattern: 'tests/test_data/outputs/ash_aggregated_results.json',
    readBy: 'real-report.test.ts parses it as the real multi-scanner report',
  },
  {
    pattern: VSCODE_EXTENSION,
    readBy: 'snapshot-policy.test.ts checks its VS Code version pin; repo-inputs.test.ts reads its filters',
  },
  {
    pattern: TYPESCRIPT_CI,
    readBy: 'repo-inputs.test.ts reads its filters',
  },
  {
    pattern: '.github/scripts/check-snapshot-trailers.py',
    readBy: 'snapshot-policy.test.ts reads it to confirm the update-flag forms it mirrors',
  },
  {
    pattern: '.github/scripts/assert-artifact-contents.py',
    readBy: "vsix-contents.test.ts holds src/vsix-contents.ts's payload tables to this file's",
  },
  {
    pattern: '.github/**',
    readBy: 'snapshot-policy.test.ts scans every file under .github/ for a snapshot update flag',
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
 *
 * `relative` uses forward slashes and must already be normal: a `..`, `.` or
 * empty segment, a backslash or a leading `/` is refused rather than normalized,
 * because `.github/../tests/x` would otherwise match the `.github/**` entry and
 * name an undeclared file.
 */
export function repoPath(relative: string, inputs: readonly RepoInput[] = REPO_INPUTS): string {
  const abnormal = relative.split('/').some((seg) => seg === '' || seg === '.' || seg === '..');
  if (abnormal || relative.includes('\\')) {
    throw new Error(`${relative} is not a normal repo-relative path; write it without "..", "." or empty segments`);
  }
  if (!inputs.some((input) => patternMatches(input.pattern, relative))) {
    throw new Error(
      `${relative} is outside editors/vscode and not declared in test/repo-inputs.ts REPO_INPUTS. ` +
        'Declare it there and add it to the push and pull_request paths of every workflow in ' +
        'GUARDED_WORKFLOWS that has a paths filter, so a change to it runs this suite.',
    );
  }
  return path.join(REPO_ROOT, ...relative.split('/'));
}

/**
 * The `paths:` entries under `on.<event>` of a workflow, read line by line, or
 * `null` when the event has no paths filter and so runs on every change.
 *
 * Not a YAML parser, and it does not need to be one: it reads one fixed shape
 * (`  <event>:` then `    paths:` then `      - "<entry>"`). Because `null`
 * credits every input, anything that could be a filter in another shape THROWS
 * rather than reading as `null`: a `paths` or `paths-ignore` key at another
 * indent or quoted, a `paths-ignore` list (it withdraws files this check would
 * credit), an empty or unreadable `paths:` block, and a missing `on:` or event.
 * A negated (`!`) entry also throws: it can withdraw what an earlier entry
 * covers, and crediting the earlier entry would pass a filter GitHub would not
 * run on.
 */
export function workflowPaths(workflow: string, event: string): string[] | null {
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
      if (pathsIndex >= 0) {
        throw new Error(`"on.${event}" has two "paths:" keys`);
      }
      pathsIndex = i;
      continue;
    }
    if (/^\s+["']?paths-ignore["']?\s*:/.test(lines[i])) {
      throw new Error(`"on.${event}" has a paths-ignore list, which this check does not model`);
    }
    if (/^\s+["']?paths["']?\s*:/.test(lines[i])) {
      throw new Error(`cannot read the "on.${event}" paths filter: ${lines[i].trim()}`);
    }
  }
  if (pathsIndex < 0) {
    return null;
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
    const entry = match[1] ?? match[2] ?? match[3];
    if (entry.startsWith('!')) {
      // A negated entry subtracts from the entries before it, so a positive entry
      // that appears to cover an input may not. Refused rather than modelled.
      throw new Error(`"on.${event}.paths" has a negated entry, which this check does not model: ${entry}`);
    }
    entries.push(entry);
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

/** Whether some entry of `filters` covers `pattern`; `null` (no filter) covers everything. */
export function isCovered(filters: readonly string[] | null, pattern: string): boolean {
  return filters === null || filters.some((filter) => filterCovers(filter, pattern));
}

/** The REPO_INPUTS patterns that `workflow` must cover and `filters` does not. */
export function uncovered(
  inputs: readonly RepoInput[],
  filters: readonly string[] | null,
  workflow?: string,
): string[] {
  return inputs
    .filter((input) => workflow === undefined || input.exemptFrom?.[workflow] === undefined)
    .map((input) => input.pattern)
    .filter((pattern) => !isCovered(filters, pattern));
}

/** A call's arguments: the code with comments removed, and each string literal's contents. */
interface CallArguments {
  readonly code: string;
  readonly strings: readonly string[];
}

/**
 * The arguments of a call whose `(` is at `open`, with nested parentheses
 * balanced. String literals and `//` and block comments are skipped while
 * balancing, so a `)` in either does not end the call. Undefined when unbalanced.
 */
function callArguments(source: string, open: number): CallArguments | undefined {
  let depth = 0;
  let code = '';
  const strings: string[] = [];
  for (let i = open; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === "'" || ch === '"' || ch === '`') {
      let text = '';
      let j = i + 1;
      for (; j < source.length && source[j] !== ch; j += 1) {
        if (source[j] === '\\') {
          text += source.slice(j, j + 2);
          j += 1;
        } else {
          text += source[j];
        }
      }
      strings.push(text);
      code += source.slice(i, j + 1);
      i = j;
      continue;
    }
    if (ch === '/' && source[i + 1] === '/') {
      const newline = source.indexOf('\n', i);
      i = newline < 0 ? source.length : newline - 1;
      code += ' ';
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      const close = source.indexOf('*/', i + 2);
      i = close < 0 ? source.length : close + 1;
      code += ' ';
      continue;
    }
    if (ch === '(') {
      depth += 1;
    } else if (ch === ')') {
      depth -= 1;
      if (depth === 0) {
        return { code: code.slice(1), strings };
      }
    }
    code += ch;
  }
  return undefined;
}

/** How many `..` path segments a string literal's contents carry, split on `/` and `\\`. */
function parentSegments(text: string): number {
  return text.split(/\\\\|[\\/]/).filter((segment) => segment === '..').length;
}

const PATH_CALL = /path\.(?:join|resolve)\(/g;
const TEMPLATE_ESCAPE = /`[^`]*\$\{\s*(?:__dirname|PACKAGE_ROOT|REPO_ROOT)\s*\}[^`]*\.\.[^`]*`/g;
const DIRNAME_CHAIN = /path\.dirname\(\s*path\.dirname\(/g;

/**
 * Places in `source` that climb out of the package without going through `repoPath`.
 *
 * A HEURISTIC, NOT A GUARANTEE. It catches the shapes a test here would plausibly
 * write:
 *
 *   - a `path.join(...)`/`path.resolve(...)` whose string arguments (nested
 *     calls included, comments ignored) carry two or more `..` path segments in
 *     total (`'../..'` is two), or any `..` from a base other
 *     than `__dirname` (`PACKAGE_ROOT, '..'` is already outside; one level from
 *     `__dirname` is test/ to the package root and stays inside);
 *   - a template literal that puts `..` after `${__dirname}`, `${PACKAGE_ROOT}` or
 *     `${REPO_ROOT}`;
 *   - `path.dirname(path.dirname(...))`.
 *
 * It does not see a path built in a variable over several statements, a
 * cwd-relative read (`readFileSync('../../x')`), or `fs` called with a URL. Those
 * need review; the runtime `repoPath` check only catches reads that use it.
 */
export function packageEscapes(source: string): string[] {
  const out: string[] = [];
  for (const match of source.matchAll(PATH_CALL)) {
    const open = (match.index ?? 0) + match[0].length - 1;
    const args = callArguments(source, open);
    if (args === undefined) {
      continue;
    }
    const ups = args.strings.reduce((total, text) => total + parentSegments(text), 0);
    const fromDirname = /^\s*__dirname\s*,/.test(args.code);
    if (ups >= 2 || (ups >= 1 && !fromDirname)) {
      out.push(`${match[0]}${args.code})`);
    }
  }
  for (const pattern of [TEMPLATE_ESCAPE, DIRNAME_CHAIN]) {
    for (const match of source.matchAll(pattern)) {
      out.push(match[0]);
    }
  }
  return out;
}
