#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Asserts every tracked production JS/TS file is either measured by a coverage
 * run or named as a committed exclusion that still needs excluding.
 *
 * WHY THIS EXISTS
 *
 * assert-coverage-scope.mjs pins each package's denominator so the measured
 * scope cannot shrink. That is the important half, and it is not the whole
 * story: a floor on the file count cannot distinguish "we measure 20 of 21
 * production files and the 21st has no harness" from "we measure 20 and lost
 * track of one". Both look identical from inside a single report, because jest
 * omits source no test imports from the report ENTIRELY rather than listing it
 * at 0%. An unmeasured file is invisible, not visibly bad, so nothing about the
 * report's own contents can reveal it.
 *
 * The census has to come from outside the report. This script gets it from
 * `git ls-files`, which knows about files no harness has ever loaded, and then
 * requires every production file to be accounted for: measured, or named in
 * .github/typescript-coverage-exclusions.json with a reason.
 *
 * WHY THE EXCLUSIONS ARE A COMMITTED FILE
 *
 * An exclusion asserted in a review comment is true once. An exclusion in the
 * repository is re-tested on every run, and its diff is reviewable. So the list
 * carries a `kind` per entry, and the kind selects a staleness test -- if
 * `zod_to_json_schema.mjs` is deleted or acquires a jest config, the entry that
 * excused it fails as stale rather than being carried silently forward.
 *
 * WHY SCOPES, RATHER THAN ONE WHOLE-REPO CHECK
 *
 * The workflow runs the packages as a parallel matrix, so no single job has both
 * packages' reports. A whole-repo check would need cross-job artifacts. Instead
 * each package job checks its own scope against its own report, and one extra
 * job checks `--scope outside`: the production files that no package scope
 * covers, which must all be exclusions.
 *
 * `--scope outside` also asserts that every directory holding a
 * `deploy/<pkg>/package.json` appears in the `--package` list it was given.
 * Without that, adding
 * `deploy/cdk-v3/` would land outside both package scopes AND outside the
 * `outside` census, and would be checked by nothing at all.
 *
 * NO VACUOUS PASSES
 *
 * The predecessor of the sibling script shipped a silent-pass path: a
 * non-numeric threshold became NaN, `n < NaN` is false, and the comparison was
 * skipped while the process still exited 0. This script has no thresholds, but
 * it has the same shape available to it in five other places, and each one is
 * closed deliberately rather than by accident:
 *
 *   - `git ls-files` returning nothing (not a repository, or a wrong cwd) would
 *     make every subsequent check iterate an empty census. Fails.
 *   - a package scope whose census is empty means the package is gone. Fails.
 *     (`--scope outside` may legitimately be empty, and is allowed to be.)
 *   - an unreadable or malformed exclusions file would otherwise read as "no
 *     exclusions are needed". Fails.
 *   - a coverage summary with zero measured files would satisfy nothing yet
 *     accuse everything; and summary keys that do not resolve to repository
 *     paths would accuse everything too. Both fail with the reason, rather than
 *     reporting a pile of false gaps or -- worse -- an empty set of real ones.
 *   - an exclusion whose `kind` is unrecognised is an entry no staleness test
 *     covers. Fails, rather than being skipped.
 *
 * USAGE
 *
 *   node assert-coverage-completeness.mjs \
 *     --exclusions .github/typescript-coverage-exclusions.json \
 *     --scope deploy/cdk \
 *     --summary deploy/cdk/coverage/coverage-summary.json
 *
 *   node assert-coverage-completeness.mjs \
 *     --exclusions .github/typescript-coverage-exclusions.json \
 *     --scope outside \
 *     --package deploy/cdk \
 *     --package deploy/cdk-constructs
 */

import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

/** Extensions the census covers. Kept in step with the exclusions file README. */
const SOURCE_GLOBS = ['*.ts', '*.tsx', '*.mts', '*.cts', '*.js', '*.mjs'];

/**
 * Files that are source by extension but are not production code: type
 * declarations carry no statements, and test sources are the measurer, not the
 * measured.
 */
const NOT_PRODUCTION = /\.d\.ts$|(^|\/)test\/|\.test\.|\.spec\./;

/**
 * Basenames that mean "a JS/TS harness is configured in this directory". Used
 * only to decide whether a `no-harness` exclusion has stopped being true, so it
 * errs toward catching a new harness rather than toward a narrow match.
 */
const HARNESS_CONFIG =
  /^(package\.json|tsconfig(\..+)?\.json|(jest|vitest)\.config\.([cm]?[jt]s|json))$/;

const KINDS = new Set(['harness-config', 'no-harness']);

function parseArgs(argv) {
  const opts = { exclusions: null, scope: null, summary: null, packages: [] };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      const value = argv[i + 1];
      // An option that lost its value must not silently consume the next
      // option, nor default to something permissive.
      if (value === undefined || value.startsWith('--')) {
        throw new Error(`${arg} needs a value, got ${JSON.stringify(value)}`);
      }
      i += 1;
      return value;
    };
    switch (arg) {
      case '--exclusions':
        opts.exclusions = next();
        break;
      case '--scope':
        opts.scope = next();
        break;
      case '--summary':
        opts.summary = next();
        break;
      case '--package':
        opts.packages.push(next());
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!opts.exclusions) throw new Error('--exclusions is required');
  if (!opts.scope) throw new Error('--scope is required');

  if (opts.scope === 'outside') {
    if (opts.summary) {
      throw new Error('--summary does not apply to --scope outside');
    }
    if (opts.packages.length === 0) {
      // Without the package list, "outside" would mean "the whole repository",
      // and every measured file would be reported as unaccounted for. The
      // failure would be loud rather than silent, but it would also be wrong.
      throw new Error('--scope outside needs at least one --package');
    }
  } else {
    if (!opts.summary) {
      throw new Error(`--scope ${opts.scope} needs --summary`);
    }
    if (opts.packages.length > 0) {
      throw new Error('--package only applies to --scope outside');
    }
  }

  return opts;
}

function git(repoRoot, args) {
  return execFileSync('git', ['-C', repoRoot, ...args], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
}

/** Splits NUL-delimited `git ls-files -z` output, dropping the trailing empty. */
function splitZ(out) {
  return out.split('\0').filter((entry) => entry !== '');
}

function normalizeScope(scope) {
  // Tolerate a trailing slash so `--scope deploy/cdk/` and `--scope deploy/cdk`
  // behave the same rather than one of them matching nothing.
  return scope.replace(/\/+$/, '');
}

/**
 * Resolves a jest json-summary key to a repository-relative POSIX path.
 *
 * jest writes absolute paths, so the prefix differs between a CI runner and a
 * local worktree. Stripping the git toplevel handles both. The `deploy/`-anchored
 * fallback covers a summary produced under a different absolute prefix (a
 * container bind mount, say) without loosening the match to a substring test --
 * an exact-suffix requirement is what makes "measured" mean this file and not a
 * same-named file elsewhere.
 */
function toRepoRelative(key, repoRoot) {
  const posixKey = key.split(path.sep).join('/');
  const posixRoot = repoRoot.split(path.sep).join('/').replace(/\/+$/, '');

  if (posixKey.startsWith(`${posixRoot}/`)) {
    return posixKey.slice(posixRoot.length + 1);
  }
  const anchor = posixKey.lastIndexOf('/deploy/');
  if (anchor !== -1) {
    return posixKey.slice(anchor + 1);
  }
  if (!posixKey.startsWith('/')) {
    return posixKey;
  }
  return null;
}

function loadExclusions(file) {
  let raw;
  try {
    raw = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    // "The list is missing" and "the list is empty" must not look the same: an
    // unreadable file would otherwise excuse nothing and pass everything that
    // happens to be measured.
    throw new Error(`cannot read ${file}: ${err.message}`);
  }

  if (!Array.isArray(raw.exclusions)) {
    throw new Error(`${file} has no "exclusions" array`);
  }

  const seen = new Set();
  return raw.exclusions.map((entry, index) => {
    const where = `${file} exclusions[${index}]`;
    if (typeof entry?.path !== 'string' || entry.path === '') {
      throw new Error(`${where} needs a non-empty "path"`);
    }
    if (typeof entry.reason !== 'string' || entry.reason.trim() === '') {
      // The reason is the whole point of the list being auditable. An entry
      // without one is an unexplained exclusion.
      throw new Error(`${where} (${entry.path}) needs a non-empty "reason"`);
    }
    if (!KINDS.has(entry.kind)) {
      // An unrecognised kind is an entry that no staleness test below would
      // examine. Refuse it rather than carrying an unchecked exclusion.
      throw new Error(
        `${where} (${entry.path}) has kind ${JSON.stringify(entry.kind)}; ` +
          `expected one of ${[...KINDS].join(', ')}`,
      );
    }
    if (entry.path.startsWith('/') || entry.path.split('/').includes('..')) {
      throw new Error(`${where} path must be repository-relative: ${entry.path}`);
    }
    if (seen.has(entry.path)) {
      throw new Error(`${where} duplicates an earlier entry: ${entry.path}`);
    }
    seen.add(entry.path);
    return entry;
  });
}

function readSummary(file, repoRoot, problems) {
  let summary;
  try {
    summary = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    problems.push(
      `cannot read ${file}: ${err.message}. The suite either did not run or ` +
        'did not emit a json-summary report, and "no report" must not read ' +
        'like "everything is accounted for".',
    );
    return null;
  }

  const keys = Object.keys(summary).filter((key) => key !== 'total');
  if (keys.length === 0) {
    problems.push(`${file} measured no files at all -- it is not a usable report`);
    return null;
  }

  const measured = new Set();
  const unresolved = [];
  for (const key of keys) {
    const rel = toRepoRelative(key, repoRoot);
    if (rel === null) {
      unresolved.push(key);
    } else {
      measured.add(rel);
    }
  }

  if (unresolved.length > 0) {
    // Every measured path failing to resolve would make the census report each
    // file as unmeasured -- a wall of false gaps that hides whether there is a
    // real one. Say so instead.
    problems.push(
      `${unresolved.length} of ${keys.length} paths in ${file} do not resolve ` +
        `under the repository root ${repoRoot} (e.g. ${unresolved[0]}). ` +
        'The report was produced against a different tree than the census.',
    );
    return null;
  }

  return measured;
}

function main(argv) {
  const opts = parseArgs(argv);
  const repoRoot = git(process.cwd(), ['rev-parse', '--show-toplevel']).trim();
  const scope = normalizeScope(opts.scope);
  const problems = [];

  const allTracked = splitZ(git(repoRoot, ['ls-files', '-z']));
  if (allTracked.length === 0) {
    // Nothing tracked means the census is empty, and an empty census satisfies
    // every check below without examining anything.
    throw new Error(`git ls-files found no tracked files under ${repoRoot}`);
  }

  const sourceFiles = splitZ(
    git(repoRoot, ['ls-files', '-z', '--', ...SOURCE_GLOBS]),
  );
  const production = sourceFiles.filter((file) => !NOT_PRODUCTION.test(file));
  const productionSet = new Set(production);
  const trackedSet = new Set(allTracked);

  const exclusions = loadExclusions(path.resolve(repoRoot, opts.exclusions));
  const excludedPaths = new Set(exclusions.map((entry) => entry.path));

  // Directories holding a JS/TS harness config, for the `no-harness` staleness
  // test. Derived from the tracked file list so an untracked stray config in a
  // working tree cannot change the verdict.
  const harnessDirs = new Set();
  for (const file of allTracked) {
    if (HARNESS_CONFIG.test(path.posix.basename(file))) {
      harnessDirs.add(path.posix.dirname(file));
    }
  }

  let census;
  let measured = null;
  // `outside` expects no report, so its membership pass is meaningful with
  // `measured` left null: a file outside every package scope is measured by
  // nobody by definition, and only an exclusion can account for it. A package
  // scope is different -- without a usable report the membership pass cannot
  // distinguish an unmeasured file from an unreadable one, so it is skipped and
  // the report problem stands alone. Skipping cannot pass vacuously: the report
  // problem is already recorded, so the exit code is 1 either way.
  let canAssessMembership = scope === 'outside';

  if (scope === 'outside') {
    const packages = opts.packages.map(normalizeScope);

    // A new package under deploy/ must be added to a matrix entry. If it were
    // only added to the tree, it would fall outside every package scope and
    // outside this census too, so nothing would check it.
    for (const file of allTracked) {
      if (path.posix.basename(file) !== 'package.json') continue;
      const dir = path.posix.dirname(file);
      if (path.posix.dirname(dir) !== 'deploy') continue;
      if (!packages.includes(dir)) {
        problems.push(
          `${dir} contains a package.json but is not one of the --package ` +
            'scopes, so no job measures it. Add a matrix entry for it.',
        );
      }
    }

    census = production.filter(
      (file) => !packages.some((pkg) => file.startsWith(`${pkg}/`)),
    );
  } else {
    census = production.filter((file) => file.startsWith(`${scope}/`));
    if (census.length === 0) {
      // The package's sources are gone. Reporting "0 of 0 accounted for" would
      // be a pass.
      throw new Error(
        `no tracked production source under ${scope}/ -- ` +
          'the package is missing, and this check must not pass by finding nothing',
      );
    }
    measured = readSummary(path.resolve(repoRoot, opts.summary), repoRoot, problems);
    canAssessMembership = measured !== null;
  }

  // 1. Completeness: every production file in scope is measured or excluded.
  if (canAssessMembership) {
    for (const file of census) {
      if (measured?.has(file)) continue;
      if (excludedPaths.has(file)) continue;
      problems.push(
        `${file} is measured by no coverage report and is named in no exclusion. ` +
          'jest omits unimported source from a report entirely rather than at 0%, ' +
          'so this file is unmeasured rather than uncovered. Either give it a test ' +
          'that imports it, or add it to the exclusions file with a reason.',
      );
    }
  }

  // 2. Staleness: every exclusion still needs excluding. Checked for ALL
  //    entries on every run, not just the ones in scope, so no entry depends on
  //    a particular job having run to be examined.
  for (const entry of exclusions) {
    const { path: file, kind } = entry;

    if (!trackedSet.has(file)) {
      problems.push(
        `exclusion ${file} names a file that is not tracked (deleted or renamed). ` +
          'Remove the entry.',
      );
      continue;
    }

    if (!productionSet.has(file)) {
      problems.push(
        `exclusion ${file} names a file the census never asks about -- it is not ` +
          'tracked production source. The entry guards nothing; remove it.',
      );
      continue;
    }

    if (measured?.has(file)) {
      problems.push(
        `exclusion ${file} (${kind}) is now measured by ` +
          `${opts.summary}. The reason it was excluded no longer holds; remove the entry.`,
      );
      continue;
    }

    if (kind === 'no-harness') {
      const owners = [];
      for (let dir = path.posix.dirname(file); dir !== '.' && dir !== '/'; dir = path.posix.dirname(dir)) {
        if (harnessDirs.has(dir)) owners.push(dir);
      }
      if (owners.length > 0) {
        problems.push(
          `exclusion ${file} is marked no-harness, but a JS/TS harness config now ` +
            `exists in ${owners.join(', ')}. It can be measured; either measure it ` +
            'or change the entry to say why it still cannot be.',
        );
      }
    }
  }

  if (problems.length > 0) {
    process.stderr.write('Coverage completeness check failed:\n');
    for (const problem of problems) {
      process.stderr.write(`  - ${problem}\n`);
    }
    return 1;
  }

  const excludedInScope = census.filter((file) => excludedPaths.has(file));
  process.stdout.write(
    `coverage completeness OK (${scope}): ${census.length} tracked production ` +
      `file(s) in scope, ${census.length - excludedInScope.length} measured, ` +
      `${excludedInScope.length} excluded by name, ` +
      `${exclusions.length} exclusion(s) re-checked and still needed\n`,
  );
  return 0;
}

try {
  process.exitCode = main(process.argv);
} catch (err) {
  process.stderr.write(`coverage completeness: ${err.message}\n`);
  process.exitCode = 2;
}
