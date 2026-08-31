#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Asserts a jest coverage run measured the scope it was supposed to measure.
 *
 * WHY THIS EXISTS
 *
 * A coverage threshold on its own is gameable, and not hypothetically. Both of
 * this repository's jest configs set `roots: ['<rootDir>/test']`, which confines
 * jest's crawler to the test directory. A source file that no test imports is
 * then never enumerated, so it does not appear at 0% -- it does not appear at
 * all, and the percentage is computed over a denominator that silently excludes
 * it. `deploy/cdk-constructs` reported 97.35% that way while a 0%-covered file
 * sat in `src/`; the honest figure was 82.51%. Nothing errored.
 *
 * So a threshold alone can be satisfied by shrinking what is measured rather
 * than by testing more, and the shrink looks like a config tidy-up in review.
 * This script pins the denominator: it fails when the report covers fewer files
 * or fewer statements than expected, and when a file that must be measured is
 * missing from the report entirely.
 *
 * The same shape has bitten this repository in Python too: `automated_security_
 * helper/tools/` has no `__init__.py`, so coverage.py's `source=` scan never
 * descends into it and `install_dependencies.py` was absent from every report
 * rather than reported uncovered.
 *
 * USAGE
 *
 *   node assert-coverage-scope.mjs \
 *     --summary deploy/cdk/coverage/coverage-summary.json \
 *     --min-files 12 \
 *     --min-statements 380 \
 *     --require lib/ash-config.ts \
 *     --require bin/ash.ts
 *
 * `--min-*` are floors, not equalities: adding a source file legitimately raises
 * both, and a floor does not have to be edited every time that happens. Removing
 * one lowers them and fails, which is the case worth catching.
 */

import { readFileSync } from 'node:fs';

/**
 * Rejects a non-numeric threshold instead of letting it become NaN.
 *
 * `Number('--min-statements')` is NaN, and `11 < NaN` is false, so an argument
 * that lost its value -- an unset CI matrix key, a hyphenated expression that
 * evaluated to empty -- would make the comparison vacuously true and skip the
 * check while still exiting 0. That is the failure this whole script exists to
 * prevent, so it must not be reachable from inside it.
 */
function requireNumber(flag, raw) {
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    throw new Error(`${flag} needs a number, got ${JSON.stringify(raw)}`);
  }
  return value;
}

function parseArgs(argv) {
  const opts = { summary: null, minFiles: null, minStatements: null, require: [] };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      const value = argv[i + 1];
      if (value === undefined) {
        throw new Error(`${arg} needs a value`);
      }
      i += 1;
      return value;
    };
    switch (arg) {
      case '--summary':
        opts.summary = next();
        break;
      case '--min-files':
        opts.minFiles = requireNumber(arg, next());
        break;
      case '--min-statements':
        opts.minStatements = requireNumber(arg, next());
        break;
      case '--require':
        opts.require.push(next());
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!opts.summary) throw new Error('--summary is required');
  return opts;
}

function main(argv) {
  const opts = parseArgs(argv);

  let summary;
  try {
    summary = JSON.parse(readFileSync(opts.summary, 'utf8'));
  } catch (err) {
    // A missing summary is the most likely way this gate goes quiet: if jest
    // never ran, or ran without --coverageReporters=json-summary, there is no
    // file to read. Treat that as a failure rather than skipping the checks,
    // because "no report" and "a clean report" must not look the same.
    process.stderr.write(
      `coverage scope: cannot read ${opts.summary}: ${err.message}\n` +
        'The suite either did not run or did not emit a json-summary report.\n',
    );
    return 1;
  }

  const files = Object.keys(summary).filter((key) => key !== 'total');
  const totals = summary.total?.statements;
  const problems = [];

  if (!totals || typeof totals.total !== 'number') {
    problems.push('report has no total.statements -- it is not a jest json-summary');
  }

  if (opts.minFiles !== null && files.length < opts.minFiles) {
    problems.push(
      `measured ${files.length} files, expected at least ${opts.minFiles}. ` +
        'A file that no test imports is omitted from the report entirely rather ' +
        'than counted at 0%, so a narrowed `roots` or `collectCoverageFrom` ' +
        'raises the percentage by shrinking the denominator.',
    );
  }

  if (opts.minStatements !== null && totals && totals.total < opts.minStatements) {
    problems.push(
      `denominator is ${totals.total} statements, expected at least ` +
        `${opts.minStatements}. Coverage went up because less was measured.`,
    );
  }

  for (const needle of opts.require) {
    if (!files.some((file) => file.includes(needle))) {
      problems.push(`${needle} is absent from the coverage report entirely`);
    }
  }

  if (problems.length > 0) {
    process.stderr.write('Coverage scope check failed:\n');
    for (const problem of problems) {
      process.stderr.write(`  - ${problem}\n`);
    }
    return 1;
  }

  process.stdout.write(
    `coverage scope OK: ${files.length} files, ` +
      `${totals.total} statements in the denominator, ` +
      `${opts.require.length} required file(s) present\n`,
  );
  return 0;
}

try {
  process.exitCode = main(process.argv);
} catch (err) {
  process.stderr.write(`coverage scope: ${err.message}\n`);
  process.exitCode = 2;
}
