#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Asserts a jest run actually executed tests.
 *
 * WHY THIS EXISTS
 *
 * A jest run that collected nothing exits 0 and prints "Tests: 0 total". Read in a
 * CI log that is a green check, and this repository has already shipped one: a
 * suite reporting no tests was taken as passing.
 *
 * The two gates next door do not catch it. A coverage threshold cannot: with no
 * test importing anything, no file is instrumented, the report has no statements,
 * and there is no percentage to fall below. assert-coverage-scope.mjs comes closer
 * -- a missing summary fails it -- but jest writes a summary for a zero-test run,
 * and the file-count and statement floors are about the DENOMINATOR, which
 * `collectCoverageFrom` populates whether or not a single test ran.
 *
 * So the count has to be read from outside the coverage report, the same way
 * assert-coverage-completeness.mjs takes its census from `git ls-files` rather than
 * from the report it is checking.
 *
 * WHY IT READS --json OUTPUT AND NOT THE LOG
 *
 * jest's own summary line is coloured. `grep -c '^Tests:'` over raw jest output
 * matches nothing, because the anchor lands before an ANSI escape rather than
 * before the T -- the same class of error that made `grep -c FAILED` read 36 on a
 * fully green pytest log in this repository. So the workflow passes
 * `--json --outputFile`, which writes a machine-readable result alongside the
 * unchanged human-readable log, and this script reads `numTotalTests` from that.
 *
 * NO VACUOUS PASSES
 *
 * Every way this script could report success without having checked anything is
 * closed on purpose, because a gate against silent passes must not have one:
 *
 *   - an unreadable or missing results file fails. "jest never wrote a result" is
 *     the loudest possible form of the thing being checked for.
 *   - a results file with no `numTotalTests` key fails, rather than treating
 *     `undefined >= 1` as false and then only reporting a count mismatch.
 *   - a non-numeric --min-tests fails. `Number('--min-tests')` is NaN and
 *     `0 < NaN` is false, so a flag that lost its value would skip the comparison
 *     and still exit 0. That is exactly the bug assert-coverage-scope.mjs's
 *     requireNumber closes, and it is closed here the same way.
 *   - a run jest itself reported as failed fails here too, even when the count is
 *     high enough. This script runs after the test step, so a red suite has
 *     already stopped the job -- but if it were ever reordered, "tests ran" must
 *     not be mistaken for "tests passed".
 *
 * USAGE
 *
 *   node assert-jest-ran.mjs --results "$RUNNER_TEMP/jest-cdk.json" --min-tests 1
 */

import { readFileSync } from 'node:fs';

function requireNumber(flag, raw) {
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    throw new Error(`${flag} needs a number, got ${JSON.stringify(raw)}`);
  }
  return value;
}

function parseArgs(argv) {
  const opts = { results: null, minTests: 1 };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) {
        throw new Error(`${arg} needs a value, got ${JSON.stringify(value)}`);
      }
      i += 1;
      return value;
    };
    switch (arg) {
      case '--results':
        opts.results = next();
        break;
      case '--min-tests':
        opts.minTests = requireNumber(arg, next());
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!opts.results) throw new Error('--results is required');
  if (opts.minTests < 1) {
    // A floor of 0 is satisfied by a run that did nothing, which is the whole
    // point of this script. Refuse the argument rather than the run.
    throw new Error(`--min-tests must be at least 1, got ${opts.minTests}`);
  }
  return opts;
}

function main(argv) {
  const opts = parseArgs(argv);

  let results;
  try {
    results = JSON.parse(readFileSync(opts.results, 'utf8'));
  } catch (err) {
    process.stderr.write(
      `jest ran: cannot read ${opts.results}: ${err.message}\n` +
        'jest either did not run or did not write --outputFile, and "no result" must ' +
        'not read like "a passing result".\n',
    );
    return 1;
  }

  const problems = [];
  const total = results.numTotalTests;
  const failed = results.numFailedTests;

  if (typeof total !== 'number') {
    problems.push(
      `${opts.results} has no numeric numTotalTests -- it is not a jest --json result`,
    );
  } else if (total < opts.minTests) {
    problems.push(
      `jest reported ${total} test(s), expected at least ${opts.minTests}. ` +
        'A run that collected no tests exits 0 and prints "Tests: 0 total", which ' +
        'reads as a pass. Check testMatch, roots and the test file names.',
    );
  }

  if (typeof failed === 'number' && failed > 0) {
    problems.push(`jest reported ${failed} failing test(s)`);
  }

  if (results.success === false) {
    problems.push(`${opts.results} reports success: false`);
  }

  if (problems.length > 0) {
    process.stderr.write('Jest run check failed:\n');
    for (const problem of problems) {
      process.stderr.write(`  - ${problem}\n`);
    }
    return 1;
  }

  process.stdout.write(
    `jest ran OK: ${total} test(s) executed, ${results.numPassedTests ?? total} passed, ` +
      `${results.numTotalTestSuites ?? '?'} suite(s)\n`,
  );
  return 0;
}

try {
  process.exitCode = main(process.argv);
} catch (err) {
  process.stderr.write(`jest ran: ${err.message}\n`);
  process.exitCode = 2;
}
