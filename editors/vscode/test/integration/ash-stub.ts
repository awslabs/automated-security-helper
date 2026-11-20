// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * A stand-in for the ASH CLI that replays a captured scan.
 *
 * run.ts puts a two-line shell wrapper named `ashx` or `ash` on the extension
 * host's PATH that runs this file with node. The extension cannot tell it from
 * ASH by any means it uses: it answers `--version` with the string a real ASH
 * prints, and `scan --source-dir S --output-dir O` writes the SARIF and
 * aggregated results of one directory under test/fixtures/scans/ into O and exits
 * with the status that real run exited with. Those directories are real
 * `ash scan` output with the two paths replaced by placeholders, so what the
 * extension reads is what ASH wrote, not what this file's author expected.
 *
 * The scenario is a JSON file named by ASH_STUB_SCENARIO_FILE, rewritten by the
 * suite before each scan:
 *
 *   { "fixture": "findings" }            replay scans/findings
 *   { "fixture": null, "exitCode": 1 }   write nothing and exit 1
 *   { "fixture": "findings", "hangSeconds": 60 }   hang first, for the timeout
 *
 * Invoked through the wrapper named `crashing-ash` (ASH_STUB_INVOKED_AS=crash), a
 * scan writes nothing and exits 1 whatever the scenario says: the crash half of
 * ASH's exit 1. The suite reaches it by configuring that wrapper's path, so the
 * case runs in real mode too.
 *
 * Every invocation is appended to ASH_STUB_SCENARIO_FILE + ".calls" so a test can
 * see which wrapper ran and with what arguments.
 */

import * as fs from 'fs';
import * as path from 'path';

interface Scenario {
  readonly fixture: string | null;
  readonly exitCode?: number;
  /** Hang this long before doing anything, so a timeout can fire. */
  readonly hangSeconds?: number;
}

const VERSION = 'awslabs/automated-security-helper v3.7.0';

function argument(args: readonly string[], flag: string): string {
  const index = args.indexOf(flag);
  if (index < 0 || index + 1 >= args.length) {
    throw new Error(`ash-stub: ${flag} is required`);
  }
  return args[index + 1];
}

/** JSON-escapes a path for substitution inside a JSON string literal. */
function asJsonText(value: string): string {
  return JSON.stringify(value).slice(1, -1);
}

function main(): number | 'hang' {
  const args = process.argv.slice(2);
  const scenarioFile = process.env.ASH_STUB_SCENARIO_FILE;
  const fixtures = process.env.ASH_STUB_FIXTURES;
  if (scenarioFile === undefined || fixtures === undefined) {
    process.stderr.write('ash-stub: ASH_STUB_SCENARIO_FILE and ASH_STUB_FIXTURES must be set\n');
    return 70;
  }
  fs.appendFileSync(
    `${scenarioFile}.calls`,
    `${JSON.stringify({ invokedAs: process.env.ASH_STUB_INVOKED_AS, args })}\n`,
  );

  if (args[0] === '--version') {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (args[0] !== 'scan') {
    process.stderr.write(`ash-stub: unsupported command ${JSON.stringify(args)}\n`);
    return 64;
  }

  const scenario: Scenario =
    process.env.ASH_STUB_INVOKED_AS === 'crash'
      ? { fixture: null, exitCode: 1 }
      : (JSON.parse(fs.readFileSync(scenarioFile, 'utf8')) as Scenario);
  const sourceDir = argument(args, '--source-dir');
  const outputDir = argument(args, '--output-dir');
  if (scenario.hangSeconds !== undefined) {
    // Keeps the event loop alive; the extension's timeout must stop this.
    setTimeout(() => undefined, scenario.hangSeconds * 1000);
    return 'hang';
  }
  if (scenario.fixture === null) {
    process.stderr.write('ash-stub: simulated crash before any report was written\n');
    return scenario.exitCode ?? 1;
  }

  const captured = path.join(fixtures, 'scans', scenario.fixture);
  const restore = (text: string): string =>
    text
      .split('__ASH_SOURCE_DIR__')
      .join(asJsonText(sourceDir))
      .split('__ASH_OUTPUT_DIR__')
      .join(asJsonText(outputDir));
  fs.mkdirSync(path.join(outputDir, 'reports'), { recursive: true });
  fs.writeFileSync(
    path.join(outputDir, 'reports', 'ash.sarif'),
    restore(fs.readFileSync(path.join(captured, 'ash.sarif'), 'utf8')),
  );
  fs.writeFileSync(
    path.join(outputDir, 'ash_aggregated_results.json'),
    restore(fs.readFileSync(path.join(captured, 'ash_aggregated_results.json'), 'utf8')),
  );
  const recorded = Number(fs.readFileSync(path.join(captured, 'exit-code'), 'utf8').trim());
  return scenario.exitCode ?? recorded;
}

const outcome = main();
if (outcome !== 'hang') {
  process.exitCode = outcome;
}
