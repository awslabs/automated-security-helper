// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The pixel snapshots the visual suite takes, read from scenarios.json beside this
 * file.
 *
 * JSON rather than a TypeScript literal so the orphan check in
 * .github/scripts/check-editor-snapshot-trailers.py, which runs without node, reads
 * the same list the suite does: a baseline under test/visual/__snapshots__/ that no
 * scenario names fails there, and the suite itself fails at the end of a run when a
 * baseline was not compared.
 */

import * as fs from 'fs';
import * as path from 'path';

export interface VisualScenario {
  /** Baseline file name, without `.png`. */
  readonly name: string;
  /** What the picture shows, for the failure message. */
  readonly shows: string;
}

/**
 * scenarios.json is not compiled, so from out-integration/test/visual/ it is read
 * from the source tree, three levels up and back down.
 */
function scenariosFile(): string {
  const beside = path.join(__dirname, 'scenarios.json');
  return fs.existsSync(beside)
    ? beside
    : path.resolve(__dirname, '..', '..', '..', 'test', 'visual', 'scenarios.json');
}

export const VISUAL_SCENARIOS: readonly VisualScenario[] = (
  JSON.parse(fs.readFileSync(scenariosFile(), 'utf8')) as { scenarios: VisualScenario[] }
).scenarios;
