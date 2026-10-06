// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The one rule both snapshot suites share: snapshots are rewritten only when a
 * person asks for it with `--snapshot-update`, and never under CI.
 *
 * The flag name and the refusal are the ones core ASH's snapshot suite uses
 * (tests/snapshot/conftest.py refuses pytest's `--snapshot-update` when CI or
 * GITHUB_ACTIONS is "true"), so one habit and one policy check cover every snapshot
 * in the repository. jest's own update flag is `--updateSnapshot`; only
 * test/snapshots.ts passes it, after this check.
 *
 * Pure, with no VS Code or jest import, so test/snapshot-policy.test.ts can call it
 * under jest and test/visual/run.ts can call it inside the container.
 */

/** The flag a person passes to rewrite snapshots. */
export const UPDATE_FLAG = '--snapshot-update';

/** Set by test/snapshots.ts for the visual run inside the container. */
export const UPDATE_ENV = 'ASH_SNAPSHOT_UPDATE';

/** True when the environment is a CI run, by the two variables CI providers set. */
export function underCi(env: NodeJS.ProcessEnv): boolean {
  return env.CI === 'true' || env.GITHUB_ACTIONS === 'true';
}

/** Throws when an update is asked for under CI; otherwise returns whether one was. */
export function updateAllowed(asked: boolean, env: NodeJS.ProcessEnv): boolean {
  if (asked && underCi(env)) {
    throw new Error(
      `${UPDATE_FLAG} is refused under CI. Update snapshots locally, review the diff, ` +
        "and commit it with a 'Snapshot-Update: <reason>' trailer.",
    );
  }
  return asked;
}
