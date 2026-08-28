// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The single source of truth for every ASH command line this package emits.
 *
 * Both consumers render from here: `ASHScanStep` builds CodeBuild projects out
 * of these strings, and the buildspec generator writes the same strings into
 * the committed `buildspec*.yml` files. Nothing else may assemble an ASH
 * command line, because a second assembler is how the CDK path and the
 * committed buildspecs drift apart.
 *
 * This module is deliberately not re-exported from `index.ts`. jsii models only
 * classes, interfaces and enums, so the free functions here cannot appear in
 * the public API surface.
 */

import { ASHInstallMode, ASHSeverityThreshold } from '../types';

/**
 * Characters that would let a path escape its argument and run as shell code.
 *
 * Values are interpolated into double-quoted shell words, so these are exactly
 * the characters double quotes do not neutralize, plus the quote itself.
 */
const SHELL_UNSAFE = /["`$\\\n\r]/;

/** An `$ENV_VAR` reference, which is the one case where `$` is intentional. */
const ENV_REFERENCE = /^\$[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Render a value as a single double-quoted shell word.
 *
 * A bare `$NAME` passes through so callers can reference build environment
 * variables. Anything else must be free of shell metacharacters: rejecting them
 * here is what stops a path from turning into a command, and it keeps the
 * generated buildspec safe to read as data.
 */
export function shellArg(value: string): string {
  if (ENV_REFERENCE.test(value)) {
    return `"${value}"`;
  }
  if (SHELL_UNSAFE.test(value)) {
    throw new Error(
      `Refusing to build a shell command from ${JSON.stringify(value)}: it contains one of ` +
        '" ` $ \\ or a newline. Pass a plain path, or a bare $ENVIRONMENT_VARIABLE reference.',
    );
  }
  return `"${value}"`;
}

/** Inputs shared by every ASH invocation this package renders. */
export interface CommonCommandOptions {
  /** Directory ASH scans. */
  readonly sourceDirectory: string;
  /** Directory ASH writes results into. */
  readonly outputDirectory: string;
  /** Lowest severity that produces a non-zero exit code. */
  readonly severityThreshold: ASHSeverityThreshold;
  /** Extra arguments appended verbatim to the `ash scan` invocation. */
  readonly extraScanArguments: string[];
}

/** Inputs for a single shard of a fanned-out scan. */
export interface ShardCommandOptions extends CommonCommandOptions {
  /** Zero-based index of this shard. */
  readonly shardIndex: string;
  /** Total number of shards. */
  readonly shardCount: string;
}

/**
 * Render the commands that put an `ash` executable on `PATH`.
 *
 * Returns an empty list for `PREINSTALLED`, where the consumer's own image
 * already provides ASH.
 */
export function installCommands(
  mode: ASHInstallMode,
  version: string | undefined,
  sourceRepository: string,
): string[] {
  switch (mode) {
    case ASHInstallMode.PREINSTALLED:
      return [];

    case ASHInstallMode.PIP: {
      const spec = version === undefined
        ? 'automated-security-helper'
        : `automated-security-helper==${version}`;
      return [`python3 -m pip install --no-cache-dir --disable-pip-version-check ${shellArg(spec)}`];
    }

    case ASHInstallMode.UVX: {
      // uvx resolves the distribution per invocation, so there is nothing to
      // install. Pinning here only records the resolved version in the log.
      const spec = version === undefined
        ? 'automated-security-helper'
        : `automated-security-helper==${version}`;
      return [`uvx --from ${shellArg(spec)} ash --version`];
    }

    case ASHInstallMode.GIT: {
      const ref = version === undefined ? 'main' : version;
      return [
        `python3 -m pip install --no-cache-dir --disable-pip-version-check ` +
          `"git+${assertGitUrl(sourceRepository)}@${assertGitRef(ref)}"`,
      ];
    }
  }
}

/** Reject a repository URL that could break out of the pip argument. */
function assertGitUrl(url: string): string {
  if (!/^https:\/\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]+$/.test(url)) {
    throw new Error(
      `sourceRepository must be an https:// URL, got ${JSON.stringify(url)}.`,
    );
  }
  return url;
}

/** Reject a git ref that could break out of the pip argument. */
function assertGitRef(ref: string): string {
  if (!/^[A-Za-z0-9._/-]+$/.test(ref)) {
    throw new Error(
      `version must be a plain git ref when installMode is GIT, got ${JSON.stringify(ref)}.`,
    );
  }
  return ref;
}

/**
 * Render the command that invokes `ash` itself, honouring the install mode.
 *
 * `UVX` has no persistent executable, so its scan runs through `uvx --from`.
 */
function ashInvocation(mode: ASHInstallMode, version: string | undefined): string {
  if (mode !== ASHInstallMode.UVX) {
    return 'ash';
  }
  const spec = version === undefined
    ? 'automated-security-helper'
    : `automated-security-helper==${version}`;
  return `uvx --from ${shellArg(spec)} ash`;
}

/**
 * Render the unsharded scan, which owns the pass/fail verdict itself.
 *
 * `--fail-on-findings` is passed explicitly rather than left to the ASH
 * configuration file. The verdict of a security gate should be visible in the
 * command line that produces it, not inherited from a file the pipeline
 * definition does not show.
 */
export function scanCommands(
  options: CommonCommandOptions,
  mode: ASHInstallMode,
  version: string | undefined,
): string[] {
  const argv = [
    ashInvocation(mode, version),
    'scan',
    '--source-dir',
    shellArg(options.sourceDirectory),
    '--output-dir',
    shellArg(options.outputDirectory),
    '--min-severity',
    options.severityThreshold,
    '--fail-on-findings',
    ...options.extraScanArguments,
  ];
  return [argv.join(' ')];
}

/**
 * Render one shard of a fanned-out scan.
 *
 * `--no-fail-on-findings` is not optional and is not configurable. A shard runs
 * a subset of the scanners, so its exit code describes a subset of the
 * repository: a shard that finds nothing exits 0 whether or not another shard
 * found a critical issue. Letting a shard fail the build would also stop the
 * merge from ever running, which would replace the aggregate verdict with a
 * partial one. The merge step is the only step allowed to fail on findings.
 */
export function shardScanCommands(
  options: ShardCommandOptions,
  mode: ASHInstallMode,
  version: string | undefined,
): string[] {
  const argv = [
    ashInvocation(mode, version),
    'scan',
    '--source-dir',
    shellArg(options.sourceDirectory),
    '--output-dir',
    shellArg(options.outputDirectory),
    '--shard-index',
    shellArg(options.shardIndex),
    '--shard-count',
    shellArg(options.shardCount),
    '--min-severity',
    options.severityThreshold,
    '--no-fail-on-findings',
    ...options.extraScanArguments,
  ];
  return [argv.join(' ')];
}

/**
 * Render the merge, which reduces every shard's partial results to one report
 * and one exit code.
 *
 * `--results` is repeated once per shard and accepts a file or a directory.
 * This command's exit code is the pipeline's verdict, so `ash merge` must exit
 * non-zero when the merged findings breach the configured threshold.
 */
export function mergeCommands(
  resultsPaths: string[],
  outputDirectory: string,
  mode: ASHInstallMode,
  version: string | undefined,
): string[] {
  if (resultsPaths.length === 0) {
    throw new Error('mergeCommands requires at least one results path.');
  }
  const argv = [ashInvocation(mode, version), 'merge'];
  for (const results of resultsPaths) {
    argv.push('--results', shellArg(results));
  }
  argv.push('--output-dir', shellArg(outputDirectory));
  return [argv.join(' ')];
}

/**
 * Directory a given shard writes its results into, relative to the step's
 * output directory.
 *
 * Shards must not share an output directory: ASH clears the output directory
 * before a scan, so two shards pointed at one directory would delete each
 * other's results.
 */
export function shardOutputDirectory(outputDirectory: string, shardIndex: number): string {
  return `${outputDirectory}/shard-${shardIndex}`;
}
