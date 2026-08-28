// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Buildspec documents rendered from the command source of truth.
 *
 * `ASHScanStep` and these files render from the same functions in
 * `./commands`, which is what keeps the CDK path and the committed YAML from
 * describing different scans. CI byte-compares the committed files against a
 * fresh render, so any change here must be accompanied by a regenerated file.
 */

import {
  DEFAULT_ASH_REF,
  DEFAULT_ASH_REPOSITORY,
  installCommands,
  InstallOptions,
  scanCommands,
  shardScanCommands,
  shellArg,
} from './commands';
import { toYamlFile, YamlMap } from './yaml';
import { ASHInstallMode, ASHSeverityThreshold } from '../types';

/**
 * The Python runtime the generated buildspecs request.
 *
 * A literal, not a lookup: reading the local interpreter version would make the
 * output depend on the machine that ran the generator, and the drift gate would
 * fail for whoever upgrades their Python.
 */
const PYTHON_RUNTIME = '3.12';

/** Buildspec `env.variables` defaults shared by all three documents. */
const SOURCE_DIR_VAR = 'ASH_SOURCE_DIR';
const OUTPUT_DIR_VAR = 'ASH_OUTPUT_DIR';
const SHARD_INDEX_VAR = 'ASH_SHARD_INDEX';
const SHARD_COUNT_VAR = 'ASH_SHARD_COUNT';
const SHARD_RESULTS_VAR = 'ASH_SHARD_RESULTS';
const VERSION_VAR = 'ASH_VERSION';

/**
 * How the standalone buildspecs install ASH.
 *
 * The ref is deferred to the `ASH_VERSION` build environment variable rather
 * than baked in, so a consumer can scan with a different ASH release by
 * overriding one variable instead of editing a generated file. The variable's
 * default, declared in each document's `env.variables`, is the pinned
 * `DEFAULT_ASH_REF`.
 */
const STANDALONE_INSTALL: InstallOptions = {
  mode: ASHInstallMode.PIP,
  version: `$${VERSION_VAR}`,
  sourceRepository: DEFAULT_ASH_REPOSITORY,
};

/** Install commands for the standalone buildspecs, which use pip. */
function standaloneInstall(): string[] {
  return installCommands(STANDALONE_INSTALL);
}

/**
 * The header every generated file carries.
 *
 * It names the regeneration command because the first thing a reader who wants
 * to change one of these files needs is the command that rewrites it.
 */
function header(purpose: string[]): string[] {
  return [
    'GENERATED FILE - DO NOT EDIT.',
    '',
    'Rendered from deploy/cdk-constructs/src/private/buildspec.ts, which is also',
    'what the ASHScanStep CDK construct renders its CodeBuild projects from.',
    'Editing this file by hand makes the construct and the committed buildspec',
    'disagree, and CI byte-compares the two.',
    '',
    'Regenerate with:',
    '  cd deploy/cdk-constructs && npm ci && npm run generate:buildspec',
    '',
    ...purpose,
  ];
}

/**
 * Unsharded scan. Owns the pass/fail verdict.
 *
 * This is the document most non-CDK consumers want: one CodeBuild project that
 * scans a repository and fails the build on findings.
 */
export function scanBuildspec(): YamlMap {
  return {
    version: 0.2,
    env: {
      variables: {
        [SOURCE_DIR_VAR]: '.',
        [OUTPUT_DIR_VAR]: '.ash/ash_output',
        [VERSION_VAR]: DEFAULT_ASH_REF,
      },
    },
    phases: {
      install: {
        'runtime-versions': { python: PYTHON_RUNTIME },
        commands: standaloneInstall(),
      },
      build: {
        commands: scanCommands(
          {
            sourceDirectory: `$${SOURCE_DIR_VAR}`,
            outputDirectory: `$${OUTPUT_DIR_VAR}`,
            severityThreshold: ASHSeverityThreshold.LOW,
            extraScanArguments: [],
          },
          STANDALONE_INSTALL,
        ),
      },
    },
    artifacts: {
      'base-directory': `$${OUTPUT_DIR_VAR}`,
      files: ['**/*'],
    },
  };
}

/**
 * One shard of a fanned-out scan. Never fails on findings.
 *
 * Run this document N times with `ASH_SHARD_INDEX` set to 0..N-1, then run
 * `buildspec-merge.yml` once over the collected outputs. Gating on this
 * document's exit code instead of the merge's would gate on a subset of the
 * scanners, which is the failure mode the merge step exists to prevent.
 */
export function shardBuildspec(): YamlMap {
  return {
    version: 0.2,
    env: {
      variables: {
        [SOURCE_DIR_VAR]: '.',
        [OUTPUT_DIR_VAR]: '.ash/ash_output',
        [VERSION_VAR]: DEFAULT_ASH_REF,
        [SHARD_INDEX_VAR]: '0',
        [SHARD_COUNT_VAR]: '1',
      },
    },
    phases: {
      install: {
        'runtime-versions': { python: PYTHON_RUNTIME },
        commands: standaloneInstall(),
      },
      build: {
        commands: shardScanCommands(
          {
            sourceDirectory: `$${SOURCE_DIR_VAR}`,
            outputDirectory: `$${OUTPUT_DIR_VAR}`,
            shardIndex: `$${SHARD_INDEX_VAR}`,
            shardCount: `$${SHARD_COUNT_VAR}`,
            severityThreshold: ASHSeverityThreshold.LOW,
            extraScanArguments: [],
          },
          STANDALONE_INSTALL,
        ),
      },
    },
    artifacts: {
      'base-directory': `$${OUTPUT_DIR_VAR}`,
      files: ['**/*'],
    },
  };
}

/**
 * Merge every shard's partial results into one report and one exit code.
 *
 * `ASH_SHARD_RESULTS` is a space-separated list of directories, one per shard.
 * The loop turns it into the repeated `--results` form, which is the same shape
 * the construct emits with literal paths; `mergeExpansionMatchesLoop` in the
 * tests pins the two together.
 *
 * This step's exit code is the verdict for the whole scan.
 */
export function mergeBuildspec(): YamlMap {
  return {
    version: 0.2,
    env: {
      variables: {
        [OUTPUT_DIR_VAR]: '.ash/ash_output',
        [VERSION_VAR]: DEFAULT_ASH_REF,
        [SHARD_RESULTS_VAR]: '',
      },
    },
    phases: {
      install: {
        'runtime-versions': { python: PYTHON_RUNTIME },
        commands: standaloneInstall(),
      },
      build: {
        commands: mergeLoopCommands(),
      },
    },
    artifacts: {
      'base-directory': `$${OUTPUT_DIR_VAR}`,
      files: ['**/*'],
    },
  };
}

/**
 * The env-var-driven form of `mergeCommands`.
 *
 * Kept beside the merge renderer on purpose. It expands to exactly the argument
 * vector `mergeCommands` builds, one `--results` per shard directory, and it
 * refuses to run on an empty list rather than silently merging nothing, which
 * would report a clean verdict for a scan that never happened.
 */
export function mergeLoopCommands(): string[] {
  return [
    `if [ -z "$${SHARD_RESULTS_VAR}" ]; then ` +
      `echo "${SHARD_RESULTS_VAR} is empty; refusing to report a verdict for zero shards." >&2; ` +
      'exit 1; fi',
    `set --; for shard_dir in $${SHARD_RESULTS_VAR}; do set -- "$@" --results "$shard_dir"; done; ` +
      `ash merge "$@" --output-dir ${shellArg(`$${OUTPUT_DIR_VAR}`)}`,
  ];
}

/** One generated file: its path relative to the package, and its bytes. */
export interface GeneratedBuildspec {
  /** Filename, relative to the package root. */
  readonly filename: string;
  /** Complete file contents, including the trailing newline. */
  readonly contents: string;
}

/**
 * Render every generated buildspec.
 *
 * Order is fixed so callers that print results produce stable output.
 */
export function generatedBuildspecs(): GeneratedBuildspec[] {
  return [
    {
      filename: 'buildspec.yml',
      contents: toYamlFile(
        header([
          'Runs a full, unsharded ASH scan and fails the build on findings.',
          'This document owns its own pass/fail verdict.',
        ]),
        scanBuildspec(),
      ),
    },
    {
      filename: 'buildspec-shard.yml',
      contents: toYamlFile(
        header([
          `One shard of a fanned-out scan. Set ${SHARD_INDEX_VAR} to 0..N-1 and`,
          `${SHARD_COUNT_VAR} to N, then run buildspec-merge.yml over the outputs.`,
          '',
          'This document never fails on findings, by design. A shard runs a subset',
          'of the scanners, so its exit code describes a subset of the repository:',
          'a shard that finds nothing exits 0 even when another shard found a',
          'critical issue. Gate on the merge step, never on a shard.',
        ]),
        shardBuildspec(),
      ),
    },
    {
      filename: 'buildspec-merge.yml',
      contents: toYamlFile(
        header([
          'Merges every shard\'s partial results into one report and one exit code.',
          `Set ${SHARD_RESULTS_VAR} to a space-separated list of shard output`,
          'directories, one per shard.',
          '',
          'This step is the verdict for the whole scan, so `ash merge` must exit',
          'non-zero when the merged findings breach the configured threshold.',
        ]),
        mergeBuildspec(),
      ),
    },
  ];
}
