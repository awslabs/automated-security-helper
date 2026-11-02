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
 * Where ASH comes from, for every command that has to name it.
 *
 * Grouped rather than passed as three positional arguments because all three
 * renderers need all three values, and a caller that swapped two strings would
 * still compile.
 */
export interface InstallOptions {
  /** How ASH is provisioned into the build container. */
  readonly mode: ASHInstallMode;
  /** Git ref to install, or an `$ENV_VAR` reference. Defaults to `DEFAULT_ASH_REF`. */
  readonly version?: string;
  /** Repository to install from. */
  readonly sourceRepository: string;
}

/**
 * Default git ref installed when the caller does not pin one.
 *
 * A tag rather than a branch, so two runs of the same pipeline definition scan
 * with the same ASH. It names the release this tree is: `cz bump` rewrites it at
 * every release, together with the generated `buildspec*.yml` files, so the
 * buildspec drift gate stays green on the release commit ([tool.commitizen]
 * version_files in pyproject.toml). The sharded commands need `ash merge` and the
 * shard options, which v3.7.0 and v3.7.1 predate, so this has to move with the
 * release.
 */
export const DEFAULT_ASH_REF = 'v3.7.1';

/** Default repository ASH is installed from. */
export const DEFAULT_ASH_REPOSITORY =
  'https://github.com/awslabs/automated-security-helper.git';

/**
 * Build the `git+https://...@ref` requirement specifier, quoted for the shell.
 *
 * Composed here rather than through `shellArg` because the ref may legitimately
 * be an `$ENV_VAR` reference embedded mid-string, which `shellArg` only accepts
 * as a whole value. Both halves are validated instead, so nothing unvalidated
 * reaches the command either way.
 */
function gitRequirement(sourceRepository: string, ref: string): string {
  return `"git+${assertGitUrl(sourceRepository)}@${assertGitRef(ref)}"`;
}

/**
 * Render the commands that put an `ash` executable on `PATH`.
 *
 * Nothing here installs by distribution name. ASH is not published to PyPI, and
 * the name `automated-security-helper` there is an unrelated placeholder
 * package, so a name-based install would silently succeed, leave no `ash` on
 * `PATH`, and put a third party's code in the scan container. Installing from
 * the git repository at a pinned ref is what this repository documents for CI.
 *
 * Returns an empty list for `PREINSTALLED`, where the consumer's own image
 * already provides ASH. `UVX` resolves the repository as part of the scan
 * invocation instead, so it installs nothing here either.
 *
 * When the ref is deferred to a build environment variable, the first command,
 * in both `PIP` and `UVX`, checks the variable's value; see `refCheckCommands`.
 */
export function installCommands(install: InstallOptions): string[] {
  const version = install.version ?? DEFAULT_ASH_REF;
  switch (install.mode) {
    case ASHInstallMode.PREINSTALLED:
      return [];

    case ASHInstallMode.UVX:
      // uvx resolves and runs in one step, so there is nothing to install ahead
      // of the scan. See ashInvocation.
      return refCheckCommands(version);

    case ASHInstallMode.PIP:
      return [
        ...refCheckCommands(version),
        'python3 -m pip install --no-cache-dir --disable-pip-version-check ' +
          gitRequirement(install.sourceRepository, version),
      ];
  }
}

/** Reject a repository URL that could break out of the pip argument. */
function assertGitUrl(url: string): string {
  if (!/^https:\/\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]+$/.test(url)) {
    throw new Error(
      `sourceRepository must be an https:// URL, got ${JSON.stringify(url)}.`,
    );
  }
  if (/["`\\]/.test(url)) {
    throw new Error(
      `sourceRepository must not contain shell metacharacters, got ${JSON.stringify(url)}.`,
    );
  }
  return url;
}

/** What a ref may consist of: characters that need no quoting in a shell word. */
const REF_CHARACTERS =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-';

/** The rule both checks below apply, for their error messages. */
const REF_RULE =
  'a plain git ref (a tag, branch name or commit id): letters, digits and . _ / -, ' +
  'not starting with - or ., with no .., no empty path component and no component ' +
  'starting with . or ending in .lock';

/**
 * Whether a ref is one git can only read as a ref.
 *
 * The installers hand the ref to git as an argument of its own: pip runs
 * `git show-ref <ref>` and `git checkout -q <ref>`, and git reads an argument
 * that starts with `-` as an option. So on top of the shell-safe characters, a
 * ref has to follow git's ref-name rules (`git check-ref-format`) that those
 * characters can break, the leading `-` among them. A full commit id passes.
 */
function isPlainGitRef(ref: string): boolean {
  return (
    ref !== '' &&
    [...ref].every((c) => REF_CHARACTERS.includes(c)) &&
    !ref.startsWith('-') &&
    !ref.includes('..') &&
    !ref.endsWith('.') &&
    ref
      .split('/')
      .every((part) => part !== '' && !part.startsWith('.') && !part.endsWith('.lock'))
  );
}

/**
 * Reject a git ref that is not plainly a ref. See `isPlainGitRef`.
 *
 * A bare `$NAME` is allowed so the generated buildspecs can defer the ref to an
 * `ASH_VERSION` build environment variable. That value is not known until the
 * build runs, so `refCheckCommands` checks it there, before the installer.
 */
function assertGitRef(ref: string): string {
  if (ENV_REFERENCE.test(ref)) {
    return ref;
  }
  if (!isPlainGitRef(ref)) {
    throw new Error(
      `version must be ${REF_RULE}, or a bare $ENVIRONMENT_VARIABLE reference; ` +
        `got ${JSON.stringify(ref)}.`,
    );
  }
  return ref;
}

/**
 * The shell command that applies `isPlainGitRef` to a ref deferred to a build
 * environment variable, and stops the build when it fails.
 *
 * Empty for a literal ref, which `assertGitRef` has already checked. The case
 * patterns are `isPlainGitRef`'s rules one by one; the characters are listed
 * rather than written as ranges, because what a range matches depends on the
 * shell's locale.
 */
function refCheckCommands(ref: string): string[] {
  if (!ENV_REFERENCE.test(ref)) {
    return [];
  }
  const variable = ref.slice(1);
  const refused = [
    "''",
    '-*',
    '*..*',
    '*.',
    '/*',
    '*/',
    '*//*',
    '.*',
    '*/.*',
    '*.lock',
    '*.lock/*',
    `*[!${REF_CHARACTERS}]*`,
  ];
  return [
    `case "$${variable}" in ${refused.join('|')}) ` +
      `echo "${variable} must be ${REF_RULE}; got: $${variable}" >&2; exit 1;; esac`,
  ];
}

/**
 * Render the command that invokes `ash` itself, honouring the install mode.
 *
 * `UVX` has no installed executable, so its scan resolves the repository through
 * `uvx --from`. The explicit `--from` form is used rather than `uvx <spec>`
 * because the executable is named `ash` while the distribution is named
 * `automated-security-helper`, and `--from` is what states that difference.
 */
function ashInvocation(install: InstallOptions): string {
  if (install.mode !== ASHInstallMode.UVX) {
    return 'ash';
  }
  const requirement = gitRequirement(
    install.sourceRepository,
    install.version ?? DEFAULT_ASH_REF,
  );
  return `uvx --from ${requirement} ash`;
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
  install: InstallOptions,
): string[] {
  const argv = [
    ashInvocation(install),
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
 *
 * No `--min-severity` here, deliberately. On `ash scan` that option changes only
 * that scan's exit code, and a shard's exit code is discarded by design, so
 * passing it would read as if it set the severity floor while having no effect
 * on anything. The floor belongs on the command that owns the verdict, which is
 * `mergeCommands`.
 */
export function shardScanCommands(
  options: ShardCommandOptions,
  install: InstallOptions,
): string[] {
  const argv = [
    ashInvocation(install),
    'scan',
    '--source-dir',
    shellArg(options.sourceDirectory),
    '--output-dir',
    shellArg(options.outputDirectory),
    '--shard-index',
    shellArg(options.shardIndex),
    '--shard-count',
    shellArg(options.shardCount),
    '--no-fail-on-findings',
    ...options.extraScanArguments,
  ];
  return [argv.join(' ')];
}

/**
 * Render the merge, which reduces every shard's partial results to one report
 * and one exit code.
 *
 * One `--results` per shard, each a directory. Passing a single parent directory
 * holding every shard is refused by `ash merge`, on the grounds that it would
 * make the merged set depend on whatever else happens to be in the tree,
 * including a previous merged report.
 *
 * This command's exit code is the pipeline's verdict, which is also why
 * `--min-severity` is passed here and nowhere else: the severity floor has to
 * reach the command that decides pass or fail. It is passed explicitly rather
 * than left to the shards' recorded configuration, so the floor a pipeline gates
 * on is visible in the command line that applies it.
 */
export function mergeCommands(
  resultsPaths: string[],
  outputDirectory: string,
  severityThreshold: ASHSeverityThreshold,
  install: InstallOptions,
): string[] {
  if (resultsPaths.length === 0) {
    throw new Error('mergeCommands requires at least one results path.');
  }
  const argv = [ashInvocation(install), 'merge'];
  for (const results of resultsPaths) {
    argv.push('--results', shellArg(results));
  }
  argv.push('--output-dir', shellArg(outputDirectory));
  argv.push('--min-severity', severityThreshold);
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
