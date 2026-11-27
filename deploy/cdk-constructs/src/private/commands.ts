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
  /**
   * Extra arguments appended verbatim to the `ash scan` invocation, except a
   * `--source-dir`, which names the directory scanned in place of
   * `sourceDirectory`; see `withoutSourceDirectory`.
   */
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
export const DEFAULT_ASH_REF = 'v3.8.0';

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
export function ashInvocation(install: InstallOptions): string {
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
 * A command ASH 3.9 added, and what an ASH older than 3.9 says when asked for it.
 *
 * ASH 3.9 names the scan's subject, `ash scan fs PATH`, and groups the commands
 * that read saved results under `ash results`. The old spellings still work there
 * but print a deprecation line, and they go in ASH v4.0. An ASH older than 3.9 has
 * only the old ones, and the ref these commands install can be one: the default
 * names the release this package came from until the release commit moves it, and
 * a caller may pin any ref. So the command asks the ASH it is about to run.
 */
interface NewCommand {
  /** The command's words after `ash`, as its own help names it. */
  readonly words: string[];
  /** The word an older ASH refuses: `fs` for `scan fs`, `results` for `results merge`. */
  readonly refused: string;
  /** What the command is for, in the line the probe prints: `scanning`, `merging`. */
  readonly doing: string;
}

const SCAN_FS: NewCommand = { words: ['scan', 'fs'], refused: 'fs', doing: 'scanning' };
const RESULTS_MERGE: NewCommand = {
  words: ['results', 'merge'],
  refused: 'results',
  doing: 'merging',
};

/**
 * The shell variables the probe answers through. Lower case on purpose: the
 * generated buildspecs declare every `$ASH_` variable they read, and these are the
 * probe's own, not settings.
 */
const PROBE_STATUS = 'ash_probe_status';
const PROBE_HELP = 'ash_probe_help';
const SPELLING = 'ash_spelling';

/**
 * The status a version check ends with when the ASH gives no answer. It is not one of
 * ASH's own: 1 is the verdict for an incomplete result, 2 for findings and 5 for a
 * usage error, so a build whose step ended with one of those could be a refused merge
 * or a check that crashed. 70 is EX_SOFTWARE, an internal error, and a log reader
 * seeing it knows no scan or merge ran.
 */
const UNANSWERED_PROBE_STATUS = 70;

/**
 * The shell text that asks the installed ASH whether it has `command`, and leaves
 * the answer in `$ash_spelling`: `current` for an ASH that has it, `older` for one
 * that does not. For an ASH that gives no answer it prints why and ends with status
 * 70 (`UNANSWERED_PROBE_STATUS`) in a subshell, so a caller that chains the next
 * command with `&&` never runs it, and the status of the chain is the 70.
 *
 * Only an answer settles it, and the answer is read from the probe's exit status
 * and its output together:
 *
 * - exit 0 with a help that names the command: the ASH has it;
 * - exit 0 with a help that does not: an older ASH shows the subject-less scan's
 *   help for `ash scan fs --help`, since its help option is read before the extra
 *   argument is refused;
 * - a non-zero exit with the usage error an older ASH gives for the refused word
 *   (`Got unexpected extra argument (fs)`, `No such command 'results'`): it does not.
 *
 * Any other failure (a crash, an import error, an out-of-memory kill, a `uvx` that
 * could not fetch ASH) says nothing about the ASH's commands. Reading it as an
 * older ASH would run the older spelling on an ASH that has the new one, so the
 * step fails instead, with status 70 and the end of the probe's output, and nothing
 * runs.
 *
 * The probe's output is captured whole and matched with `case`, with no pipe, so an
 * ASH that prints thousands of lines never writes into a closed pipe, which under
 * pipefail would read as a failed probe for an ASH that has the command. The
 * choice and its reason go to stderr on every run.
 */
function askAsh(ash: string, command: NewCommand): string {
  const name = command.words.join(' ');
  const asked = `ash ${name} --help`;
  const status = `$${PROBE_STATUS}`;
  const help = `$${PROBE_HELP}`;
  const say = (message: string): string => `echo "ash: ${message}" >&2`;
  const answer = (spelling: string, message: string): string =>
    `${SPELLING}=${spelling}; ${say(message)};;`;
  return [
    `${PROBE_STATUS}=0;`,
    `${PROBE_HELP}="$(${ash} ${name} --help 2>&1)" || ${PROBE_STATUS}=$?;`,
    `case "${status}:${help}" in`,
    `0:*"${name}"*)`,
    answer('current', `${command.doing} with 'ash ${name}': its help names '${name}'`),
    '0:*)',
    answer(
      'older',
      `${command.doing} with the older spelling: the help of '${asked}' does not name ` +
        `'${name}', as an ASH older than 3.9 answers`,
    ),
    `*:*"unexpected extra argument"*"${command.refused}"*|*:*"No such command"*"${command.refused}"*)`,
    answer(
      'older',
      `${command.doing} with the older spelling: this ASH refused the word ` +
        `'${command.refused}', as an ASH older than 3.9 does`,
    ),
    '*)',
    say(
      `could not tell whether this ASH has 'ash ${name}': '${asked}' exited ${status} ` +
        `without saying it refused '${command.refused}', so no spelling is chosen by guess. ` +
        'The end of its output:',
    ) + ';',
    `printf '%s\\n' "${help}" | tail -n 20 >&2;`,
    `(exit ${UNANSWERED_PROBE_STATUS});;`,
    'esac',
  ].join(' ');
}

/**
 * One command line for each ASH: the new spelling when the installed ASH has it,
 * the old one when it does not, and neither when it cannot be asked. The exit
 * status of the `if` is that of the branch that ran, so the verdict is the scan's
 * or the merge's own; when the probe gives no answer it is the probe's 70.
 */
function onEitherAsh(
  ash: string,
  command: NewCommand,
  current: string[],
  older: string[],
): string {
  return (
    `${askAsh(ash, command)} && ` +
    `if [ "$${SPELLING}" = current ]; then ${[ash, ...current].join(' ')}; ` +
    `else ${[ash, ...older].join(' ')}; fi`
  );
}

/** The option the scan's directory used to be named with, and still is before ASH 3.9. */
const SOURCE_DIR_OPTION = '--source-dir';

/** Whether a word is a `--source-dir`, written `--source-dir` or `--source-dir=DIR`. */
function isSourceDirWord(word: string): boolean {
  return word === SOURCE_DIR_OPTION || word.startsWith(`${SOURCE_DIR_OPTION}=`);
}

/** A quote, a backtick, `$` or a backslash: what lets a shell word mean more than its own text. */
const SHELL_SPECIAL = /["'`$\\]/;

/**
 * A long option, or `--`, as the whole of a value: `--verbose`, `--log-level=INFO`.
 * Written after `--source-dir` it is a directory that was left out, not a directory.
 */
const LONG_OPTION = /^--(?:[A-Za-z][A-Za-z0-9-]*(?:=.*)?)?$/;

/**
 * Whether the words of one element are `--source-dir` and one plain directory word,
 * which is read as the two elements `['--source-dir', 'DIR']` would be.
 */
function isSourceDirAndPlainDirectory(words: string[]): boolean {
  return (
    words.length === 2 &&
    words[0] === SOURCE_DIR_OPTION &&
    !SHELL_SPECIAL.test(words[1]) &&
    !words[1].startsWith('-')
  );
}

/**
 * The directory text a `--source-dir` names, checked and safe to put after `ash scan fs`.
 *
 * The text is what the caller wrote, trimmed, and goes into the command as written. It
 * is refused when it is empty, when it holds another `--source-dir`, which ASH 3.9
 * refuses beside the PATH, and when it is written like a long option, which is a
 * directory that was left out. A name that starts with a dash is made `./NAME`, the
 * same directory, because `ash scan fs` would read the bare name as an option. The
 * checks read the word the shell makes, with its quotes taken out, so `"-x"` is
 * written `./"-x"`. The reusable workflow rewrites the same input the same way.
 */
function sourceDirectoryWord(text: string): string {
  const directory = text.trim();
  const word = directory.replace(/["']/g, '');
  if (word.trim() === '') {
    throw new Error(
      `${SOURCE_DIR_OPTION} in extraScanArguments needs a directory after it: pass ` +
        `['${SOURCE_DIR_OPTION}', 'DIR'] or ['${SOURCE_DIR_OPTION}=DIR'].`,
    );
  }
  const words = word.split(/\s+/);
  if (words.some(isSourceDirWord)) {
    throw new Error(
      `${SOURCE_DIR_OPTION} in extraScanArguments is followed by ${JSON.stringify(directory)}, ` +
        `which holds another ${SOURCE_DIR_OPTION}. Name one directory.`,
    );
  }
  if (LONG_OPTION.test(words[0])) {
    throw new Error(
      `${SOURCE_DIR_OPTION} in extraScanArguments needs a directory after it, but ` +
        `${JSON.stringify(directory)} reads as an option.`,
    );
  }
  return word.startsWith('-') ? `./${directory}` : directory;
}

/** Extra scan arguments with a `--source-dir` among them taken out. */
export interface ExtraScanArguments {
  /** The directory the last `--source-dir` named, as the caller wrote it; absent if none did. */
  readonly sourceDirectory?: string;
  /** The extra arguments without any `--source-dir` and its directory, in their order. */
  readonly rest: string[];
}

/**
 * Take the directory a `--source-dir` among the extra arguments names out of them.
 *
 * Before ASH 3.9 every scan rendered here named its own directory with
 * `--source-dir`, ahead of the extra arguments, so a `--source-dir DIR` among them
 * came later and click scanned DIR; that was the way to scan part of the input.
 * ASH 3.9 takes the directory as the argument of `ash scan fs` and refuses a
 * `--source-dir` that names another one beside it, so DIR left among the extra
 * arguments would fail the scan when it runs. `directoryScanCommand` names DIR the
 * way the installed ASH names a directory instead.
 *
 * The arguments are read one element at a time: `--source-dir` and the directory
 * as two elements, or `--source-dir=DIR` as one, or `--source-dir DIR` as one when
 * DIR is a single word with no quote, backtick, `$` or backslash that does not start
 * with a dash. An element that holds a `--source-dir` among other words, a
 * `--source-dir` with no directory after it, a directory that holds another
 * `--source-dir`, and a directory written like a long option (`--verbose`) are
 * refused rather than guessed at. A directory name that starts with a dash is given
 * as `./NAME`, the same directory, since `ash scan fs` would read the bare name as
 * an option; the reusable workflow does the same. The directory is shell text the
 * caller wrote, like every extra argument, and is passed on as written. When several
 * are given, the last one is the directory, as click resolves a repeated option.
 */
export function withoutSourceDirectory(extraScanArguments: string[]): ExtraScanArguments {
  let sourceDirectory: string | undefined;
  const rest: string[] = [];
  for (let index = 0; index < extraScanArguments.length; index++) {
    const argument = extraScanArguments[index];
    let directory: string;
    if (argument === SOURCE_DIR_OPTION) {
      index += 1;
      directory = extraScanArguments[index] ?? '';
    } else if (argument.startsWith(`${SOURCE_DIR_OPTION}=`)) {
      directory = argument.slice(SOURCE_DIR_OPTION.length + 1);
    } else {
      const words = argument.trim().split(/\s+/);
      if (!words.some(isSourceDirWord)) {
        rest.push(argument);
        continue;
      }
      if (!isSourceDirAndPlainDirectory(words)) {
        throw new Error(
          `${SOURCE_DIR_OPTION} must be an element of its own in extraScanArguments, ` +
            `followed by the directory as the next element, or written ${SOURCE_DIR_OPTION}=DIR; ` +
            `${JSON.stringify(argument)} holds it among other words, or with a directory that ` +
            `is not one plain word. Write ['${SOURCE_DIR_OPTION}', 'DIR'] instead.`,
        );
      }
      directory = words[1];
    }
    sourceDirectory = sourceDirectoryWord(directory);
  }
  return { sourceDirectory, rest };
}

/**
 * A directory scan: `ash scan fs DIR` on an ASH that has the subject, and
 * `ash scan --source-dir DIR` on one that does not, with the same options after.
 *
 * DIR is the one a `--source-dir` among the extra arguments names, else
 * `sourceDirectory`; see `withoutSourceDirectory`. The options come first, then the
 * rest of the extra arguments, so an option the caller repeats wins as it always did.
 */
function directoryScanCommand(
  ash: string,
  sourceDirectory: string,
  options: string[],
  extraScanArguments: string[],
): string {
  const extra = withoutSourceDirectory(extraScanArguments);
  // Rendered before the choice, so an unsafe `sourceDirectory` is refused whether or
  // not a `--source-dir` among the extra arguments replaces it.
  const defaultDirectory = shellArg(sourceDirectory);
  const directory = extra.sourceDirectory ?? defaultDirectory;
  const after = [...options, ...extra.rest];
  return onEitherAsh(
    ash,
    SCAN_FS,
    ['scan', 'fs', directory, ...after],
    ['scan', SOURCE_DIR_OPTION, directory, ...after],
  );
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
  return [
    directoryScanCommand(
      ashInvocation(install),
      options.sourceDirectory,
      [
        '--output-dir',
        shellArg(options.outputDirectory),
        '--min-severity',
        options.severityThreshold,
        '--fail-on-findings',
      ],
      options.extraScanArguments,
    ),
  ];
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
  return [
    directoryScanCommand(
      ashInvocation(install),
      options.sourceDirectory,
      [
        '--output-dir',
        shellArg(options.outputDirectory),
        '--shard-index',
        shellArg(options.shardIndex),
        '--shard-count',
        shellArg(options.shardCount),
        '--no-fail-on-findings',
      ],
      options.extraScanArguments,
    ),
  ];
}

/**
 * Render the merge, which reduces every shard's partial results to one report
 * and one exit code.
 *
 * One `--results` per shard, each a directory. Passing a single parent directory
 * holding every shard is refused by the merge, on the grounds that it would make
 * the merged set depend on whatever else happens to be in the tree, including a
 * previous merged report.
 *
 * The merge is `ash results merge` on an ASH that has the `results` group (3.9 and
 * later) and `ash merge` on one that does not; see `askAsh`.
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
  const options: string[] = [];
  for (const results of resultsPaths) {
    options.push('--results', shellArg(results));
  }
  options.push('--output-dir', shellArg(outputDirectory));
  options.push('--min-severity', severityThreshold);
  return [resultsMergeCommand(ashInvocation(install), options)];
}

/**
 * The merge with `options` after it: `ash results merge` on an ASH that has it,
 * `ash merge` on one that does not.
 *
 * Exported for the buildspec generator, whose merge takes its `--results` from an
 * environment variable at build time and so builds its options in the shell.
 */
export function resultsMergeCommand(ash: string, options: string[]): string {
  return onEitherAsh(ash, RESULTS_MERGE, ['results', 'merge', ...options], [
    'merge',
    ...options,
  ]);
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
