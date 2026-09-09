#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Asserts every `uses:` reference in .github/workflows and .github/actions names
 * a commit sha rather than a tag or branch.
 *
 * WHY THIS EXISTS
 *
 * A tag is a mutable pointer. `uses: actions/checkout@v7` resolves at run time to
 * whatever `v7` points at then, so an upstream force-push -- or a compromised
 * maintainer account -- changes the code that executes inside a workflow already
 * holding this repository's tokens, with no diff here to review. A commit sha
 * removes the indirection.
 *
 * Pinning by hand is a one-time act; the refs drift back the moment someone adds
 * a step, and the drift looks exactly like every other new step in review. So the
 * invariant needs a check that runs on every pull request rather than a note in a
 * commit message.
 *
 * WHAT COUNTS AS PINNED, AND WHAT THIS CANNOT SEE
 *
 * 40 hex characters after `@`. That is a check on FORM, and form is all a check
 * running offline can have: this script cannot tell a real commit sha from a
 * 40-character tag name, because distinguishing them needs a network call to the
 * upstream repository. The refs in the tree were each confirmed against the
 * GitHub API when they were pinned -- resolved to a commit and then re-read back
 * as a commit -- and that is the half of the guarantee living in the commit
 * message rather than here. What this script guarantees is that nobody
 * REINTRODUCES a tag, which is the failure mode that actually recurs.
 *
 * A trailing `# v7.0.1` is required alongside the sha, and not for tidiness.
 * .github/dependabot.yml declares the `github-actions` ecosystem, and Dependabot
 * reads that comment to learn which version a sha represents. A pinned ref with
 * no comment silently removes itself from the upgrade path: it never goes stale
 * visibly, it just stops being offered updates. A sha with nothing beside it is
 * also unreviewable, since no reader can say which release it is.
 *
 * WHY LOCAL REFS ARE EXEMPT RATHER THAN TOLERATED
 *
 * `./.github/actions/setup-ash` resolves inside this repository at the commit
 * already being run. There is no third party and no mutable pointer, so there is
 * nothing a sha would add -- and GitHub rejects a sha on a local ref outright.
 * Failing on them would make the gate fail on correct configuration, which is the
 * quickest way to get a gate deleted.
 *
 * EXEMPTIONS EXPIRE BY FAILING
 *
 * `--allow-unpinned <path>` exempts one file. The mechanism exists for exactly one
 * situation: a file whose pins are already in flight in another change, where
 * pinning it here too would put two pull requests in conflict over the same lines.
 *
 * An exemption that outlives its reason is worse than no gate, because it reads as
 * coverage. So each one carries a staleness test, the same way the entries in
 * .github/typescript-coverage-exclusions.json do: an exemption naming a file with
 * NO unpinned refs left has stopped being needed, and this script fails and says
 * to delete it. The carve-out therefore cannot be forgotten -- the moment the
 * other change lands, this gate turns red until the flag is removed. An exemption
 * naming a file that is not in the census at all fails for the same reason.
 *
 * NO VACUOUS PASSES
 *
 * The way a check like this really fails is by matching nothing and exiting 0.
 * Every path to an empty examination is closed deliberately:
 *
 *   - `git ls-files` returning no workflow or action files (wrong cwd, not a
 *     repository) would leave nothing to iterate. Fails.
 *   - finding zero `uses:` refs across the whole census means the line scanner is
 *     broken, not that the repository is clean. Fails.
 *   - finding refs but zero that a sha could apply to means every ref was
 *     classified local, which is the same broken-scanner symptom one step later.
 *     Fails.
 *   - a line whose first token is `uses:` but whose value the scanner cannot read
 *     is a ref that would otherwise be skipped in silence. Fails, named.
 *
 * That last one is why the scan is anchored at the start of the line instead of
 * searching for `uses:` anywhere in it. `statuses: write` and `if not statuses:`
 * both contain the substring, and a looser pattern reports both as unpinned refs
 * -- a gate that cries wolf on correct config gets switched off.
 *
 * USAGE
 *
 *   node assert-actions-pinned.mjs
 *
 *   node assert-actions-pinned.mjs \
 *     --allow-unpinned .github/workflows/some-workflow.yml
 */

import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

/** Directories whose YAML can carry a `uses:` key. Nothing else can. */
const SCANNED_DIRS = ['.github/workflows', '.github/actions'];

/**
 * A step or job reference. Anchored at the first token on the line on purpose:
 * see NO VACUOUS PASSES above for what a substring search does to `statuses:`.
 */
const USES = /^(\s*)(?:-\s+)?uses\s*:\s*(\S+)(.*)$/;

/** Same anchor, value optional, so a `uses:` the pattern above cannot read is caught. */
const LOOKS_LIKE_USES = /^\s*(?:-\s+)?uses\s*:/;

const COMMIT_SHA = /^[0-9a-fA-F]{40}$/;

/** An OCI digest is the docker:// equivalent of a commit sha. */
const DIGEST = /@sha256:[0-9a-fA-F]{64}$/;

function parseArgs(argv) {
  const opts = { allowUnpinned: [] };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      const value = argv[i + 1];
      // An option that lost its value must not consume the next option, and must
      // not quietly become an exemption for the empty path.
      if (value === undefined || value.startsWith('--')) {
        throw new Error(`${arg} needs a value, got ${JSON.stringify(value)}`);
      }
      i += 1;
      return value;
    };
    switch (arg) {
      case '--allow-unpinned': {
        const value = next();
        if (opts.allowUnpinned.includes(value)) {
          throw new Error(`--allow-unpinned ${value} given twice`);
        }
        opts.allowUnpinned.push(value);
        break;
      }
      default:
        throw new Error(`unknown argument: ${arg}`);
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

/** Drops a trailing comment so a commented-out `uses:` is not read as a live ref. */
function codeOf(line) {
  const hash = line.indexOf('#');
  return hash === -1 ? line : line.slice(0, hash);
}

/** Strips one layer of matching quotes, so `uses: "actions/checkout@v7"` classifies. */
function unquote(value) {
  const quoted = /^(['"])(.*)\1$/.exec(value);
  return quoted ? quoted[2] : value;
}

/**
 * Reads every `uses:` ref out of one file.
 *
 * Returns refs plus any line the scanner could not read, which the caller reports
 * rather than skips.
 */
function scanFile(repoRoot, file) {
  const text = readFileSync(path.resolve(repoRoot, file), 'utf8');
  const refs = [];
  const unreadable = [];

  text.split('\n').forEach((line, index) => {
    const lineNumber = index + 1;
    const match = USES.exec(line);
    if (!match) {
      // A commented-out example resolves to empty code and is correctly ignored;
      // a real `uses:` whose value this pattern cannot read is not.
      if (LOOKS_LIKE_USES.test(codeOf(line))) {
        unreadable.push({ file, line: lineNumber, text: line.trim() });
      }
      return;
    }
    refs.push({
      file,
      line: lineNumber,
      value: unquote(match[2]),
      comment: match[3].trim(),
    });
  });

  return { refs, unreadable };
}

/**
 * Classifies one ref: `local`, `pinned`, or a problem string explaining what is
 * wrong and what to do about it.
 */
function classify(ref) {
  const { value, comment } = ref;

  if (value.startsWith('./') || value.startsWith('../')) {
    return { kind: 'local' };
  }

  if (value.startsWith('docker://')) {
    if (DIGEST.test(value)) return { kind: 'pinned' };
    return {
      kind: 'unpinned',
      problem:
        `${value} is a docker:// image referenced by tag. A tag is repushable, so ` +
        'this has the same mutability as a git tag. Reference the image by digest ' +
        'instead: docker://<image>@sha256:<64 hex>.',
    };
  }

  const at = value.lastIndexOf('@');
  if (at === -1) {
    return {
      kind: 'unpinned',
      problem:
        `${value} has no ref at all, so it resolves to the action's default branch, ` +
        'which moves with every push upstream. Pin it to a commit sha.',
    };
  }

  const gitRef = value.slice(at + 1);
  if (!COMMIT_SHA.test(gitRef)) {
    return {
      kind: 'unpinned',
      problem:
        `${value} is pinned to ${JSON.stringify(gitRef)}, which is a tag or branch, ` +
        'not a commit sha. Tags are mutable: the code this runs can change with no ' +
        'diff here to review. Resolve it to the commit and add the version as a ' +
        'trailing comment, e.g. actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1. ' +
        'Dereference annotated tags to the COMMIT -- an annotated tag ref names a ' +
        'tag object whose sha is 40 hex characters and is not checkoutable.',
    };
  }

  if (!/^#\s*\S/.test(comment)) {
    return {
      kind: 'uncommented',
      problem:
        `${value} is pinned to a sha but carries no trailing version comment. ` +
        'Dependabot reads that comment to learn which version the sha is, so ' +
        'without it the github-actions ecosystem entry in .github/dependabot.yml ' +
        'cannot offer an upgrade, and no reader can tell which release this is. ' +
        'Add one, e.g. `# v7.0.1`.',
    };
  }

  return { kind: 'pinned' };
}

function main(argv) {
  const opts = parseArgs(argv);
  const repoRoot = git(process.cwd(), ['rev-parse', '--show-toplevel']).trim();
  const problems = [];

  // Tracked files only, so an untracked stray in a working tree cannot change the
  // verdict either way.
  const census = splitZ(
    git(repoRoot, ['ls-files', '-z', '--', ...SCANNED_DIRS]),
  ).filter((file) => file.endsWith('.yml') || file.endsWith('.yaml'));

  if (census.length === 0) {
    throw new Error(
      `git ls-files found no YAML under ${SCANNED_DIRS.join(' or ')} in ${repoRoot} -- ` +
        'there is nothing to check, and this gate must not pass by finding nothing',
    );
  }

  const exempt = new Set(opts.allowUnpinned);
  for (const file of exempt) {
    if (!census.includes(file)) {
      problems.push(
        `--allow-unpinned ${file} names a file that is not tracked YAML under ` +
          `${SCANNED_DIRS.join(' or ')}. It was renamed, deleted, or misspelled; ` +
          'the flag exempts nothing. Remove it.',
      );
    }
  }

  const counts = { total: 0, local: 0, pinned: 0, exempted: 0 };
  const unpinnedByFile = new Map();

  for (const file of census) {
    const { refs, unreadable } = scanFile(repoRoot, file);

    for (const bad of unreadable) {
      // Not skippable: a ref the scanner cannot read is a ref it cannot check,
      // and silently ignoring it is how a gate passes while covering less.
      problems.push(
        `${bad.file}:${bad.line} begins with \`uses:\` but this check cannot read ` +
          `its value: ${JSON.stringify(bad.text)}. Refusing to skip a reference ` +
          'it cannot classify.',
      );
    }

    for (const ref of refs) {
      counts.total += 1;
      const verdict = classify(ref);

      if (verdict.kind === 'local') {
        counts.local += 1;
        continue;
      }
      if (verdict.kind === 'pinned') {
        counts.pinned += 1;
        continue;
      }

      // Unpinned or uncommented from here down.
      if (!unpinnedByFile.has(ref.file)) unpinnedByFile.set(ref.file, []);
      unpinnedByFile.get(ref.file).push(ref);

      if (exempt.has(ref.file)) {
        counts.exempted += 1;
        continue;
      }
      problems.push(`${ref.file}:${ref.line} ${verdict.problem}`);
    }
  }

  if (counts.total === 0) {
    throw new Error(
      `no \`uses:\` reference found in any of the ${census.length} file(s) scanned. ` +
        'Workflows without a single step reference are implausible, so this is the ' +
        'scanner failing rather than the repository being clean',
    );
  }

  if (counts.total === counts.local) {
    throw new Error(
      `all ${counts.total} \`uses:\` reference(s) classified as local, so the sha ` +
        'requirement was applied to nothing. A pass here would measure the ' +
        'classifier, not the repository',
    );
  }

  // An exemption that is no longer needed must not be carried forward silently:
  // it reads as coverage while covering nothing.
  for (const file of exempt) {
    if (!census.includes(file)) continue;
    if (!unpinnedByFile.has(file)) {
      problems.push(
        `--allow-unpinned ${file} is stale: every reference in that file is now ` +
          'pinned, so the exemption excuses nothing. Remove the flag from the ' +
          'workflow that passes it.',
      );
    }
  }

  if (problems.length > 0) {
    process.stderr.write('Action pinning check failed:\n');
    for (const problem of problems) {
      process.stderr.write(`  - ${problem}\n`);
    }
    return 1;
  }

  process.stdout.write(
    `action pinning OK: ${counts.total} \`uses:\` reference(s) across ` +
      `${census.length} file(s) -- ${counts.pinned} pinned to a commit sha, ` +
      `${counts.local} local and exempt by nature, ` +
      `${counts.exempted} unpinned under an explicit --allow-unpinned exemption ` +
      `that is still needed\n`,
  );
  return 0;
}

try {
  process.exitCode = main(process.argv);
} catch (err) {
  process.stderr.write(`action pinning: ${err.message}\n`);
  process.exitCode = 2;
}
