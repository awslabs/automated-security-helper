# Run ASH with pre-commit

ASH's repository defines hooks for the [pre-commit](https://pre-commit.com/) framework.
This page sets up the `ash` hook, says what it scans, and what it costs per commit.

Prerequisites:

- pre-commit, running on Python 3.10 to 3.14, or a `language_version` as shown
  [below](#python-version).
- A git repository with a `.pre-commit-config.yaml`.
- Network access to GitHub and PyPI the first time the hook runs.

## Add the hook {#add}

<!-- doctest: config kind=pre-commit -->
```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.7.1
    hooks:
      - id: ash
```

Then install the git hook and run it once on every file:

<!-- doctest: illustrative reason="installs the hook environment from GitHub" -->
```bash
pre-commit install
pre-commit run ash --all-files
```

The first run builds the hook's environment, with ASH's `cdk` extra, and installs bandit
and checkov, so it takes longer than later runs. When the hook finds something,
pre-commit prints `Failed` with ASH's summary and `- exit code: 2`, and the commit stops.
Exit code 1 means the scan did not complete, for example because a scanner was MISSING;
[Exit codes](../reference/exit-codes.md) lists every cause.

Ignore ASH's output directory in git, so the reports are not committed. ASH leaves its own
files there out of the scan whether or not `.gitignore` lists them, but it scans a file
committed there like any other. `ash config init`
writes a `.ash/.gitignore` that ignores it, or add the line yourself:

```text
.ash/ash_output/
```

Do not ignore all of `.ash/`: an ASH config file can live there, as `.ash/.ash.yaml`.

## What the hook runs {#behavior}

The `ash` hook runs `ashv3 --mode=precommit` with your `args`. Precommit mode:

- runs five scanners: bandit, detect-secrets, checkov, cdk-nag, and npm-audit. `--scanners`
  can add others but cannot remove these; `--exclude-scanners` removes them.
- scans the whole repository on every run, not only the staged files. A commit that touches
  one file is still blocked by a finding in a file committed earlier.
- prints simplified output and writes the usual reports to `.ash/ash_output/`.

The hook's environment includes the `cdk` extra that cdk-nag needs. cdk-nag and npm-audit
also need Node.js and npm on `PATH`, but only when the repository has files they scan:
CloudFormation templates for cdk-nag, including the `*.template.json` files `cdk synth`
writes to `cdk.out` even when `.gitignore` lists `cdk.out`, and a `package.json` with an
npm, yarn, or pnpm lockfile beside it for npm-audit. In a repository with neither, both are SKIPPED and the
hook runs without Node.js. In one that has them, Node.js and npm must be on `PATH`, or ASH
reports the scanner that has files to scan as MISSING and the hook fails with exit code 1
on every commit. To run without Node.js there, exclude the two scanners:

<!-- doctest: config kind=pre-commit -->
```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.7.1
    hooks:
      - id: ash
        args: [--exclude-scanners, cdk-nag, --exclude-scanners, npm-audit]
```

They are then SKIPPED, and the hook passes or fails on the other three. `ash-simple-scan`
is the same hook under another name.

Do not add `--no-fail-on-incomplete-scanners` to the hook: with it, a commit passes when a
scanner did not run, and the output says only `Passed`.

### Add Python packages to the hook {#additional-dependencies}

`additional_dependencies` in your configuration replaces the hook's own list rather than
adding to it. The `ash` hook's list is `.[cdk]`, which installs the `cdk` extra from the
hook's clone of ASH, so a list of your own has to include `.[cdk]` as well. Without it,
cdk-nag is MISSING in a repository with CloudFormation templates.

## When the hook runs {#stages}

The hook has no `stages` setting, so it runs on every commit. To run it less often, set one:

<!-- doctest: config kind=pre-commit -->
```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.7.1
    hooks:
      - id: ash
        stages: [pre-push]
```

With `stages: [pre-push]`, install that hook type with
`pre-commit install --hook-type pre-push`, and a failing scan blocks `git push`. With
`stages: [manual]`, the hook runs only when you ask:
`pre-commit run --hook-stage manual ash`.

## What it costs {#cost}

Measured on a repository of three files:

| Run | Time |
|---|---|
| First run, with the hook environment and scanner installs | 65 to 150 seconds |
| Later runs | 11 to 15 seconds |

checkov is the slowest scanner. Scan time grows with the size of the repository, because
every run scans all of it. The hook environment takes about 650 MB under
`~/.cache/pre-commit`, and bandit and checkov about 240 MB under `~/.local/share/uv`.

## Use an ASH you already installed {#local-hook}

If ASH is installed with `uv tool install` or in a virtual environment outside the
repository, a local hook runs that installation instead of building one per repository:

<!-- doctest: config kind=pre-commit -->
```yaml
repos:
  - repo: local
    hooks:
      - id: ash
        name: ASH
        entry: ash --mode precommit
        language: system
        pass_filenames: false
```

`ash` must be on `PATH` when git runs the hook. ASH installs bandit and checkov with the
`uv` installed with it, or with a `uv` on `PATH`. `pass_filenames: false` is required.
Without it, pre-commit appends the staged file names, and ASH rejects the first one as an
unknown command, a usage error, with exit code 5.

This hook uses the extras and tools of that installation. When the repository has
CloudFormation templates, cdk-nag needs the `cdk` extra in that installation and Node.js
on `PATH`; when it has npm lockfiles, npm-audit needs npm on `PATH`. A scanner that lacks
them is MISSING and every commit fails with exit code 1. Add
`--exclude-scanners cdk-nag --exclude-scanners npm-audit` to `entry` to leave the two
out.

## Pre-commit on another Python {#python-version}

pre-commit builds a Python hook's environment with the interpreter it runs under, and ASH
installs on Python 3.10 to 3.14 only. If pre-commit itself runs on another version,
building the hook environment fails; on Python 3.9 the error is
`No matching distribution found for hatchling>=1.32.4`. Install pre-commit on a supported
interpreter:

<!-- doctest: illustrative reason="installs pre-commit from PyPI" -->
```bash
uv tool install --python 3.12 pre-commit
```

Or point the hook at a newer Python that is on your `PATH`:

<!-- doctest: config kind=pre-commit -->
```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.7.1
    hooks:
      - id: ash
        language_version: python3.12
```

`default_language_version` at the top of the file does the same for every Python hook.

## A frozen rev is flagged as a secret {#frozen-rev}

`pre-commit autoupdate --freeze` replaces the tag with a 40-character commit SHA, and
detect-secrets reports that line of `.pre-commit-config.yaml` as a high-entropy string,
which fails the hook with exit code 2. Suppress that finding for that file, with the
reason:

<!-- doctest: config kind=ash -->
```yaml
global_settings:
  suppressions:
    - path: .pre-commit-config.yaml
      rule_id: SECRET-HEX-HIGH-ENTROPY-STRING
      reason: pre-commit autoupdate --freeze pins hooks to commit SHAs
```

Put it in your ASH config file, or, if the repository has none, in a new `.ashrc.yaml` at
its root. [Suppress findings](suppress-findings.md) covers expiration dates and narrower
matches.

## The ash-full-scan hook {#full-scan}

`.pre-commit-hooks.yaml` also defines `ash-full-scan`, which runs
`ashv3 --mode=container --simple`. It builds ASH's container image from the source that
pre-commit installed, then scans the repository inside it with every scanner the image
carries. It needs a container runtime on the host: finch, docker, nerdctl, or podman, found
in that order. The first run builds the image and takes several minutes, so give the hook
`stages: [pre-push]` or `stages: [manual]`:

<!-- doctest: config kind=pre-commit -->
```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.7.1
    hooks:
      - id: ash-full-scan
        stages: [manual]
```

<!-- doctest: illustrative reason="builds ASH's container image, which needs a container runtime and the network" -->
```bash
pre-commit run --hook-stage manual ash-full-scan --all-files
```

[Run ASH in a container](run-in-a-container.md) covers container mode.
