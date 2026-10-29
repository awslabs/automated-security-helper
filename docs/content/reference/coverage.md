# Scanner coverage

Which scanners read which files. Every built-in scanner is on by default, and each one
decides for itself what to read, so a scanner with nothing to read in your repository
reports `SKIPPED` or `PASSED` with no findings. [Scanners](scanners.md) lists each
scanner's tool, version, and options, and [Choose scanners](../how-to/choose-scanners.md)
shows how to turn them on and off.

Community plugins run only when you load their module with `ash_plugin_modules` or
`--ash-plugin-modules`; see [Community plugins](../docs/plugins/community/index.md).

## By stack {#by-stack}

| What your repository has | Built-in scanners | Community plugins |
|---|---|---|
| Python code | bandit, semgrep, opengrep | snyk-code |
| JavaScript and TypeScript code | semgrep, opengrep | snyk-code |
| Java, Go, Ruby, C#, PHP, and other languages | semgrep, opengrep (as far as their rules cover the language) | snyk-code |
| Python dependencies (`requirements.txt`, lockfiles) | grype, trivy, syft | trivy-repo |
| npm, Yarn, and pnpm dependencies | npm-audit, grype, trivy, syft | trivy-repo |
| Other dependency manifests and lockfiles (`go.mod`, `pom.xml`, and the others grype and trivy recognize) | grype, trivy, syft | trivy-repo |
| CloudFormation templates | cfn-nag, cfn-lint, cfn-guard, cdk-nag, checkov | trivy-repo |
| AWS CDK apps | cfn-nag, cfn-lint, cfn-guard, cdk-nag, checkov (on the templates `cdk synth` writes to `cdk.out`); bandit, semgrep, opengrep (on the app code; bandit reads only Python) | trivy-repo |
| Terraform | checkov | trivy-repo |
| Kubernetes manifests and the other formats checkov supports | checkov | trivy-repo |
| Dockerfiles | checkov | trivy-repo |
| GitHub Actions workflows | actionlint, zizmor, checkov | |
| Composite actions (`action.yml`) | zizmor | |
| Secrets, in any file | detect-secrets, gitleaks | ferret-scan (sensitive data), trivy-repo |
| A software bill of materials | syft | |
| Jupyter notebooks | bandit, detect-secrets, gitleaks (on the converted script, bandit only for a Python notebook; see [Converted files](#converted-files)) | |
| `.zip`, `.tar`, and `.gz` archives | detect-secrets, gitleaks (on every extracted file; see [Converted files](#converted-files)) | |

The other scanners read converted scripts and extracted files of the kinds they cover, as
they do in the source directory, except that semgrep and opengrep leave scripts converted
from Python notebooks out by default.

For a CDK app, synthesize before you scan, so that `cdk.out` holds the templates. ASH
keeps the synthesized templates in the scan set when your root `.gitignore` excludes
`cdk.out`; see [What decides the files](#what-decides-the-files).

## By scanner {#by-scanner}

"Whole directory" means the tool walks the source directory itself and applies its own
rules for which files to read. "Selected files" means ASH picks the files and passes
them to the tool.

<!-- doctest: options of=scanners complete -->
| Scanner | Type | What it reads | `--python-only` | `--mode precommit` |
|---|---|---|---|---|
| actionlint | IaC | Selected files: GitHub Actions workflows | no | no |
| bandit | SAST | Whole directory: Python files, skipping `.venv/`, `venv/`, and `node_modules/` | yes | yes |
| cdk-nag | IaC | Selected files: CloudFormation templates | no | yes |
| cfn-guard | IaC | Selected files: CloudFormation templates, against the `wa-Security-Pillar` ruleset by default | no | no |
| cfn-lint | IaC | Selected files: CloudFormation templates | yes | no |
| cfn-nag | IaC | Selected files: CloudFormation templates | no | no |
| checkov | IaC | Whole directory, every checkov framework (`--framework all`), skipping `.venv/`, `venv/`, and `node_modules/` | yes | yes |
| detect-secrets | Secrets | Selected files: every file in the scan set except generated lockfiles | yes | yes |
| gitleaks | Secrets | Whole directory: the files on disk, not git history | no | no |
| grype | SCA | Whole directory: the packages it catalogs from manifests and lockfiles | no | no |
| npm-audit | SCA | Selected files: each `package.json` that has a lockfile beside it | no | yes |
| opengrep | SAST | Whole directory, with ASH's bundled rules and the `p/ci` ruleset | no | no |
| semgrep | SAST | Whole directory, with ASH's bundled rules and the `p/ci` ruleset | yes | no |
| syft | SBOM | Whole directory: builds an SBOM and reports no findings | no | no |
| trivy | SCA | Whole directory: `trivy fs` with the vulnerability scanner only, by default | no | no |
| zizmor | SAST | Selected files: GitHub Actions workflows and composite actions | yes | no |
| ferret-scan | Secrets | Whole directory, including files `.gitignore` excludes | no | no |
| snyk-code | SAST | Whole directory, sent to Snyk's service | no | no |
| trivy-repo | SAST | Whole directory: `trivy repository` with the vulnerability, secret, misconfiguration, and license scanners | no | no |

`--python-only` runs only the scanners marked yes and reports the rest `SKIPPED`, whether
or not their tools are installed.

`--mode precommit` runs the five scanners marked yes, plus any you name with
`--scanners`.

## How each scanner picks its files {#file-patterns}

### GitHub Actions

actionlint reads every `*.yml` and `*.yaml` file whose parent directory is `workflows`
inside a `.github` directory, at any depth, so `sub/.github/workflows/ci.yml` counts and
`.github/workflows/nested/ci.yml` does not. The directory names are case-sensitive; the
extension is not.

zizmor reads the same workflows plus every `action.yml` and `action.yaml`, and skips
paths under `.venv`, `venv`, or `node_modules`. zizmor itself rejects an upper-case
extension such as `CI.YML`, and the scanner then reports `ERROR`.

With no workflows, both report `SKIPPED`. checkov also checks workflows, through its
own GitHub Actions framework.

### CloudFormation

cfn-nag, cfn-lint, cfn-guard, and cdk-nag share one rule: a file in the scan set whose
name ends in `.json`, `.yaml`, or `.yml` (lowercase) and that parses to a document with a
top-level `Resources` mapping. `AWSTemplateFormatVersion` is not required. Files ending
in `.template` are not read by these four; checkov reads them.

cfn-nag and cfn-guard run once per template; cfn-lint checks them all in one run.
cdk-nag applies its AWS Solutions rule pack. With no templates, all four report
`SKIPPED`.

cfn-nag reads a copy of each template that ASH writes in the scanner's results
directory, named `template.json`, `template.yaml`, or `template.yml` after the
template's extension, and removes it after the run. Findings name the original
template. On Windows, where `cfn_nag_scan` is a batch file, the template's own name
never reaches its command line, so characters such as `&` and `|` in it are not read as
command syntax.

### Dependencies {#dependencies}

npm-audit finds each `package.json` and audits the first lockfile beside it of
`yarn.lock`, `pnpm-lock.yaml`, and `package-lock.json`, with `yarn`, `pnpm`, or `npm`. A
`package.json` with no lockfile is not audited. If `yarn` or `pnpm` is not installed,
that lockfile is not audited and counts as an input npm-audit could not read, so the scan
is incomplete. With no lockfile beside any `package.json`, npm-audit reports `SKIPPED`,
whether or not npm is installed. npm-audit does not run offline, because the package
managers audit a lockfile by asking the registry: offline, a project with a lockfile
reports npm-audit `MISSING`, and one without reports it `SKIPPED`.

grype and trivy read the source directory themselves, so they find every manifest and
lockfile their own catalogers recognize. trivy runs only its vulnerability scanner
unless you set `scanners.trivy.options.scanners`. syft builds the SBOM from the same
kind of catalog and reports no findings.

### Secrets

detect-secrets reads every file in the scan set except generated lockfiles
(`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `npm-shrinkwrap.json`,
`poetry.lock`, `uv.lock`, `pipenv.lock`, `Pipfile.lock`, `conda-lock.yml`,
`conda-lock.yaml`). gitleaks runs `gitleaks dir` on the source directory, so it reads
the files on disk and not the git history.

### Source code

bandit, semgrep, opengrep, checkov, and snyk-code read the source directory themselves.
semgrep and opengrep always use ASH's bundled rules. Online they add the ruleset in
their `config` option, `p/ci` by default (`scanners.semgrep.options.config`); offline
they add the rules cached in the directory `SEMGREP_RULES_CACHE_DIR` or
`OPENGREP_RULES_CACHE_DIR` names. The languages they cover are the languages those
rules cover.

## What decides the files {#what-decides-the-files}

Before the scan, ASH lists the files to scan, the scan set, and writes it to
`ash-scan-set-files-list.txt` in the output directory (see
[Output files](output-files.md)):

- It walks the source directory. It does not ask git, so untracked files are included
  and the directory does not have to be a repository.
- Every `.gitignore` and `.ignore` file in the tree applies, with git's rules: a nested
  file applies to its own directory.
- ASH always leaves out `.git` and `cdk.out/asset.*`, keeps `*.template.json` files
  that an ignore file would otherwise exclude, and drops every path containing
  `/node_modules/aws-cdk` (which also matches `aws-cdk-lib`). A directory the root
  `.gitignore` excludes is skipped whole, except a CDK cloud assembly: a directory named
  `cdk.out`, or one that holds a `cdk.out` file and a `manifest.json`. ASH still looks in
  it and keeps its `*.template.json` files, so the CloudFormation scanners read the
  synthesized templates.
- ASH leaves out its own output directories: this scan's `--output-dir`, and
  `.ash/ash_output` under the source directory and under the working directory, when they
  are inside the source directory and not reached through a symbolic link. In a git
  repository, the files git tracks in them stay in the scan set, in this scan's own
  output directory too, and ASH logs a warning. Outside git, these directories are left
  out whole. Any other directory, such
  as another shard's output, is scanned like the rest of the tree; when it holds ASH's
  result files, ASH logs a warning.
- `node_modules`, `.venv`, and `venv` stay in the scan set. bandit, checkov, and zizmor
  skip them on their own.

The scanners marked "Selected files" above read only the scan set. The scanners that
walk the directory themselves do not use it, so they can report files your `.gitignore`
excludes; bandit, checkov, gitleaks, grype, and trivy do. bandit, checkov, semgrep,
opengrep, grype, syft, and ferret-scan skip ASH's output directories that hold no file
git tracks. checkov gets each of them as a `checkov --skip-path` value, unless
`scanners.checkov.options.skip_ash_output_dir` is `false`. On Windows, ASH passes none,
and it leaves out a directory whose path holds `(` or `)` with a warning; there, add the
directory to `scanners.checkov.options.skip_path`, or move `--output-dir` outside the
source directory. ASH drops what checkov reports in those directories either way.

To drop findings from every scanner, add paths to `global_settings.ignore_paths`. ASH
removes the findings under them after the scan, and actionlint, zizmor, detect-secrets,
ferret-scan, snyk-code, and the converters also skip those files.
bandit skips the ignore paths it can be given as exclude patterns, and ASH drops its
findings under the others afterward. An ignore path stops applying on its `expiration`
date. With `--ignore-suppressions`, ASH gives no scanner or converter the ignore paths and
drops no finding under them. See [Suppress findings](../how-to/suppress-findings.md).

ASH drops the findings scanners report in its output directories, even with
`--ignore-suppressions`, except in files git tracks there and in this scan's
`converted/`. A file a repository commits to one of those directories is scanned and
reported like any other, in this scan's own output directory too:

<!-- doctest: run expect-exit=2 fixture=empty -->
```bash
mkdir -p .ash/ash_output/keep
printf 'DATABASE_PASSWORD = "correct-horse-battery-staple-1234"\n' > .ash/ash_output/keep/tracked.py
git add -f .ash/ash_output/keep/tracked.py
git commit -q -m "Commit a file under the default output directory"
ash scan --scanners detect-secrets
```

detect-secrets reports the password in `.ash/ash_output/keep/tracked.py`, and the scan
exits 2. Outside a git repository, ASH cannot tell a committed file from its own, and
drops every finding in those directories.

`--changed-files-only` drops the findings outside the changed files from every report
after the scan; every scanner still reads its whole input.

## Converted files {#converted-files}

Two converters run before the scanners, and every selected scanner then scans their
output in `converted/` as a second target:

- `archive` extracts `.zip`, `.tar`, and `.gz` files from the scan set. It extracts only
  members with a file extension ASH knows how to scan, compared case-sensitively, so
  files such as `Dockerfile` or `go.mod` inside an archive, and archives inside
  archives, are not extracted. `.tgz`, `.bz2`, `.xz`, `.jar`, and `.whl` files are not
  opened. A `.gz` file whose name does not end in `.tar.gz` and that holds one compressed
  file rather than a tar archive, such as `data.json.gz`, is decompressed and scanned. It is
  a failed input only when it cannot be decompressed (a damaged stream or a bad CRC), and is
  refused when it exceeds an extraction limit or decompresses to an archive name. A `.gz`
  file that is neither gzip nor tar data is skipped. Any other file with one of the three
  extensions that Python cannot read as a zip or tar archive is a failed input.
- `jupyter` converts each `.ipynb` notebook to a script with nbconvert. ASH runs
  nbconvert on a copy of the notebook named `notebook.ipynb`, in a temporary directory
  that holds nothing else, so nbconvert does not pick up a Python module or template
  directory from the repository through its working directory, and a notebook whose
  name contains characters such as `[` or `{` still converts. The copy drops
  `language_info.nbconvert_exporter`, and keeps `language_info.file_extension` only when
  it is a plain extension such as `.r`. The converted file, in `converted/jupyter/`, is
  named after the notebook's path with characters other than letters, digits, and `_`
  replaced, and ends in `-converted.py`, or in `-converted` plus the notebook's plain
  extension, such as `-converted.r`, for a notebook in another language.

semgrep and opengrep scan the converted files. Their default `exclude` option lists
`*-converted.py`, but that entry applies only to the scan of the source tree, where it
keeps a converted copy inside the tree from being scanned twice; on the scan of the
converted files it is left out, and both scanners read files the repository's `.gitignore`
matches there, because the output directory that holds them is ignored by git. An
`exclude` pattern you add yourself applies to both scans. Findings in converted files
point into the output directory, not into the original archive or notebook.
