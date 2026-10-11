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
| Java, Go, Ruby, C#, PHP, and other languages | semgrep, opengrep, as far as their rules cover the language | snyk-code |
| Python dependencies (`requirements.txt`, lockfiles) | grype, trivy, syft | trivy-repo |
| npm, Yarn, and pnpm dependencies | npm-audit, grype, trivy, syft | trivy-repo |
| Other dependency manifests and lockfiles (`go.mod`, `pom.xml`, and the others grype and trivy recognize) | grype, trivy, syft | trivy-repo |
| Your own package's manifest (`setup.py`, `pyproject.toml`, `package.json`, `go.mod`, `*.gemspec`, `Cargo.toml`) | | guarddog |
| CloudFormation templates | cfn-nag, cfn-lint, cfn-guard, cdk-nag, checkov | trivy-repo |
| AWS CDK apps | the CloudFormation scanners, on the templates `cdk synth` writes to `cdk.out`; the source-code scanners on the app code | trivy-repo |
| Terraform | checkov | trivy-repo |
| Kubernetes manifests and the other formats checkov supports | checkov | trivy-repo |
| Dockerfiles | checkov | hadolint, trivy-repo |
| GitHub Actions workflows | actionlint, zizmor, checkov | |
| Composite actions (`action.yml`) | zizmor | guarddog |
| Secrets, in any file | detect-secrets, gitleaks | ferret-scan (sensitive data), trivy-repo |
| A software bill of materials | syft | |
| Jupyter notebooks | every scanner that reads the converted script (see [Converted files](#converted-files)) | |
| `.zip`, `.tar`, and `.gz` archives | every scanner that reads the extracted files (see [Converted files](#converted-files)) | |

For a CDK app, synthesize before you scan, so that `cdk.out` holds the templates. If your
root `.gitignore` excludes `cdk.out`, cfn-nag, cfn-lint, cfn-guard, and cdk-nag do not
see them, and checkov does; see
[What decides the files](#what-decides-the-files).

## By scanner {#by-scanner}

"Whole directory" means the tool walks the source directory itself and applies its own
rules for which files to read. "Selected files" means ASH picks the files and passes
them to the tool.

| Scanner | Type | What it reads | `--python-only` | `--mode precommit` |
|---|---|---|---|---|
| actionlint | IaC | Selected files: GitHub Actions workflows | no | no |
| bandit | SAST | Whole directory: Python files, skipping `.venv/`, `venv/`, and `node_modules/` | yes | yes |
| cdk-nag | IaC | Selected files: CloudFormation templates | yes | yes |
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
| ferret-scan | Secrets | Whole directory, including files `.gitignore` excludes | yes | no |
| guarddog | SCA | Selected files: a copy of each package root (see [Dependencies](#dependencies)) | yes | no |
| hadolint | IaC | Selected files: Dockerfiles | no | no |
| snyk-code | SAST | Whole directory, sent to Snyk's service | yes | no |
| trivy-repo | SAST | Whole directory: `trivy repository` with the vulnerability, secret, misconfiguration, and license scanners | no | no |

`--python-only` runs only the scanners marked yes and reports the rest `SKIPPED`. A
scanner marked no whose tool is not installed is reported `MISSING` instead, which makes
the scan exit 1; add it to `--exclude-scanners`. ferret-scan and snyk-code run under
`--python-only` although they start external programs.

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

### Dependencies {#dependencies}

npm-audit finds each `package.json` and audits the first lockfile beside it of
`yarn.lock`, `pnpm-lock.yaml`, and `package-lock.json`, with `yarn`, `pnpm`, or `npm`. A
`package.json` with no lockfile is not audited. If `yarn` or `pnpm` is not installed,
that lockfile is skipped with a warning. With no lockfile anywhere, npm-audit reports
`PASSED`.

grype and trivy read the source directory themselves, so they find every manifest and
lockfile their own catalogers recognize. trivy runs only its vulnerability scanner
unless you set `scanners.trivy.options.scanners`. syft builds the SBOM from the same
kind of catalog and reports no findings.

guarddog checks your own package for signs of malicious code: it scans each package root
it finds, `setup.py`, `setup.cfg`, or `pyproject.toml` (PyPI), `package.json` (npm),
`go.mod` (Go), `action.yml` or `action.yaml` (GitHub Actions), `*.gemspec` (RubyGems),
and `Cargo.toml` (crates). It checks your dependency manifests and lockfiles only with
`scanners.guarddog.options.verify: true`, which downloads every dependency.

### Dockerfiles

hadolint reads files named `Dockerfile` or `Containerfile`, and names matching
`*.Dockerfile` or `Dockerfile.*`, case-sensitively, except `*.dockerignore`. With none,
it reports `SKIPPED`.

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
  `/node_modules/aws-cdk` (which also matches `aws-cdk-lib`). The `*.template.json` exception does not help when the root
  `.gitignore` excludes a whole directory such as `cdk.out`: ASH then skips the
  directory, and only the scanners that walk the directory themselves, such as
  checkov, see the templates in it.
- `node_modules`, `.venv`, and `venv` stay in the scan set. bandit, checkov, zizmor, and
  guarddog skip them on their own.

The scanners marked "Selected files" above read only the scan set. The scanners that
walk the directory themselves do not use it, so they can report files your `.gitignore`
excludes; bandit, checkov, gitleaks, grype, and trivy do.

To drop findings from every scanner, add paths to `global_settings.ignore_paths`. ASH
removes the findings under them after the scan, and actionlint, zizmor, detect-secrets,
hadolint, guarddog, and the converters also skip those files. bandit still reads them,
and ASH drops its findings there afterward. See
[Suppress findings](../how-to/suppress-findings.md).

Findings inside the output directory are dropped, except in `converted/`.
`--changed-files-only` also filters findings after the scan; every scanner still reads
its whole input.

## Converted files {#converted-files}

Two converters run before the scanners, and every selected scanner then scans their
output in `converted/` as a second target:

- `archive` extracts `.zip`, `.tar`, and `.gz` files from the scan set. It extracts only
  members with a file extension ASH knows how to scan, compared case-sensitively, so
  files such as `Dockerfile` or `go.mod` inside an archive, and archives inside
  archives, are not extracted. `.tgz`, `.bz2`, `.xz`, `.jar`, and `.whl` files are not
  opened.
- `jupyter` converts each `.ipynb` notebook to a script with nbconvert.

semgrep and opengrep exclude `*-converted.py`, so they do not scan converted notebooks.
Findings in converted files point into the output directory, not into the original
archive or notebook.
