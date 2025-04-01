# Automated Security Helper - CHANGELOG
- [v2.0.1](#v201)
    - [What's Changed](#whats-changed)
- [v2.0.0](#v200)
    - [Breaking Changes](#breaking-changes)
    - [Features](#features)
    - [Fixes](#fixes)
- [v1.5.1](#v151)
    - [What's Changed](#whats-changed-1)
- [v1.5.0](#v150)
    - [What's Changed](#whats-changed-2)
    - [New Contributors](#new-contributors)
- [v1.4.1](#v141)
    - [What's Changed](#whats-changed-3)
- [v1.4.0](#v140)
    - [What's Changed](#whats-changed-4)
- [v1.3.3](#v133)
    - [What's Changed](#whats-changed-5)
- [v1.3.2](#v132)
    - [What's Changed](#whats-changed-6)
    - [New Contributors](#new-contributors-1)
- [1.3.0 - 2024-04-17](#130---2024-04-17)
    - [Features](#features-1)
    - [Fixes](#fixes-1)
    - [Maintenance / Internal](#maintenance--internal)
- [1.2.0-e-06Mar2024](#120-e-06mar2024)
- [1.1.0-e-01Dec2023](#110-e-01dec2023)
- [1.0.9-e-16May2023](#109-e-16may2023)
- [1.0.8-e-03May2023](#108-e-03may2023)
- [1.0.5-e-06Mar2023](#105-e-06mar2023)
- [1.0.1-e-10Jan2023](#101-e-10jan2023)

## v2.0.1

### What's Changed

- Fix handling of Bandit config files in util script

## v2.0.0

### Breaking Changes

- Building ASH images for use in CI platforms (or other orchestration platforms that may require elevated access within the container) now requires targeting the `ci` stage of the `Dockerfile`:

_via `ash` CLI_

```sh
ash --no-run --build-target ci
```

_via `docker` or other OCI CLI_

```sh
docker build --tag automated-security-helper:ci --target ci .
```

### Features

- Run ASH as non-root user to align with security best practices.
- Create a CI version of the docker file that still runs as root to comply with the different requirements from building platforms where UID/GID cannot be modified and there are additional agents installed at runtime that requires elevated privileges.

### Fixes

- Offline mode now skips NPM/PNPM/Yarn Audit checks (requires connection to registry to pull package information)
- NPM install during image build now restricts available memory to prevent segmentation fault

**Full Changelog**: https://github.com/awslabs/automated-security-helper/compare/v1.5.1...v2.0.0

## v1.5.1

### What's Changed

- Fix SHELL directive in Dockerfile
- Fix small items in Mkdocs config

**Full Changelog**: https://github.com/awslabs/automated-security-helper/compare/v1.5.0...v1.5.1

## v1.5.0

### What's Changed

- Introduced support for offline execution via `--offline`

### New Contributors
* @awsmadi made their first contribution in https://github.com/awslabs/automated-security-helper/pull/104

**Full Changelog**: https://github.com/awslabs/automated-security-helper/compare/v1.4.1...v1.5.0

## v1.4.1

### What's Changed

- Fixed line endings on relevant files from CRLF to LF to resolve Windows build issues

## v1.4.0

### What's Changed

- Adds `--format` parameter to `ash`/`ash-multi` scripts to enable additional output integrations, beginning with ASHARP (Automated Security Helper Aggregated Report Parser) as the intermediary data model to enable subsequent conversion from there.
- Adds `automated_security_helper` Python code as a module of the same name from within new `src` directory, including poetry.lock and pyproject.toml files to support. This module includes the `asharp` script (CLI tool) that enabled programmatic parsing of the aggregated_results content in conjunction with the JSON output changes.
- Adds pre-stage build of `automated_security_helper` module to Dockerfile
- Adds support to handle when `--format` is a value other than the current default of `text` so scanners switch output to programmatically parseable output formats and `asharp` is called to parse the `aggregated_results.txt` file into `aggregated_results.txt.json`.
- Moved source of version string truth into `pyproject.toml` for all projects, removed `__version__` file to coincide with this.

**Full Changelog**: https://github.com/awslabs/automated-security-helper/compare/v1.3.3...v1.4.0

## v1.3.3

### What's Changed
* fix(ash): adjust where/when output-dir is created, if necessary by @climbertjh2 in https://github.com/awslabs/automated-security-helper/pull/74
* fix(ash): set execute permission on ash script in the container by @climbertjh2 in https://github.com/awslabs/automated-security-helper/pull/81
* fix: update __version__ file to match release tag format in github.com by @climbertjh2 in https://github.com/awslabs/automated-security-helper/pull/84


**Full Changelog**: https://github.com/awslabs/automated-security-helper/compare/v1.3.2...v1.3.3

## v1.3.2

### What's Changed
* added get-scan-set.py to utils scripts to return a list of non-ignored files for processing by @scrthq in https://github.com/awslabs/automated-security-helper/pull/47
* fix/codebuild shared bindmount issue by @scrthq in https://github.com/awslabs/automated-security-helper/pull/49
* fix error in reflecting return code in ash script by @climbertjh2 in https://github.com/awslabs/automated-security-helper/pull/51
* Issue 58: missing double quotes by @awsntheule in https://github.com/awslabs/automated-security-helper/pull/64
* fixed cdk nag scanner, added unique stack names based on input filenames. corrected guards on git clone calls within the scanner scripts to ensure those happen in the container image by @scrthq in https://github.com/awslabs/automated-security-helper/pull/54
* Add support for pnpm audit by @awsntheule in https://github.com/awslabs/automated-security-helper/pull/66
* fix(cdk-nag-scan): copy output files to separate folders by @climbertjh2 in https://github.com/awslabs/automated-security-helper/pull/69
* fix(ash): use /tmp rather than tmpfs for scratch area by @climbertjh2 in https://github.com/awslabs/automated-security-helper/pull/73
* Fix CTRL-C cancelling by @awsntheule in https://github.com/awslabs/automated-security-helper/pull/71

### New Contributors
* @awsntheule made their first contribution in https://github.com/awslabs/automated-security-helper/pull/64

**Full Changelog**: https://github.com/awslabs/automated-security-helper/compare/1.2.0-e-06Mar2024...v1.3.2

## 1.3.0 - 2024-04-17

### Features

* New version scheme introduced, moving ASH to SemVer alignment for versioning releases
* Moved version number to standalone `__version__` file for easier version maintainability
* Added [ripgrep](https://github.com/BurntSushi/ripgrep) to replace `grep` on the `cdk-docker-execute.sh` script for speed as well as to respect `.gitignore`/`.ignore` file specifications automatically. Implemented `ripgrep` for the intended purposes.
* Updated `cdk-docker-execute.sh` script to create a unique internal stack name per imported-and-scanned CloudFormation template.

### Fixes

* Removed extraneous `git clone` calls into the temporary `${_ASH_RUN_DIR}` now that single container is the primary use case to prevent collisions and spending time on repeat tasks during scans.

### Maintenance / Internal

* Added better support for debug logging via `--debug` flag.
* Added new `debug_show_tree` function to `utils/common.sh` for easy debugging insertion of a tree call at any point in the scan to see repository contents
* Improved functionality of `utils/get-scan-set.py` script to generate the ignore spec and initial scan set to file in the output directory

## 1.2.0-e-06Mar2024

* Changes default base image in the root Dockerfile from `public.ecr.aws/bitnami/python:3.10` to `public.ecr.aws/docker/library/python:3.10-bullseye` to allow builds for linux/arm64 platforms to work
* `ash` script has been renamed to `ash-multi` if multi-container architecture is needed from local. When running in the single-container, this is copied in as `ash` itself and becomes the entrypoint of the in-container run to prevent API changes for CI invocations.
* New `ash` script for local invocation entrypoint is now defaulting to building the single-container image and running the scan within as normal
* Printed output path of the `aggregated_results.txt` now shows the correct, local output path when using the single container instead of `/out/aggregated_results.txt`
* Updated GitHub Actions workflow for the repo to invoke ASH using the `ash` script as well to validate the entire experience end-to-end
* Deprecated `--finch|-f` option with warning indicating to use `--oci-runner finch|-o finch` if needing to use Finch explicitly

## 1.1.0-e-01Dec2023

* Introduced single-container architecture via single Dockerfile in the repo root
    * Updated `utils/*.sh` and `ash` shell scripts to support running within a single container
    * Added new `ash_helpers.{sh,ps1}` scripts to support building and running the new container image
* Changed CDK Nag scanning to use TypeScript instead of Python in order to reduce the number of dependencies
* Changed identification of files to scan from `find` to `git ls-files` for Git repositories in order to reduce the number of files scanned and to avoid scanning files that are not tracked by Git
* Updated the multi-container Dockerfiles to be compatible with the script updates and retain backwards compatibility
* Updated ASH documentation and README content to reflect the changes and improve the user experience
* Added simple image build workflow configured as a required status check for PRs

## 1.0.9-e-16May2023

* Changed YAML scanning (presumed CloudFormation templates) to look for CloudFormation template files explicitly, and excluding some well known folders
added additional files that checkov knows how to scan to the list of CloudFormation templates (Dockerfiles, .gitlab-ci.yml)
* Re-factored CDK scanning in several ways:
    * Moved Python package install to the Dockerfile (container image build) so it's done once
    * Removed code that doesn't do anything
    * Added diagnostic information to report regarding the CDK version, Node version, and NPM packages installed.
* Fixed Semgrep exit code

## 1.0.8-e-03May2023

* Cloud9 Quickstart
* Remove cdk virtual env
* README reformat
* Pre-commit hook guidance
* Fix Grype error code
* Minor bug fixes

<!-- CHANGELOG SPLIT MARKER -->

## 1.0.5-e-06Mar2023

* hardcoded Checkov config
* Fix return code for the different Docker containers
* Fix image for ARM based machines
* Added Finch support

<!-- CHANGELOG SPLIT MARKER -->

## 1.0.1-e-10Jan2023

ASH version 1.0.1-e-10Jan2023 is out!

* Speed - running time is shorter by 40-50%
* Frameworks support - we support Bash, Java, Go and C## code
* New tool - ASH is running [Semgrep](https://github.com/returntocorp/semgrep) for supported frameworks
* Force scans for specific frameworks - You can use the `--ext` flag to enforce scan for specific framework
For example: `ash --source-dir . --ext py` (Python)
* Versioning - use `ash --version` to check your current version
* Bug fixes and improvements

<!-- CHANGELOG SPLIT MARKER -->
