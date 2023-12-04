# 1.1.0-e-01Dec2023
### Automated Security Helper
* Introduced single-container architecture via single Dockerfile in the repo root
    * Updated `utils/*.sh` and `ash` shell scripts to support running within a single container
    * Added new `ash_helpers.{sh,ps1}` scripts to support building and running the new container image
* Changed CDK Nag scanning to use TypeScript instead of Python in order to reduce the number of dependencies
* Changed identification of files to scan from `find` to `git ls-files` for Git repositories in order to reduce the number of files scanned and to avoid scanning files that are not tracked by Git
* Updated the multi-container Dockerfiles to be compatible with the script updates and retain backwards compatibility
* Updated ASH documentation and README content to reflect the changes and improve the user experience
* Added simple image build workflow configured as a required status check for PRs

# 1.0.9-e-16May2023
### Automated Security Helper

* Changed YAML scanning (presumed CloudFormation templates) to look for CloudFormation template files explicitly, and excluding some well known folders
added additional files that checkov knows how to scan to the list of CloudFormation templates (Dockerfiles, .gitlab-ci.yml)
* Re-factored CDK scanning in several ways:
    * Moved Python package install to the Dockerfile (container image build) so it's done once
    * Removed code that doesn't do anything
    * Added diagnostic information to report regarding the CDK version, Node version, and NPM packages installed.
* Fixed Semgrep exit code

# 1.0.8-e-03May2023
### Automated Security Helper

* Cloud9 Quickstart
* Remove cdk virtual env
* README reformat
* Pre-commit hook guidance
* Fix Grype error code
* Minor bug fixes

<!-- CHANGELOG SPLIT MARKER -->

# 1.0.5-e-06Mar2023
### Automated Security Helper

* hardcoded Checkov config
* Fix return code for the different Docker containers
* Fix image for ARM based machines
* Added Finch support

<!-- CHANGELOG SPLIT MARKER -->

# 1.0.1-e-10Jan2023
### Automated Security Helper
ASH version 1.0.1-e-10Jan2023 is out!

* Speed - running time is shorter by 40-50%
* Frameworks support - we support Bash, Java, Go and C# code
* New tool - ASH is running [Semgrep](https://github.com/returntocorp/semgrep) for supported frameworks
* Force scans for specific frameworks - You can use the `--ext` flag to enforce scan for specific framework
For example: `ash --source-dir . --ext py` (Python)
* Versioning - use `ash --version` to check your current version
* Bug fixes and improvements

<!-- CHANGELOG SPLIT MARKER -->
