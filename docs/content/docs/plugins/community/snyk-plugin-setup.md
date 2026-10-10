# Snyk plugin in ASH's CI

This page is for maintainers of the ASH repository. It describes how ASH's own CI handles the [Snyk Code plugin](snyk-plugin.md). To use the plugin in your own scans, see that page.

## What the CI runs

The workflow `.github/workflows/ash-unified-ci.yml` has four "Community Plugins" scan legs, all with `method: python-local` and `config-file: community`, on `ubuntu-latest`, `ubuntu-24.04-arm`, `macos-latest` and `windows-latest`. Each calls the composite action [`.github/actions/run-scan-test`](https://github.com/awslabs/automated-security-helper/blob/main/.github/actions/run-scan-test/action.yml) with `snyk-token: ${{ secrets.SNYK_TOKEN }}`. For these legs the action:

1. installs the community tools: the Snyk CLI with `npm install -g snyk` (up to three attempts), ferret-scan with `pip install` against the version range its plugin declares, and trivy, hadolint and, except on Windows, GuardDog with `ash dependencies install --config .ash/.ash_community_plugins.yaml`;
2. scans with `--config .ash/.ash_community_plugins.yaml --ash-plugin-modules automated_security_helper.plugin_modules.ash_snyk_plugins`, with `SNYK_TOKEN` set from the input.

`.ash/.ash_community_plugins.yaml` is inside the scanned tree, so it cannot load `ash_snyk_plugins` itself; that is why the legs name it on the command line. The file lists the other four community modules, and it disables snyk-code (`scanners.snyk-code.enabled: false`).

So the community legs install the Snyk CLI and load the plugin, but never run a Snyk Code scan, and no source is sent to Snyk. They check that the plugin imports and that its config section is accepted; they do not exercise its scan, including the [known defect](snyk-plugin.md#known-defect) in how it reads Snyk's exit code.

## The `SNYK_TOKEN` secret

The token is a GitHub Actions repository secret named `SNYK_TOKEN`, holding a Snyk API token. To set or rotate it, create a token in your Snyk account settings, then in the GitHub repository open **Settings**, **Secrets and variables**, **Actions**, and add or update the repository secret `SNYK_TOKEN`.

Because no leg runs a Snyk Code scan, the legs pass whether or not the secret is set. GitHub does not give secrets to workflows that a pull request from a fork triggers, so on those the input is empty.

If snyk-code is ever enabled in `.ash/.ash_community_plugins.yaml`, the legs will upload the repository's source to Snyk with this token, a pull request's changes included, and with the defect above any Snyk finding will fail the leg with exit code 1.
