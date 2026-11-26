# OpenSSF Scorecard Plugin

[OpenSSF Scorecard](https://github.com/ossf/scorecard) (Apache-2.0) rates the security posture of an open-source repository with a set of automated checks (Branch-Protection, Code-Review, Pinned-Dependencies, Token-Permissions, SAST and others), each scored from 0 (worst) to 10 (best).

!!! warning "It scores the origin repository, not your checkout"
    Scorecard reads the repository as GitHub hosts it. Local edits, unpushed commits and the files ASH scans do not change the result, and a clean checkout of a poorly protected repository still reports findings. ASH runs it as `scorecard --repo`, never as `scorecard --local`, and every finding's message says what it scored.

## Enabling

Its module is loaded only when you list it, and the scanner stays **off until you enable it**, because it needs a network and a GitHub token:

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_scorecard_plugins
scanners:
  scorecard:
    enabled: true
```

With the module listed and the scanner enabled, `scorecard` runs once per scan. `--scanners` and `--exclude-scanners` select it as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

### When it refuses to run

Like the `snyk-code` scanner, it fails closed and says why:

- ASH is offline (its offline strategy is skip-offline).
- None of `GITHUB_AUTH_TOKEN`, `GITHUB_TOKEN`, `GH_AUTH_TOKEN` or `GH_TOKEN` is set. Scorecard has no token flag; these are the variables its documentation names.
- No `github.com` repository can be determined. ASH uses the `repo` option, else the `origin` remote in `<source>/.git/config`. Any other host is refused.
- `<source>/.git/config` is not read. ASH reads it in its own process, so it reads it only when it is a regular file inside the source directory: a symbolic link at `.git` or at `config`, a FIFO or device, a file with a second hard link, and a file larger than 1 MiB are refused, and the message names the reason. Set the `repo` option instead.

An MCP client cannot configure the scanner at all: its whole section, `/scanners/scorecard/**`, is denied to a client whatever a profile's `denied_paths` says, as for every scanner that can send data off the host. Otherwise a client could turn it on and set `repo` to any repository the GitHub token in ASH's environment can read, and get that repository's findings back.

## Installing Scorecard

ASH pins Scorecard v5.7.0 in the plugin's own install module (`ash_scorecard_plugins/scorecard_install.py`: the version, one release asset per platform, a SHA256 for each archive and for the executable inside it, taken from the release's `scorecard_checksums.txt`). Install it with:

<!-- doctest: illustrative reason="downloads a release binary" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_scorecard_plugins"]' --tool scorecard
```

A download that does not hash to its pin is refused. If `scorecard` is already on `PATH`, ASH uses it. The ASH container image installs it the same way.

## What is scanned

ASH runs `scorecard --repo=github.com/<owner>/<name> --format=json --show-details` once per scan, with the working directory at the source directory, and converts the JSON on stdout to SARIF. The converted-target pass does not run it again. A result's location is the repository (`github.com/<owner>/<name>`), since the checks do not point at files. The aggregate score is kept in the run properties and is not a finding.

## Configuration

```yaml
# .ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_scorecard_plugins
scanners:
  scorecard:
    enabled: true
    options:
      # owner/name, github.com/owner/name or an https URL. Unset: the origin remote.
      repo: null
      # Seconds for the whole scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override, or null for the global threshold.
      severity_threshold: null
```

## Severity

Scorecard's checks measure how a project is run, not whether code is exploitable, so the ceiling is HIGH. `issue_severity` and the SARIF level come from one table.

| Check score | ASH severity | SARIF level |
|---|---|---|
| 0 to 2 | HIGH | error |
| 3 to 5 | MEDIUM | warning |
| 6 to 9 | LOW | note |
| 10 | not a finding | |
| -1 (inconclusive) | not a finding; named in the log | |

## Failures

Any exit code other than 0, a timeout, empty output, output that is not JSON or not a Scorecard result, and a check with no name or a score outside -1 to 10 all fail the scan rather than read as clean. Scorecard v5.7.0 exits 1 when one of its checks fails at run time, even though it still prints the rest of its result; ASH fails that scan instead of reporting a partial result. Scorecard's stderr is not copied into the scan errors.

## Suppressions

Every result's location is the repository it scored, `github.com/<owner>/<name>`. Suppress a check with its name as `rule_id` (such as `Branch-Protection`) and that repository as `path`. Line ranges do not apply, because a result has no lines, and package-scoped and symbol-scoped suppressions do not apply either.

## Offline and air-gapped use

Scorecard calls the GitHub API, so it does not run offline.

## License

Scorecard is Apache-2.0 licensed. The ASH container image redistributes the pinned release binary, so it carries the repository `LICENSE` at the pinned commit beside it (the `scorecard` entry in `THIRD_PARTY_LICENSES`; the release archives' own `LICENSE` is byte-identical to that file; see [third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses)). Nothing of Scorecard is shipped in the ASH Python package itself.
