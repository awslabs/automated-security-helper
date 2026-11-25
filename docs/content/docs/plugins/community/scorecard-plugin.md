# OpenSSF Scorecard (community plugin)

[OpenSSF Scorecard](https://github.com/ossf/scorecard) rates the security posture of an open-source repository with a set of automated checks (Branch-Protection, Code-Review, Pinned-Dependencies, Token-Permissions, SAST and others), each scored from 0 (worst) to 10 (best).

!!! warning "It scores the origin repository, not your checkout"
    Scorecard reads the repository as GitHub hosts it. Local edits, unpushed commits and the files ASH scans do not change the result, and a clean checkout of a poorly protected repository still reports findings. ASH runs it with `--repo`, never with `--local`, and every finding's message says what it scored.

## Enabling it

Scorecard is a community plugin that ships with ASH. Its module is loaded only when you list it, and the scanner stays **off until you enable it**, because it needs a network and a GitHub token.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_scorecard_plugins
scanners:
  scorecard:
    enabled: true
```

<!-- doctest: illustrative reason="runs a full scan against the GitHub API, which needs a token and network" -->
```bash
# For one run, with a token in the environment
GITHUB_TOKEN="<your token>" ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_scorecard_plugins
```

### When it refuses to run

Like the `snyk-code` scanner, it fails closed and says why:

- ASH is offline (`offline_strategy` is skip-offline).
- None of `GITHUB_AUTH_TOKEN`, `GITHUB_TOKEN`, `GH_AUTH_TOKEN` or `GH_TOKEN` is set. Scorecard has no token flag; these are the variables its documentation names.
- No `github.com` repository can be determined. ASH uses the `repo` option, else the `origin` remote in `<source>/.git/config`. Any other host is refused.

## Installing Scorecard

ASH does not download Scorecard: it has no pinned release entry for it, so `ash dependencies install` cannot provide it. Install a release from the [Scorecard releases page](https://github.com/ossf/scorecard/releases) and put `scorecard` on `PATH`. Until it is there the scanner reports itself as missing.

## What is scanned

ASH runs `scorecard --repo=github.com/<owner>/<name> --format=json --show-details` once per scan, with the working directory at the source directory, and converts the JSON on stdout to SARIF. The converted-target pass does not run it again. A result's location is the repository (`github.com/<owner>/<name>`), since the checks do not point at files. The aggregate score is kept in the run properties and is not a finding.

## Configuration

```yaml
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

Any exit code other than 0, a timeout, empty output, output that is not JSON or not a Scorecard result, and a check with no name or a score outside -1 to 10 all fail the scan rather than read as clean. Scorecard's stderr is not copied into the scan errors.

## Suppressions

Use ASH suppressions by rule (`rule_id` is the check name, such as `Branch-Protection`). Path and line suppressions do not apply, because a result has no file location. Package-scoped and symbol-scoped suppressions do not apply either.

## Offline and air-gapped use

Scorecard calls the GitHub API, so it does not run offline.

## License

Scorecard is licensed under Apache-2.0. See [third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses).
