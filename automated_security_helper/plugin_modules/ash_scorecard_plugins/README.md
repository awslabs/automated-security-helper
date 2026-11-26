# OpenSSF Scorecard alpha scanner plugin

[OpenSSF Scorecard](https://github.com/ossf/scorecard) (Apache-2.0) rates the security posture of an open-source project's repository with eighteen checks in v5.7.0, among them branch protection, code review, pinned dependencies, token permissions and signed releases, each scored 0 to 10.

> **Read this first: it scores the origin repository, not your checkout.** Scorecard reads the repository as GitHub hosts it. Local edits, unpushed commits and the files ASH scans do not change the result. A clean checkout of a poorly protected repository still reports findings. Every finding's message says so.

## Opt-in and fail-closed

The scanner is **disabled by default** and needs a network and a GitHub token. Turn it on once the module is listed:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_scorecard_plugins
scanners:
  scorecard:
    enabled: true
```

It refuses to run, and the scan reports why, when:

- ASH is offline;
- none of `GITHUB_AUTH_TOKEN`, `GITHUB_TOKEN`, `GH_AUTH_TOKEN` or `GH_TOKEN` is set (Scorecard has no token flag);
- no `github.com` repository can be determined: set `scanners.scorecard.options.repo` (`owner/name`), or have an `origin` remote in the source directory's `.git/config`. Other hosts are not supported.

## Installing

```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_scorecard_plugins"]' --tool scorecard
```

This installs the pinned Scorecard release (v5.7.0, checked against its SHA256). If `scorecard` is already on `PATH`, ASH uses it.

## Severity

| Check score | ASH severity | SARIF level |
|---|---|---|
| 0 to 2 | HIGH | error |
| 3 to 5 | MEDIUM | warning |
| 6 to 9 | LOW | note |
| 10 | not a finding | |
| -1 (inconclusive) | not a finding, logged | |

## Suppressions

Every result's location is the repository, `github.com/<owner>/<name>`, not a file. Suppress a check with its name as `rule_id` (such as `Branch-Protection`) and that repository as `path`.

## Documentation

See <https://awslabs.github.io/automated-security-helper/docs/plugins/alpha/scorecard-plugin/>.
