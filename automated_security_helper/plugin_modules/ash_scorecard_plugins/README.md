# ASH scorecard Plugin

[OpenSSF Scorecard](https://github.com/ossf/scorecard) rates the security posture of an open-source project's repository: branch protection, code review, pinned dependencies, token permissions, signed releases, and about twenty more checks, each scored 0 to 10.

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

ASH has no pinned download for Scorecard, so `ash dependencies install` cannot provide it. Install a release from <https://github.com/ossf/scorecard/releases> and put `scorecard` on `PATH`.

## Severity

| Check score | ASH severity | SARIF level |
|---|---|---|
| 0 to 2 | HIGH | error |
| 3 to 5 | MEDIUM | warning |
| 6 to 9 | LOW | note |
| 10 | not a finding | |
| -1 (inconclusive) | not a finding, logged | |

## Documentation

See [the plugin page](https://awslabs.github.io/automated-security-helper/docs/plugins/community/scorecard-plugin/).
