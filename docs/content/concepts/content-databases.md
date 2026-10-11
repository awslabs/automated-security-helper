# Content databases

Some scanners compare your code against data they download: vulnerability advisories, or a set of rules. ASH calls that data a content database. A scan can only find what its databases know about, so after every scanner that reads one, ASH checks how old the database is and, by default, fails the scan when it is older than its bound.

## Which scanners use one

| Database | Read by | Age bound | Where the bound comes from | Age read from |
|---|---|---|---|---|
| `grype-db` | grype | 5 days (120 hours) | grype's own default for `db.max-allowed-built-age` | `built` in `grype db status -o json` |
| `trivy-db` | trivy, trivy-repo | 24 hours | trivy's own rule for its official database: current until the next scheduled update, 24 hours after it was built | `VulnerabilityDB.UpdatedAt` in `trivy version --format json` |
| `semgrep-offline-rules` | semgrep, offline only | 30 days | ASH's choice | the time in `.ash-rules-fetched-at` in the rules cache, else the oldest rules file's modification time |
| `opengrep-offline-rules` | opengrep, offline only | 30 days | ASH's choice | the same |

The bounds are fixed: no config key, variable, or flag changes them. Online, semgrep and opengrep download their ruleset at scan time, so there is no local copy to age. checkov, npm-audit, and syft are declared as having no content database: checkov's policies ship inside the checkov package ASH installs, npm-audit asks the npm registry at scan time, and syft only catalogs packages. trivy's Java database is never downloaded (ASH tells trivy to skip it), and trivy's misconfiguration checks bundle is refreshed but not age-checked.

## Why a stale database fails the scan

A clean result from an old database is not evidence that the code is clean: every advisory or rule published since the database was built is missing from the scan. An offline scan makes this worse, because the tools themselves stop checking. ASH runs grype offline with grype's age validation turned off, and trivy with database updates skipped, so that an air-gapped host can scan at all. ASH's check after the scan is then the only limit on the database's age.

A database whose age cannot be read counts as stale, for example when the probe fails or the cache holds no database. A scanner that did not run at all (MISSING) has no database reading; it fails the scan as incomplete instead.

## What happens when a database is stale

With `content_db_staleness: fail`, the default, ASH keeps the scan's findings, logs an error that names the database, its age, and how to refresh it, adds an `ASH-CONTENT-DB-STALE` notification at level `error` to the SARIF, and exits 1. That happens whatever `fail_on_findings` says.

With `content_db_staleness: warn`, ASH logs a warning, adds the same notification at level `warning`, and lets the scan pass or fail on its findings. The reports carry the notification, so a reader can see the scan ran against an old database.

There are three ways to change the default:

- `content_db_staleness: warn` for every database;
- a `content_db_staleness_overrides` entry for one database, which needs an expiration date and a reason and stops applying at 00:00 UTC on that date;
- `--allow-stale-content-db` or `--no-allow-stale-content-db` on the command line. Either one wins over the config file and clears every per-database override: the first sets `warn`, the second `fail`.

Every reading, fresh or stale, is recorded in the results. On the CLI, a repository's own config can set `content_db_staleness: warn`; pass your own config with `--config`, or `--no-allow-stale-content-db`, to keep `fail`. A config an MCP client delivers may not change either setting under the default policy. See [Configuration trust model](trust-model.md).

## Where the databases are cached

ASH resolves one cache directory per tool and passes the same directory to the scan, the refresh, and the age check. It always names that directory to the tool (`GRYPE_DB_CACHE_DIR` for grype, `trivy --cache-dir` for trivy), so a `db.cache-dir` in a grype config is ignored with a warning, and a `cache.dir` in a trivy config is overridden.

| Tool | Linux | macOS | Windows |
|---|---|---|---|
| grype | `$GRYPE_DB_CACHE_DIR`, else `$XDG_CACHE_HOME/grype/db`, else `~/.cache/grype/db` | `$GRYPE_DB_CACHE_DIR`, else `$XDG_CACHE_HOME/grype/db`, else `~/Library/Caches/grype/db` | `%GRYPE_DB_CACHE_DIR%`, else `%XDG_CACHE_HOME%\grype\db`, else `%LOCALAPPDATA%\cache\grype\db` |
| trivy | `$TRIVY_CACHE_DIR`, else `$XDG_CACHE_HOME/trivy`, else `~/.cache/trivy` | `$TRIVY_CACHE_DIR`, else `~/Library/Caches/trivy` | `%TRIVY_CACHE_DIR%`, else `%LOCALAPPDATA%\trivy` |

`XDG_CACHE_HOME` counts only when it is an absolute path. For trivy on Linux, a relative value sends the cache to `$TMPDIR/trivy`. The ASH container image sets `GRYPE_DB_CACHE_DIR=/deps/.grype` and `TRIVY_CACHE_DIR=/deps/.trivy`. The offline semgrep and opengrep rules are read from the directories `SEMGREP_RULES_CACHE_DIR` and `OPENGREP_RULES_CACHE_DIR` name; the image sets them to `/deps/.semgrep` and `/deps/.opengrep`.

## When ASH refreshes a database

ASH has no command that refreshes a database on its own. Refreshes happen inside online scans:

- trivy and trivy-repo: before every online scan, ASH downloads trivy's database (and, when the scan includes misconfiguration checks, the checks bundle), once per scan, then tells trivy not to update during the scan.
- grype: under the sandbox, ASH runs `grype db update` before the scan. Without the sandbox, grype updates its own database when it is older than the 120-hour bound, which ASH passes to it.

When ASH runs a refresh itself (trivy's before every online scan, grype's under the sandbox), it runs outside the scanner sandbox, with network, from a working directory outside the scanned tree, and with ASH's empty tool configuration. For trivy, a `trivy.yaml` that the operator names in the trivy or trivy-repo scanner's `config_file` option, outside every git checkout and the scanned directory, is used instead, so a database mirror set there applies. A refresh holds a lock in the cache directory, so two scanners, or on Linux and macOS two scans, do not run ASH's refresh at once, and it times out after 900 seconds. A failed refresh fails that scanner. For a repository you do not trust, scan in local mode with the sandbox on, as in [Scan a repository you do not trust](../docs/scanner-sandbox.md#untrusted).

The age checks are protected the same way: each probe runs with ASH's empty tool configuration from outside the scanned tree, so a configuration file in the repository cannot point the probe at a different database from the one the scan read.

Offline, nothing is refreshed. The databases must already be in the cache: `ash build-image --offline` builds an image with current grype and trivy databases and the semgrep and opengrep rulesets (`p/ci` by default), in which every scan runs offline. On a host you can run `grype db update` and `trivy image --download-db-only` while online. Because each bound counts from when the database itself was built, an offline image starts failing trivy scans within a day of the image build, and grype scans within five days, unless you rebuild it or relax the policy. [Run ASH offline](../how-to/run-offline.md) covers seeding the caches and choosing a rebuild cadence.
