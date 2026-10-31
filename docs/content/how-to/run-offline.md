# Run ASH offline

In offline mode ASH installs nothing and runs every scanner in its offline mode, apart
from npm-audit, which cannot run offline. Scanners
that need vulnerability data read it from a local cache, and ASH fails the scan when a
cache is past its age bound: a clean result from a stale database is not evidence of a
clean target. Offline mode does not remove the network itself, and detect-secrets can still
make requests (see [What each scanner does offline](#scanners)); only the sandbox, or
container mode with `--offline`, takes the network away. [Content databases](../concepts/content-databases.md) explains
the bounds; this page is about preparing for them.

## Turn on offline mode

Pass `--offline` to a scan:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan --offline --scanners detect-secrets
```

This scan runs offline as usual; in a repository with a hardcoded password it exits 2.
The log also shows a warning for each scanner whose offline cache is not set up, such as
`Grype offline mode: the database directory <path> does not exist`, naming the cache
grype would read (`GRYPE_DB_CACHE_DIR`, else grype's default cache directory).

The other ways to turn it on:

| How | Scope |
|---|---|
| `ASH_OFFLINE=YES` (also `TRUE` or `1`) in the environment | Every ASH run that inherits it. `--offline` in local mode sets it for one scan and restores it afterward. |
| `ash scan --mode container --offline` | Builds an offline image and runs it with no network. See [the offline image](#offline-image). |
| `--mode nix` | Always offline. |
| `scanners.<name>.options.offline: true` | That scanner only. `false`, the default, follows ASH and cannot give a scanner network while ASH is offline. npm-audit's option does not run it offline: it makes npm-audit MISSING, or SKIPPED in a project without a lockfile, as below. |

There is no config key for offline mode. `build.build_mode` exists in the config schema but has no effect.

## What each scanner does offline {#scanners}

| Scanner | Offline behavior |
|---|---|
| grype | Reads its cached database with updates and grype's own age check off. ASH fails the scan when the database is past its age bound ([Refresh cadence](#refresh)). |
| trivy, trivy-repo | Read the cached trivy database with its updates off. ASH fails the scan when the database is past its age bound, except in the offline image, where it warns ([Refresh cadence](#refresh)). With no database, `trivy` is MISSING. Every trivy scan gets `trivy --offline-scan`, so trivy contacts no package registry. trivy does not check for a newer release either: an online scan gets `--skip-version-check`, and an offline one gets `TRIVY_SKIP_VERSION_CHECK=true` in trivy's environment instead, since a trivy too old to know the flag refuses the command over it. |
| semgrep, opengrep | Run the rulesets in `SEMGREP_RULES_CACHE_DIR` or `OPENGREP_RULES_CACHE_DIR` plus ASH's bundled rules, instead of the configured registry rulesets. MISSING when the directory is unset or empty. ASH fails the scan when the rulesets are past their age bound. |
| detect-secrets | Runs as usual. If its settings turn on detect-secrets' verification filter, it still sends each candidate secret to the service that issued it, to check whether it is live; under the sandbox, leave detect-secrets out of `sandbox.network_scanners` to stop that. |
| checkov | Uses the policies in the installed package and skips platform downloads. |
| npm-audit | Does not run: npm, yarn, and pnpm audit a lockfile by asking the registry. MISSING for a project with a `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, or `pnpm-lock.yaml` beside a `package.json`, which fails the scan, and SKIPPED for a project with none. |
| syft | Skips its update check. |
| zizmor | Runs offline, as it does by default. |
| snyk-code | Does not run. |
| bandit, cdk-nag, cfn-nag, cfn-lint, cfn-guard, actionlint, gitleaks | No change, once installed. |

Offline, ASH also skips every tool install. A scanner whose tool is not already on the
machine is MISSING, and a MISSING scanner fails the scan by default.

An offline scan of a project with a lockfile reports npm-audit MISSING and exits 1:

<!-- doctest: run expect-exit=1 -->
```bash
mkdir -p js-app
printf '{"name": "js-app", "version": "1.0.0"}\n' > js-app/package.json
printf '{"name": "js-app", "version": "1.0.0", "lockfileVersion": 3, "packages": {}}\n' > js-app/package-lock.json
ash scan --offline --scanners npm-audit --source-dir js-app --output-dir js-app-results
```

To scan such a project offline, leave npm-audit out with `--exclude-scanners npm-audit`.

## Prepare a host for offline scans {#prepare}

Do this while the host still has network access:

1. Install the scanner tools with `ash dependencies install`. It puts grype and trivy in
   `~/.ash/bin` (or the directory `ASH_BIN_PATH` names), which ASH searches but which is
   not on your `PATH`.
2. Download each database into the cache the scan will read. Set the cache variables
   the same way for the download and for every scan; when they are unset, grype and
   trivy use their platform defaults (for example `~/.cache/grype/db` and `~/.cache/trivy`
   on Linux):

    <!-- doctest: illustrative reason="downloads the grype and trivy databases from the network" -->
    ```bash
    export GRYPE_DB_CACHE_DIR="$HOME/ash-cache/grype" TRIVY_CACHE_DIR="$HOME/ash-cache/trivy"
    "${ASH_BIN_PATH:-$HOME/.ash/bin}/grype" db update
    "${ASH_BIN_PATH:-$HOME/.ash/bin}/trivy" image --download-db-only --cache-dir "$TRIVY_CACHE_DIR"
    ```

3. For semgrep and opengrep, download the rulesets into `SEMGREP_RULES_CACHE_DIR` and
   `OPENGREP_RULES_CACHE_DIR` and record the download time, as described in
   [Seeding the semgrep and opengrep rule cache](../docs/advanced-usage.md#seeding-the-semgrep-and-opengrep-rule-cache).
   Without a recorded time, ASH takes the age of the oldest rules file.

If you also run scanners in the sandbox ([Enable the scanner sandbox](../docs/scanner-sandbox.md)),
semgrep and opengrep can read only the directories the sandbox mounts. Keep the rules
cache under a system directory such as `/opt`, or add it to `sandbox.extra_read_paths` in
a config file outside every git checkout ([Who may grant](../docs/scanner-sandbox.md#who-may-grant)) or with `--config-overrides`. Then check that a
sandboxed offline scan of a file with a known finding reports it.

## The offline image {#offline-image}

`ash build-image --offline` and `ash scan --mode container --offline` build the image with
`OFFLINE=YES`. The build needs network access: it downloads the grype database, the trivy
database, and the semgrep rulesets named by `--offline-semgrep-rulesets` (default `p/ci`),
copies the rulesets for opengrep, and fails if any of them is empty. The image has
`ASH_OFFLINE` set, so every scan in it runs offline. npm-audit cannot run in it; see
[What each scanner does offline](#scanners).

Without `--force`, an offline build downloads the databases and rulesets once per UTC
day: later offline builds that day come from the build cache, and the first one on a
new day downloads again and re-runs the install steps that follow the download, so it
needs network access. With `--force`, which builds without the layer cache, every build
downloads them.
The same holds for `./ash --offline` and `Invoke-ASH -Offline`. Container mode builds the image before every scan unless you pass
`--no-build`, so on a host without network access, scan with the image you moved there:

<!-- doctest: illustrative reason="needs a container runtime and an offline image built elsewhere" -->
```bash
ash scan --mode container --offline --no-build
```

The image has to carry the name ASH runs, `automated-security-helper:<target>`, or the
one `ASH_IMAGE_NAME` names.

Offline and online builds share one tag, `automated-security-helper:<target>`, so building
one replaces the other. Set `ASH_IMAGE_NAME` to keep both. `--offline-semgrep-rulesets`
only affects the image build; it does nothing in local mode.

## Refresh cadence {#refresh}

ASH measures the grype and trivy databases from the time they were built upstream, which
is before you download them, and the rulesets from the time they were downloaded:

| Database | Name in the config | Bound | Refresh |
|---|---|---|---|
| grype | `grype-db` | 120 hours | `grype db update`, or rebuild the offline image |
| trivy | `trivy-db` | 24 hours | `trivy image --download-db-only`, or rebuild the offline image |
| semgrep rulesets | `semgrep-offline-rules` | 30 days | Download again, or rebuild the offline image |
| opengrep rulesets | `opengrep-offline-rules` | 30 days | Download again, or rebuild the offline image |

The trivy bound is the shortest. On an offline host, refresh the trivy cache more than once
a day, or exclude trivy with `--exclude-scanners trivy`. An offline image holds `trivy-db`
to `warn` by default, so its trivy scans keep passing after the first day and the reports
record the stale database; rebuild the image as often as you want trivy's findings current,
and more often than every 5 days for grype, whose bound also counts from before the image
build. A second rebuild on the same UTC day reuses that day's databases unless you pass
`--force`. The bounds are fixed in the code; no setting changes
them. When ASH cannot read a database's age at all, it counts the database as stale.

Under `fail`, a stale database fails the scan with exit code 1 and a message that names the database,
its build time, its age, and the bound. The findings are kept in the reports.

## Allow a stale database {#allow-stale}

`content_db_staleness: warn` lets a scan pass against a stale database and records the
warning in the reports. In the offline image, `trivy-db` is already held to `warn`; set
`content_db_staleness_offline_image_default: false` to make a stale trivy database fail the
scan there too ([Content databases](../concepts/content-databases.md#what-happens-when-a-database-is-stale)). To relax one database for a limited time, add an entry with an
expiration date and a reason:

<!-- doctest: config kind=ash -->
```yaml
content_db_staleness: fail
content_db_staleness_overrides:
  - database: trivy-db
    policy: warn
    expiration: "2027-06-30"
    reason: Air-gapped runners get a new image weekly until the mirror is ready.
```

The entry applies until 00:00 UTC on its expiration date, then ASH ignores it and logs a
warning. Quote the date: an unquoted date makes the whole config invalid.

For one scan, `--allow-stale-content-db` sets `warn` and `--no-allow-stale-content-db`
sets `fail`. Either form also clears every `content_db_staleness_overrides` entry for that
scan and turns the offline image's `trivy-db` default off.

Who can relax the policy depends on where the setting comes from:

- A config file inside a git checkout or the scanned directory, such as a repository's own,
  cannot relax it: ASH keeps `content_db_staleness: warn` or a `policy: warn` entry from
  such a file only when it equals yours, drops any other, and says so in a warning. It
  keeps a stricter `fail`. Relax the policy with `--allow-stale-content-db`,
  `--config-overrides`, or a config file outside every git checkout and the scanned
  directory.
- A config file that an MCP client delivers cannot set either key under the server's
  default policy.

[Set the gate](set-the-gate.md) covers the other settings that decide the exit code.
