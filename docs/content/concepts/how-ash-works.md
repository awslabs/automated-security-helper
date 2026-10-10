# How ASH works

ASH runs a set of third-party security scanners over one directory, collects what they report into one results model, writes that model out in several report formats, and returns one exit code. This page explains each of those steps and the rules that connect them.

## Phases

A scan runs up to three phases, always in this order: convert, scan, report. `--phases` runs a subset of them, and `ash report` renders reports again from an existing results file without scanning.

```mermaid
flowchart LR
    src[Source directory] --> convert[Convert phase<br/>archive, jupyter]
    convert --> conv[converted/ target]
    src --> scan
    conv --> scan[Scan phase<br/>scanners in parallel]
    scan --> sarif[Per-scanner SARIF<br/>paths, severity, suppressions]
    sarif --> merged[Aggregated results<br/>one SARIF run]
    merged --> report[Report phase<br/>final suppression pass, reporters]
    report --> out[reports/ash.*]
    report --> code[Exit code]
```

In the convert phase, converters turn files that scanners cannot read into files they can. The archive converter extracts the scannable members of zip and tar archives (`.zip`, `.tar`, `.tar.gz`), and the jupyter converter turns notebooks into scripts with nbconvert. Their output goes to `converted/` in the output directory and becomes a second scan target, `converted`, next to the `source` target. A converter that crashes, or that cannot convert one of its inputs, makes the scan incomplete.

In the scan phase, each selected scanner runs its tool against each target and produces SARIF. ASH rewrites the paths in that SARIF relative to the source directory, maps each result to a severity, applies suppressions and ignore paths, and merges the result into the aggregated SARIF.

In the report phase, ASH applies suppressions once more to the merged SARIF, recomputes the counts, and runs every enabled reporter. Each reporter writes its file under `reports/`, named `ash.<extension>`. A reporter that fails logs an error and writes nothing; it does not change the exit code.

Where the scan runs is a separate choice, the run mode. `local` (the default) runs the scanners installed on the host. `container` builds an image and runs the same scan inside it. `nix` runs it inside `nix develop`, which supplies pinned scanner binaries. `precommit` runs a fixed set of fast scanners (bandit, detect-secrets, checkov, cdk-nag and npm-audit). See [Run ASH in a container](../how-to/run-in-a-container.md) and [Use ASH with pre-commit](../how-to/pre-commit.md).

## How scanners are selected

ASH ships 16 built-in scanners, all enabled by default. For each scanner it knows about, ASH asks these questions in order and records the first answer that stops the scanner:

1. Is it enabled? `scanners.<name>.enabled: false` in the config turns a scanner off. `--scanners` cannot turn it back on; `ash scan --config-overrides scanners.<name>.enabled=true` can.
2. Was it selected? `--scanners` is an allowlist and `--exclude-scanners` removes names from it. A scanner that is not selected is recorded SKIPPED.
3. Does it support this platform? A scanner without a build for the operating system (semgrep and opengrep on Windows) is recorded SKIPPED.
4. Are its dependencies there? A scanner whose tool cannot be found, or is found only inside the scanned directory, is recorded MISSING with the reason.

Scanners outside the built-in set, such as the [community scanners](../plugins/community.md), are only considered when their plugin module is loaded. The [scanner reference](../reference/scanners.md) lists every scanner, its tool and its defaults; [Choose scanners](../how-to/choose-scanners.md) covers turning them on and off.

## How scanners run

With the default `--strategy parallel`, ASH runs scanners in a thread pool of `min(32, CPUs + 4)` workers. Each worker runs one scanner against the source target and then against the converted target when there is one. `--strategy sequential` runs them one at a time.

A scanner receives a directory, not a file list. Most scanners walk that directory themselves. ASH passes the configured ignore paths to every scanner. Some scanners use them to skip files, and ASH applies them again to the results. Each scanner's tool runs as a subprocess. When the [sandbox](sandbox.md) is on, that subprocess runs inside it; ASH's own process does not.

## The results model

The engine writes everything a scan produced to `ash_aggregated_results.json` at the root of the output directory. It holds:

- the resolved configuration the scan used;
- one row per scanner and target, with a status (PASSED, FAILED, ERROR, MISSING or SKIPPED), counts by severity, and the reason a scanner did not run;
- one row per converter, with the inputs it could not convert;
- the aggregated SARIF;
- an SBOM in CycloneDX form when an SBOM scanner ran.

Each scanner's own output is also kept under `scanners/<name>/<target>/`. Every reporter renders this same model. The layout of the output directory is in [Output files](../reference/output-files.md).

The aggregated SARIF has a single run. Each scanner's results are appended to it, and each scanner's tool description and rules are added to `tool.extensions`. Every result carries `scanner_name` in its properties, so you can tell which scanner reported it. A result's severity comes from the scanner's own severity when it reports one, and otherwise from the SARIF level: `error` counts as critical, `warning` as medium and `note` as low.

## Findings are merged, not deduplicated

ASH does not deduplicate findings, within a scan or across shards. When two scanners report the same problem, the results contain two findings, each with its own scanner name and rule id. The default scanner set overlaps in several places:

- semgrep and opengrep both run the `p/ci` ruleset;
- grype and trivy both match dependency manifests against vulnerability advisories;
- detect-secrets and gitleaks both look for secrets;
- several scanners evaluate CloudFormation templates.

This has three consequences. Finding counts are counts of scanner results, not of distinct problems. A suppression that names a `rule_id` matches the rule ids of whichever scanner uses that id, so the same problem reported by another scanner under another id stays unsuppressed; a suppression without `rule_id` covers every rule in its path. And the gate counts every unsuppressed duplicate. If two scanners overlap more than you want, turn one of them off; see [Choose scanners](../how-to/choose-scanners.md). [Suppressions, ignore paths and exclusions](suppressions.md) explains how suppressions match.

Sharding splits a scan by scanner, not by file, so `ash merge` of the shards does not count any finding twice. See [Scale to large repositories](../how-to/scale-large-repos.md).

## Where the exit code comes from

ASH decides the exit code after the report phase, from the scanner rows in the results and the unsuppressed findings in the aggregated SARIF. It checks these conditions in order and returns at the first one that holds:

1. The scan is incomplete and `fail_on_incomplete_scanners` is on (the default): a selected scanner is MISSING or ERROR, every scanner was skipped, or a converter is incomplete. Exit 1.
2. A scanner reported a rule it could not evaluate. Exit 1.
3. A content database is past its age bound and `content_db_staleness` is `fail` (the default). Exit 1. See [Content databases](content-databases.md).
4. `fail_on_findings` is off. Exit 0.
5. At least one unsuppressed finding is at or above the severity threshold that applies to its scanner (the scanner's own `severity_threshold`, else the global one, `MEDIUM` by default). Exit 2.
6. Otherwise, exit 0.

An invalid configuration stops the scan before it starts, with exit 3. Exit 4 is a workspace definition or policy error. Because an incomplete scan is checked first, a scan with a MISSING scanner exits 1 even when it also found something. The full table is in [Exit codes](../reference/exit-codes.md), and [Set the gate](../how-to/set-the-gate.md) shows how to choose what fails a build.

## Plugins

Scanners, reporters and converters are all plugins, and so are event subscribers, which run code on scan events such as a phase starting or a scanner finishing. The built-in plugins live in one package that every scan loads. Other plugin packages, including the community scanners and the AWS reporters that ship with ASH, load only when a plugin module list names them: `ash_plugin_modules` in the config, `--ash-plugin-modules`, or `ASH_PLUGIN_MODULES`. A plugin module is imported into ASH's own process and runs with ASH's access, outside the scanner sandbox; only the subprocesses a scanner starts through ASH are sandboxed. Which config files may name which modules is part of the [trust model](trust-model.md). [Plugins](../plugins/index.md) explains the plugin model and how to write one.
