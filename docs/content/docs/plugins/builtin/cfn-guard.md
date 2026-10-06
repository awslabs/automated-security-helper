# cfn-guard scanner (opt-in)

[AWS CloudFormation Guard](https://github.com/aws-cloudformation/cloudformation-guard) (cfn-guard) evaluates CloudFormation templates against policy-as-code rules written in the Guard DSL. cfn-guard ships no rules of its own, so ASH pins a rule source, the [AWS Guard Rules Registry](https://github.com/aws-cloudformation/aws-guard-rules-registry), and lets you add or substitute your own rules.

## Enabling it

cfn-guard is off until you turn it on. A scanner that is not enabled leaves no trace in a scan: it is not run, and it does not appear in the results, summaries or reports.

```yaml
scanners:
  cfn-guard:
    enabled: true
```

or for one run:

```bash
ash scan --scanners cfn-guard
ash scan --config-overrides 'scanners.cfn-guard.enabled=true'
```

Naming it in `--scanners` runs it even if the config says `enabled: false`; `--exclude-scanners cfn-guard` wins over both. Once enabled, a missing binary or missing rules are reported as MISSING with the reason, and the scan exits 1 unless you pass `--no-fail-on-incomplete-scanners`.

The config ASH records in `ash_aggregated_results.json` lists cfn-guard only when its config differs from the default (enabled, or options changed). A run that enables it only through `--scanners` still reports its results and status; the recorded config just shows no `cfn-guard` entry.

## Installation

```bash
ash dependencies install --tool cfn-guard
```

installs two pinned artifacts, each verified against a SHA256 recorded in ASH's source (`automated_security_helper/utils/tool_downloads.py`):

- the cfn-guard 3.2.1 release binary for your platform (Linux, macOS and Windows, amd64 and arm64), into `ASH_BIN_PATH`;
- the AWS Guard Rules Registry release 1.0.2 rules archive, extracted into `$ASH_CFN_GUARD_RULES_DIR`, or `<ASH_BIN_PATH>/../share/cfn-guard-rules` when that is unset.

A download whose bytes do not match the pinned digest is refused. The ASH container image ships both, installed read-only for the scan user. nixpkgs has no cfn-guard package, so `--mode nix` does not supply it; install it with the command above.

Before every scan ASH checks the installed rules against the manifest written at install time: a rules file that is missing, or no longer hashes to what was installed, makes the scanner MISSING with the reinstall command rather than scanning with whatever is left.

## Rule sets

The registry release contains 50 rule-set files: one per compliance framework (CIS AWS Benchmark, NIST 800-53, PCI DSS, HIPAA and others), a Well-Architected Security Pillar set, a Well-Architected Reliability Pillar set, and `guard-rules-registry-all-rules`.

The default is `wa-Security-Pillar`, the registry's mapping of the AWS Well-Architected Security Pillar (44 rules: public access, encryption, logging, TLS, IAM and similar). `guard-rules-registry-all-rules` (66 rules) was considered and not chosen: it adds 22 reliability and operations rules, such as backup plans, Multi-AZ, deletion protection, S3 replication and object lock, and Lambda concurrency, which are not security findings and would fail templates for reasons a security scan should not. The compliance-framework sets are a choice for your own context rather than a default.

```yaml
scanners:
  cfn-guard:
    enabled: true
    options:
      # Bundled registry rule sets, by file name without ".guard".
      rule_sets:
        - wa-Security-Pillar
        - cis-aws-benchmark-level-1
      # Your own .guard files or directories, relative to the source directory.
      # Evaluated in addition to rule_sets; set rule_sets: [] to use only these.
      rules_paths:
        - policy/guard
      scan_timeout: 1800
```

An unknown rule-set name is reported with the list of available names.

### Why the rules are not age-checked

ASH holds downloaded content databases (grype's and trivy's vulnerability databases, the offline semgrep and opengrep rulesets) to a maximum age, because those are fetched at build or scan time and can go stale silently. The Guard rules are not declared there. They are a fixed release archive pinned by digest, like the policies inside the pinned checkov package: they change only when ASH changes the pin, and an age bound would measure how recently the same bytes were copied rather than how current the rules are. Release 1.0.2 is the newest the registry has published.

## Which files it scans

The same files cfn-nag and cfn-lint scan: every `.json`, `.yaml` and `.yml` file in the scan set that parses as YAML or JSON and has a top-level `Resources` mapping. A file with a `Resources` mapping that ASH cannot model as CloudFormation is counted as not evaluated.

## Severity mapping

Every failed cfn-guard rule is reported as **MEDIUM** with SARIF level `warning`.

cfn-guard marks every failure `error` and the registry's rules carry no severity of their own, so there is nothing per rule to map from. MEDIUM fails a scan at ASH's default threshold, which is right for the security configuration the default set checks, without claiming that a missing access log is as severe as a publicly writable bucket. Adjust with `scanners.cfn-guard.options.severity_threshold`. cfn-guard reports one result per failing clause, so one rule can appear more than once for the same resource.

## Suppressions

ASH suppressions apply by `rule_id`, `path`, and `line_start`/`line_end`. Each result is located at the line cfn-guard reports, usually the resource's `Properties`, so a line-scoped suppression names that line:

```yaml
global_settings:
  suppressions:
    - rule_id: S3_BUCKET_LOGGING_ENABLED
      path: templates/logging-bucket.yaml
      reason: This bucket is the access-log destination.
```

Package-scoped and symbol-scoped suppressions do not apply to templates. The registry's rules also honor cfn-guard's own in-template suppression, which never reaches ASH:

```yaml
Resources:
  LogBucket:
    Type: AWS::S3::Bucket
    Metadata:
      guard:
        SuppressedRules:
          - S3_BUCKET_LOGGING_ENABLED
```

## Offline use

cfn-guard needs no network to scan: the binary is static and the rules are local files. A scan inside a network namespace with no interfaces produced the same results. If the binary or the rules are missing in an air-gapped environment, the scanner is MISSING with the reason; nothing is fetched at scan time.

## How ASH runs it

Once per template:

```text
cfn-guard validate --rules=<rules file>... --data=<template> \
  --output-format=sarif --structured --show-summary=none
```

One template at a time because one unparseable data file makes cfn-guard exit 255 with no output for the whole invocation, and because cfn-guard writes result locations as absolute paths, which ASH replaces with the repository-relative path of the template it ran. Exit 0 means every rule passed or was skipped and 19 means at least one failed; any other status, a timeout, or a 19 with no results marks that template as not evaluated.

## Licenses

cfn-guard and the AWS Guard Rules Registry are both Apache-2.0. Neither is bundled into ASH's Python package; both are downloaded by `ash dependencies install` or shipped in the container image as separate artifacts.
