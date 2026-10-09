# cfn-lint and cfn-guard

cfn-lint and cfn-guard are two builtin CloudFormation scanners. Both read the same templates cfn-nag reads, and neither needs network access to scan.

## Enabling it

cfn-lint and cfn-guard are builtin scanners, enabled by default: a default scan runs them. `scanners.cfn-lint.enabled: false` in the ASH config turns one off, and `--scanners` and `--exclude-scanners` select them as they select any scanner. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate), as for every builtin scanner; `ash dependencies install` and the container image provide it.

## cfn-lint

[cfn-lint](https://github.com/aws-cloudformation/cfn-lint) validates AWS CloudFormation templates against the CloudFormation resource schemas and its own rule set: misspelled or invalid properties, values a service rejects, end-of-life Lambda runtimes, unused parameters and similar problems. It checks that a template is correct, not that it is secure, which is why its severities sit below the security scanners' (see the mapping below).

### Installation

cfn-lint is a Python package (MIT-0). ASH installs it with `uv tool install 'cfn-lint[sarif]>=1.43.3,<2.0.0'`, either on first use or ahead of time:

```bash
ash dependencies install --tool cfn-lint
```

The `sarif` extra is required; it provides the SARIF output format ASH reads. An existing cfn-lint on `PATH` is used when it satisfies that requirement. The ASH container image ships cfn-lint, and the Nix flake supplies nixpkgs' cfn-lint with the `sarif` extra.

### Which files it scans

The same files cfn-nag scans: every `.json`, `.yaml` and `.yml` file in the scan set (after ASH's ignore paths and `.gitignore`) that parses as YAML or JSON and has a top-level `Resources` mapping. A file with a `Resources` mapping that ASH cannot model as CloudFormation is reported as a target the scanner could not evaluate, so it counts toward partial coverage instead of disappearing.

### Configuration

```yaml
scanners:
  cfn-lint:
    enabled: true
    options:
      # A .cfnlintrc to use, outside the scanned tree. When unset, ASH gives
      # cfn-lint an empty configuration (see "Configuration files" below).
      config_file: /etc/ash/cfnlintrc
      # Regions to validate against. Defaults to cfn-lint's own default (us-east-1).
      regions: [us-east-1, eu-west-1]
      # Rule ids or prefixes to skip everywhere, or to enable (e.g. "I" for
      # informational rules, which cfn-lint does not run by default).
      ignore_checks: [W3005]
      include_checks: [I]
      # Version constraint for the installed tool.
      tool_version: ">=1.43.3,<2.0.0"
      # Seconds before cfn-lint is killed.
      scan_timeout: 1800
```

Region names, rule ids and prefixes are validated when the config is loaded, so a value cannot be passed through to cfn-lint as an option of its own.

#### Configuration files

Left to itself, cfn-lint reads a `.cfnlintrc` from the directory it runs in (the scanned repository) and from your home directory. ASH does not let it: unless `config_file` names a file, ASH passes cfn-lint an empty configuration of its own, which stops both lookups. A `.cfnlintrc` is not passive settings. Its `append_rules` key loads Python files as rules, which runs them during the scan, and `ignore_checks: [E, W]` turns every finding off without anything showing up in ASH's suppression reporting. In a repository whose changes you scan before trusting them, such as a pull request in CI, that is code execution and a silent bypass.

For the same reason `config_file` is honored only when the operator sets it, through `--config-overrides` or a config file outside the scanned tree, and only for a file outside the scanned tree. A `config_file` from the repository's own `.ash/.ash.yaml`, or one naming a file inside the tree, is ignored with a warning and cfn-lint gets ASH's empty configuration. A file you name this way is used with `append_rules` included.

`tool_version` is appended to the package name when ASH installs cfn-lint, so it must be a version constraint such as `>=1.43.3,<2.0.0`. Anything else, a direct reference such as `@ file:///...` included, fails config validation.

### Severity mapping

cfn-lint classifies every rule by the first letter of its id. ASH maps that letter to an ASH severity and sets the SARIF level to match, so every report agrees:

| cfn-lint rule | Meaning                                                       | ASH severity | SARIF level |
|---------------|---------------------------------------------------------------|--------------|-------------|
| `E....`       | The template is invalid or will fail to deploy                | MEDIUM       | `warning`   |
| `W....`       | Best-practice or hygiene problem                               | LOW          | `note`      |
| `I....`       | Informational (only with `include_checks: [I]`)                | INFO         | `none`      |

These sit below the severities of security scanners on purpose. At ASH's default threshold (MEDIUM) an invalid template fails the scan and a warning does not. Raise or lower that per scanner with `scanners.cfn-lint.options.severity_threshold`. cfn-lint's own class is never lost: it is the first character of the rule id.

`E0003` is not reported as a finding. cfn-lint uses it for its own configuration errors, including a template path it could not open, so ASH counts the affected templates as not evaluated.

### Suppressions

ASH suppressions apply to cfn-lint findings by `rule_id`, `path`, and `line_start`/`line_end`:

```yaml
global_settings:
  suppressions:
    - rule_id: E2533
      path: templates/legacy.yaml
      line_start: 14
      line_end: 14
      reason: The function is pinned to this runtime until it is retired.
```

Package-scoped suppressions do not apply (cfn-lint reports on templates, not packages), and neither do symbol-scoped ones, which target functions and classes in source code. cfn-lint's own template-level controls also work, for example `Metadata: cfn-lint: config: ignore_checks: [W2001]` on a resource. ASH does not see findings that cfn-lint suppressed itself, so these do not appear in ASH's suppressed counts or its unused-suppressions report; treat them like inline `nosec` comments when reviewing changes.

### Offline use

cfn-lint needs no network to scan. Its resource schemas ship inside the package, and it only downloads updates when asked to (`--update-specs` and similar), which ASH never does. A scan inside a network namespace with no interfaces produced the same results as one with network access. Installing cfn-lint needs network once; in offline mode (`ASH_OFFLINE=true`) a cfn-lint that is not already installed is reported as MISSING with the reason.

### How ASH runs it

```text
cfn-lint --format sarif --output-file=<results> [options] -- <template> ...
```

from the source directory, with template paths relative to it, so the SARIF locations are repository-relative. Template paths are escaped before they are passed, because cfn-lint expands each filename argument as a glob pattern: a template named `a[1].yaml` would otherwise not be linted at all. Long template lists are split across several invocations to stay within command-line length limits.

cfn-lint's exit status is a bitmask of the levels it reported (2 error, 4 warning, 8 informational); any combination of those is a completed run. Other exit statuses, a timeout, missing output, or an `E0003` result mark every template in that invocation as not evaluated, so one such template costs the findings of the others in its batch. The scan then reports partial coverage and exits 1 by default, so nothing is lost silently.

### License

cfn-lint is MIT-0 (MIT No Attribution). It is installed as a separate tool and is not bundled into ASH's Python package.

## cfn-guard

[AWS CloudFormation Guard](https://github.com/aws-cloudformation/cloudformation-guard) (cfn-guard) evaluates CloudFormation templates against policy-as-code rules written in the Guard DSL. cfn-guard ships no rules of its own, so ASH pins a rule source, the [AWS Guard Rules Registry](https://github.com/aws-cloudformation/aws-guard-rules-registry), and lets you add or substitute your own rules.

### Installation

```bash
ash dependencies install --tool cfn-guard
```

installs two pinned artifacts, each verified against a SHA256 recorded in ASH's source (`automated_security_helper/utils/tool_downloads.py`):

- the cfn-guard 3.2.1 release binary for your platform (Linux, macOS and Windows, amd64 and arm64), into `ASH_BIN_PATH`;
- the AWS Guard Rules Registry release 1.0.2 rules archive, extracted into `$ASH_CFN_GUARD_RULES_DIR`, or `<ASH_BIN_PATH>/../share/cfn-guard-rules` when that is unset.

A download whose bytes do not match the pinned digest is refused. The ASH container image ships both, installed read-only for the scan user. nixpkgs has no cfn-guard package, so the nix flake packages the same pinned release binary (`nix/cfn-guard.nix`), and the nix shell installs the rules bundle into `ASH_CFN_GUARD_RULES_DIR` on first entry.

Before every scan ASH checks the installed rules against the manifest written at install time: a rules file that is missing, or no longer hashes to what was installed, makes the scanner MISSING with the reinstall command rather than scanning with whatever is left.

### Rule sets

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

`rules_paths` is honored only when you set it as the operator, with `--config-overrides` or an ASH config file outside the scanned tree. Set by an ASH config inside the tree, or by an MCP client, it is ignored with a warning. cfn-guard prints a rules file it cannot parse, all of it, in its error, so a path the scanned repository chose could otherwise put any file the scan can read into the report.

#### Why the rules are not age-checked

ASH holds downloaded content databases (grype's and trivy's vulnerability databases, the offline semgrep and opengrep rulesets) to a maximum age, because those are fetched at build or scan time and can go stale silently. The Guard rules are not declared there. They are a fixed release archive pinned by digest, like the policies inside the pinned checkov package: they change only when ASH changes the pin, and an age bound would measure how recently the same bytes were copied rather than how current the rules are. Release 1.0.2 is the newest the registry has published.

### Which files it scans

The same files cfn-nag and cfn-lint scan: every `.json`, `.yaml` and `.yml` file in the scan set that parses as YAML or JSON and has a top-level `Resources` mapping. A file with a `Resources` mapping that ASH cannot model as CloudFormation is counted as not evaluated.

### Severity mapping

Every failed cfn-guard rule is reported as **HIGH** with SARIF level `error`.

cfn-guard marks every failure `error` and the registry's rules carry no severity of their own, so there is nothing per rule to map from. Every finding is HIGH because a template that violates a rule of the compliance set you chose has failed that control; the default set checks security configuration (public access blocks, encryption, logging, TLS). That includes rules that are less severe in isolation, such as a missing access log: to keep those out, choose a narrower rule set with `options.rule_sets`, or suppress the rule by id. ASH sets `issue_severity` on each result as well as the SARIF level, so the summary, the exit-code gate and every reporter all read HIGH. Adjust what fails the scan with `scanners.cfn-guard.options.severity_threshold`. cfn-guard reports one result per failing clause, so one rule can appear more than once for the same resource.

### Suppressions

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

### Offline use

cfn-guard needs no network to scan: the binary is static and the rules are local files. A scan inside a network namespace with no interfaces produced the same results. If the binary or the rules are missing in an air-gapped environment, the scanner is MISSING with the reason; nothing is fetched at scan time.

### How ASH runs it

Once per template:

```text
cfn-guard validate --rules=<rules file>... --data=<template> \
  --output-format=sarif --structured --show-summary=none
```

One template at a time because one unparseable data file makes cfn-guard exit 255 with no output for the whole invocation, and because cfn-guard writes result locations as absolute paths, which ASH replaces with the repository-relative path of the template it ran. Exit 0 means every rule passed or was skipped and 19 means at least one failed; any other status, a timeout, or a 19 with no results marks that template as not evaluated.

### Licenses

cfn-guard and the AWS Guard Rules Registry are both Apache-2.0. Neither is bundled into ASH's Python package; both are downloaded by `ash dependencies install` or shipped in the container image as separate artifacts.
