# cfn-lint and cfn-guard

cfn-lint and cfn-guard are two builtin CloudFormation scanners. Both read the same templates cfn-nag reads, and neither needs network access to scan.

## Enabling it

cfn-lint and cfn-guard are builtin scanners, enabled by default: a default scan runs them. `scanners.cfn-lint.enabled: false` in the ASH config turns one off, and `--scanners` and `--exclude-scanners` select them as they select any scanner. If cfn-guard is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate), as for every builtin scanner. cfn-lint is installed on first use when ASH is online, and is `MISSING` only when that install fails and none is on `PATH`. `ash dependencies install` and the container image provide both.

`--python-only` runs cfn-lint, a Python package ASH runs through uv, and does not run cfn-guard, a native binary.

## cfn-lint

[cfn-lint](https://github.com/aws-cloudformation/cfn-lint) validates AWS CloudFormation templates against the CloudFormation resource schemas and its own rule set: misspelled or invalid properties, values a service rejects, end-of-life Lambda runtimes, unused parameters and similar problems. It checks that a template is correct, not that it is secure, which is why its severities sit below the security scanners' (see the mapping below).

### Installation

cfn-lint is a Python package (MIT-0). ASH installs it with `uv tool install 'cfn-lint[sarif]>=1.43.3,<2.0.0'`, either on first use or ahead of time:

<!-- doctest: illustrative reason="installs cfn-lint from PyPI" -->
```bash
ash dependencies install --tool cfn-lint
```

The `sarif` extra is required; it provides the SARIF output format ASH reads. An existing cfn-lint on `PATH` is used when it satisfies that requirement; without uv, any cfn-lint on `PATH` is used as it is. The ASH container image ships cfn-lint, and the Nix flake supplies nixpkgs' cfn-lint with the `sarif` extra.

### Which files it scans

The same files cfn-nag scans: every `.json`, `.yaml` and `.yml` file in the scan set (after ASH's ignore paths, and the `.gitignore` and `.ignore` files while `honor_ignore_files` is on, the default) that parses as YAML or JSON and has a top-level `Resources` mapping. A file with a `Resources` mapping that ASH cannot model as CloudFormation is reported as a target the scanner could not evaluate, so it counts toward partial coverage instead of disappearing. Templates in the converted target (archives ASH extracted) are scanned too. A template that is a symlink, sits under a symlinked directory, or has more than one hard link is skipped with a warning, because cfn-lint would read it where it points.

### Configuration

```yaml
scanners:
  cfn-lint:
    enabled: true
    options:
      # A .cfnlintrc to use, outside the scanned tree. When unset, ASH gives
      # cfn-lint an empty configuration (see "Configuration files" below).
      config_file: /etc/ash/cfnlintrc
      # Regions to validate against, or [ALL_REGIONS]. When unset, us-east-1 (see
      # "Regions" below).
      regions: [us-east-1, eu-west-1]
      # Rule ids or prefixes to skip everywhere, or to enable (e.g. "I" for
      # informational rules, which cfn-lint does not run by default).
      ignore_checks: [W3005]
      include_checks: [I]
      # Let a template's own Metadata ignore_checks and configure_rules apply
      # (see "Suppressions").
      honor_inline_ignores: false
      # Version constraint for the installed tool.
      tool_version: ">=1.43.3,<2.0.0"
      # Seconds allowed for the uv install of cfn-lint.
      install_timeout: 300
      # Seconds each cfn-lint invocation may run before it is killed (the default;
      # null means no limit).
      scan_timeout: 1800
```

Region names, rule ids and prefixes are validated when the config is loaded, so a value cannot be passed through to cfn-lint as an option of its own.

#### Regions

Some of cfn-lint's checks depend on the region, for example whether a resource type exists there (rule `E3006`). `regions` names the regions to check against. When it is unset, cfn-lint uses the regions a template names in its own `Metadata: cfn-lint: config: regions`, then those in the `config_file` you named, and otherwise us-east-1. On its own, cfn-lint would read `AWS_REGION` and `AWS_DEFAULT_REGION` before falling back to us-east-1. ASH does not let it, so a template gives the same findings on every host: an empty `AWS_REGION`, which a CI job gets from an unset variable, would otherwise make cfn-lint fail on every template.

#### Configuration files

Left to itself, cfn-lint reads a `.cfnlintrc` from the directory it runs in (the scanned repository) and from your home directory. ASH does not let it: unless `config_file` names a file, ASH passes cfn-lint an empty configuration of its own, which it writes outside the scanned tree and removes when the scan ends, and which stops both lookups. A `.cfnlintrc` is not passive settings. Its `append_rules` key names Python files that cfn-lint loads as rules, so a `.cfnlintrc` in the scanned repository would make cfn-lint import and run a rule module from the scanned tree. Its other keys, such as `ignore_checks`, would change what cfn-lint reports without appearing in the ASH config, which is where ASH takes `ignore_checks`, `include_checks` and `regions` from instead.

For the same reason `config_file` is honored only when the operator sets it, through `--config-overrides` or a config file outside the scanned tree, and only for a file outside the scanned tree. A relative `config_file` is taken from the directory of the ASH config file that sets it, or from the working directory for `--config-overrides`, not from the source directory (see [Relative paths in the operator's settings](../../configuration-guide.md#relative-paths-in-the-operators-settings)). A `config_file` from the repository's own `.ash/.ash.yaml`, or one naming a file inside the tree, is ignored with a warning and cfn-lint gets ASH's empty configuration, and so is a path inside the tree that leads out of it through a symbolic link there. A config an MCP client delivered that sets `config_file` is refused, since it is a default `denied_paths` entry. A file you name this way is used with `append_rules` included, and one that does not exist fails the scan. cfn-lint resolves the relative paths in it, such as `append_rules` and `custom_rules` entries, against its working directory rather than the file's directory. ASH runs cfn-lint in a new, empty directory outside the scanned tree that only your user can enter and that is removed after the scan, so a relative path names nothing: neither a file in the scanned repository nor one in a shared directory such as `/tmp`. Write those paths as absolute paths: a relative one makes cfn-lint fail on every template. Under `--sandbox`, a file outside the tree is not mounted unless it is listed in `sandbox.extra_read_paths`.

`tool_version` is appended to the package name when ASH installs cfn-lint, so it must be a version constraint such as `>=1.43.3,<2.0.0`. Anything else, including a direct reference such as `@ file:///...`, is ignored with a warning and the default constraint is used.

`ignore_checks` and `tool_version` are honored only when you set them as the operator, with `--config-overrides` or an ASH config file outside the scanned tree. `ignore_checks` drops findings before ASH sees them, so they are neither reported nor counted as suppressed, and `tool_version` chooses the cfn-lint release that is installed. Set by an ASH config inside the tree, each is ignored with a warning and its default is used; a config an MCP client delivered that sets either is refused, since both are default `denied_paths` entries. To silence a finding in a repository, use an ASH suppression.

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

Package-scoped suppressions do not apply (cfn-lint reports on templates, not packages), and neither do symbol-scoped ones, which target functions and classes in source code. A template's own ignores, `Metadata: cfn-lint: config: ignore_checks` on the template or on a resource, do not apply by default, and neither do the rule settings a template gives in `Metadata: cfn-lint: config: configure_rules`, such as E3031 `exceptions` or E1029 `custom_excludes`. cfn-lint would drop what they hide before ASH sees it, so those findings would appear neither as findings nor in ASH's suppressed counts and unused-suppressions report. ASH passes cfn-lint every rule outside your own `ignore_checks` (and the `ignore_checks` of the `config_file` you named) as mandatory, which cfn-lint applies whatever the template says. To let templates ignore or configure away their own findings, set `honor_inline_ignores: true` as the operator, with `--config-overrides` or an ASH config file outside the scanned tree; set by an ASH config inside the tree it is ignored with a warning.

A template's `ignore_checks` can also reach the template cfn-lint reads after it in the same run. cfn-lint keeps the last template's settings while it reads the next one, and when that one cannot be parsed (duplicate keys, for example) it drops the parse errors (`E0000`) if the kept `ignore_checks` cover them, mandatory or not. A list given on the command line replaces a template's, so ASH always passes `cfn-lint --ignore-checks`: your own ignores, or `W0000` when there are none. No rule has that id, and every rule is mandatory then, which cfn-lint ranks above an ignore, so it ignores nothing. With `honor_inline_ignores: true` ASH passes no placeholder, because it would replace the template-level `ignore_checks` you let in. It runs cfn-lint once per template instead, so a template's ignores apply to that template only. That costs one cfn-lint start-up per template: with cfn-lint 1.57.2, the 8 CloudFormation templates in ASH's own test data took 3.4 s in one run and 12.0 s in eight.

Rule settings need one more step. cfn-lint takes `configure_rules` whole from the first place that sets any: the command line, then the template, then the config file. So ASH passes the `configure_rules` of the `config_file` you named on the command line, one `cfn-lint --configure-rule=RULE:key=value` per setting, and when there are none it passes `E3012:strict=false`, which is E3012's default and changes no finding. Two limits follow from cfn-lint's command-line format. A setting it cannot carry, a list of more than one item or a value containing a comma, a colon or an equals sign, is left out with a warning, and that rule runs with its default; for the built-in rules the default reports at least as much. A `config_file` that sets `merge_configs` fails the scan, because cfn-lint would then merge a template's settings into the command line's. So does a `config_file` that uses a YAML alias: ASH reads the file with aliases refused, as it reads every YAML config, and cfn-lint would read it in full, so ASH could not check what it sets. With `honor_inline_ignores: true`, ASH passes neither, and cfn-lint reads your `config_file` as written, a template's `configure_rules` taking precedence over it.

### Offline use

cfn-lint needs no network to scan. Its resource schemas ship inside the package, and it only downloads updates when asked to (`cfn-lint --update-specs` and similar), which ASH never does. A scan inside a network namespace with no interfaces produced the same results as one with network access. Installing cfn-lint needs network once; in offline mode (`ASH_OFFLINE=true`) a cfn-lint that is not already installed is reported as MISSING with the reason.

### How ASH runs it

```text
cfn-lint --format sarif --output-file=<results> [options] -- <template> ...
```

in a new, empty directory outside the scanned tree, with every path absolute; ASH reports each location relative to the source directory. Template paths are escaped before they are passed, because cfn-lint expands each filename argument as a glob pattern: a template named `a[1].yaml` would otherwise not be linted at all. Long template lists are split across several invocations to stay within command-line length limits. With `honor_inline_ignores: true` each template has an invocation of its own (see "Suppressions").

cfn-lint's exit status is a bitmask of the levels it reported (2 error, 4 warning, 8 informational); any combination of those is a completed run. Other exit statuses, a timeout, missing output, or an `E0003` result mark every template in that invocation as not evaluated, so one such template costs the findings of the others in its batch; with `honor_inline_ignores: true` it costs only its own. The scan then reports partial coverage and exits 1 by default, so nothing is lost silently. The source tree and the converted files are separate targets, and each records the worst exit status of its own invocations.

### License

cfn-lint is MIT-0 (MIT No Attribution). It is installed as a separate tool and is not bundled into ASH's Python package.

## cfn-guard

[AWS CloudFormation Guard](https://github.com/aws-cloudformation/cloudformation-guard) (cfn-guard) evaluates CloudFormation templates against policy-as-code rules written in the Guard DSL. cfn-guard ships no rules of its own, so ASH pins a rule source, the [AWS Guard Rules Registry](https://github.com/aws-cloudformation/aws-guard-rules-registry), and lets you add or substitute your own rules.

### Installation

<!-- doctest: illustrative reason="downloads cfn-guard and its rules bundle" -->
```bash
ash dependencies install --tool cfn-guard
```

installs two pinned artifacts, each verified against a SHA256 recorded in ASH's source (`automated_security_helper/utils/tool_downloads.py`):

- the cfn-guard 3.2.1 release binary for your platform (Linux, macOS and Windows, amd64 and arm64), into `ASH_BIN_PATH`;
- the AWS Guard Rules Registry release 1.0.2 rules archive. Its `output/*.guard` files are extracted into `aws-guard-rules-registry-1.0.2/` under `$ASH_CFN_GUARD_RULES_DIR`, or under `<ASH_BIN_PATH>/../share/cfn-guard-rules` when that is unset, with a `.ash-rules-manifest.json` recording each file's digest.

A download whose bytes do not match the pinned digest is refused. The ASH container image ships both, installed read-only for the scan user: the rules are in `/usr/share/ash/cfn-guard-rules`, which the image checks at build time is owned by root, as is every directory above it. nixpkgs has no cfn-guard package, so the nix flake packages the same pinned release binary (`nix/cfn-guard.nix`), and the nix shell installs the rules bundle into `ASH_CFN_GUARD_RULES_DIR` on first entry, and again on any entry where the bundle there is not the pinned one: after an ASH upgrade that changes the pin, or when a rule file no longer matches its manifest.

Before every scan ASH checks the installed rules against the manifest written at install time: a manifest naming a different pin, or a selected rule-set file that is missing or no longer hashes to what was installed, makes the scanner MISSING with the reinstall command rather than scanning with whatever is left.

### Rule sets

The registry release contains 50 rule-set files: one per compliance framework (CIS AWS Benchmark, NIST 800-53, PCI DSS, HIPAA and others), a Well-Architected Security Pillar set, a Well-Architected Reliability Pillar set, and `guard-rules-registry-all-rules`.

The default is `wa-Security-Pillar`, the registry's mapping of the AWS Well-Architected Security Pillar (45 rules: public access, encryption, logging, TLS, IAM and similar). `guard-rules-registry-all-rules` (67 rules) was considered and not chosen: it adds 22 reliability and operations rules, such as backup plans, Multi-AZ, deletion protection, S3 replication and object lock, and Lambda concurrency, which are not security findings and would fail templates for reasons a security scan should not. The compliance-framework sets are a choice for your own context rather than a default.

```yaml
scanners:
  cfn-guard:
    enabled: true
    options:
      # Bundled registry rule sets, by file name without ".guard".
      rule_sets:
        - wa-Security-Pillar
        - cis-aws-benchmark-level-1
      # Your own .guard files or directories. A relative path is taken from the
      # directory of this config file (from the working directory for
      # --config-overrides). Evaluated in addition to rule_sets; set
      # rule_sets: [] to use only these.
      rules_paths:
        - policy/guard
      # Seconds each per-template cfn-guard run may take.
      scan_timeout: 1800
```

A rule-set name with a `.guard` extension or characters outside letters, digits, `.`, `_` and `-` fails config validation. A well-formed name that is not in the bundle makes the scanner MISSING, with the list of available names.

`rule_sets` is honored only when you set it as the operator, with `--config-overrides` or an ASH config file outside the scanned tree. A narrower set drops findings before ASH sees them: `wa-Reliability-Pillar` alone turns the 24 findings on ASH's test template into 9, losing every public-access, encryption and logging finding. Set by an ASH config inside the tree, or by an MCP client, it is ignored with a warning and `wa-Security-Pillar` is evaluated.

`rules_paths` is honored only when you set it as the operator, with `--config-overrides` or an ASH config file outside the scanned tree; a path the operator names may be inside the scanned tree. A relative entry is taken from the directory of the ASH config file that sets it, or from the working directory for `--config-overrides` (`rules_paths=[...]` or `rules_paths+=<path>`), not from the source directory (see [Relative paths in the operator's settings](../../configuration-guide.md#relative-paths-in-the-operators-settings)). The scanned repository decides what is at such a path, so one that leads out of the tree through a symbolic link in it, to a file or a directory, makes the scanner MISSING and is not read. Set by an ASH config inside the tree, or by an MCP client, it is ignored with a warning, and if `rule_sets` is empty as well, cfn-guard evaluates the default `wa-Security-Pillar` set instead of nothing. cfn-guard prints a rules file it cannot parse, all of it, in its error, so a path the scanned repository chose could otherwise put any file the scan can read into the report.

For a directory, ASH collects the files cfn-guard would read from it: `.guard` and `.ruleset` files at any depth, case-sensitively, not entering symlinked subdirectories. cfn-guard follows a symlinked rules file, so one that resolves outside the directory you named is refused with a warning; a link that stays inside it is read. ASH reads each file itself and gives cfn-guard a copy under the scanner's results directory (`cfn-guard-rules/`), which is also why `rules_paths` needs no sandbox grant. A directory with no rules files selects nothing, and when nothing else is selected the scanner is MISSING ("no cfn-guard rules are selected"): cfn-guard given such a directory would report a clean run. A `rules_paths` entry that does not exist, a named file that is not a regular file, or a subdirectory that cannot be listed also makes the scanner MISSING.

#### Why the rules are not age-checked

ASH holds downloaded content databases (grype's and trivy's vulnerability databases, the offline semgrep and opengrep rulesets) to a maximum age, because those are fetched at build or scan time and can go stale silently. The Guard rules are not declared there. They are a fixed release archive pinned by digest, like the policies inside the pinned checkov package: they change only when ASH changes the pin, and an age bound would measure how recently the same bytes were copied rather than how current the rules are. Release 1.0.2 is the newest the registry has published.

### Which files it scans

The same files cfn-nag and cfn-lint scan: every `.json`, `.yaml` and `.yml` file in the scan set that parses as YAML or JSON and has a top-level `Resources` mapping. A file with a `Resources` mapping that ASH cannot model as CloudFormation is counted as not evaluated.

### Severity mapping

Every failed cfn-guard rule is reported as **HIGH** with SARIF level `error`.

cfn-guard marks every failure `error` and the registry's rules carry no severity of their own, so there is nothing per rule to map from. Every finding is HIGH because a template that violates a rule of the compliance set you chose has failed that control; the default set checks security configuration (public access blocks, encryption, logging, TLS). That includes rules that are less severe in isolation, such as a missing access log: to keep those out, choose a narrower rule set with `options.rule_sets`, or suppress the rule by id. ASH sets `issue_severity` on each result as well as the SARIF level, so the summary, the exit-code gate and every reporter all read HIGH. Adjust what fails the scan with `scanners.cfn-guard.options.severity_threshold`. cfn-guard reports one result per failing clause, so one rule can appear more than once for the same resource. Many rules are in more than one of the registry's rule sets, and cfn-guard reports such a rule's results once for each selected set that holds it; ASH reports each identical result once.

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

<!-- doctest: config kind=other reason="a CloudFormation template fragment" -->
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

One template at a time because one unparseable data file makes cfn-guard exit 255 with no output for the whole invocation, and because cfn-guard writes result locations as absolute paths, which ASH replaces with the repository-relative path of the template it ran. Exit 0 means every rule passed or was skipped and 19 means at least one failed; any other status, a timeout, or a 19 with no results marks that template as not evaluated. As for cfn-lint, the source tree and the converted files each record the worst exit status of their own runs.

### Licenses

cfn-guard and the AWS Guard Rules Registry are both Apache-2.0. Neither is bundled into ASH's Python package; both are downloaded by `ash dependencies install` or shipped in the container image as separate artifacts.
