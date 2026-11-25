# SpotBugs with Find Security Bugs (community plugin)

[SpotBugs](https://spotbugs.github.io/) is a static analyzer for JVM bytecode. [Find Security Bugs](https://find-sec-bugs.github.io/) is a SpotBugs plugin that adds the security detectors: injection, XML external entities, unsafe deserialization, weak cryptography, path traversal and more, for Java, Kotlin, Scala and Groovy code. ASH runs `spotbugs -textui` over the compiled classes and archives in the scan target and keeps the security results. ASH pins SpotBugs 4.10.5 and Find Security Bugs 1.14.0.

## Enabling it

SpotBugs is a community plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_spotbugs_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_spotbugs_plugins
```

With the module listed, `spotbugs` runs by default, like every other scanner. `scanners.spotbugs.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners spotbugs` without the module listed is refused, with a message naming the module to add. If the tool is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

No license or account is needed, and nothing in this plugin is gated behind an opt-in beyond listing the module.

## Installing SpotBugs

SpotBugs is a Java program: it needs a Java runtime (`JAVA_HOME`, or `java` on `PATH`), and ASH does not install one.

- **Local mode:** `ash dependencies install --tool spotbugs`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_spotbugs_plugins"]'`), downloads the SpotBugs 4.10.5 release archive from GitHub and the Find Security Bugs 1.14.0 jar from Maven Central, checks each against the SHA256 digest pinned in ASH, extracts SpotBugs to `spotbugs-4.10.5` in the ASH bin directory, puts the plugin jar in its `plugin` directory, and links `spotbugs` in the bin directory to the launcher script. Linux and macOS on x86_64 and arm64 are supported; Windows is not.
- **Container mode and Nix mode:** the image and the flake do not supply SpotBugs. Install it with `ash dependencies install`, or have a SpotBugs installation on `PATH`.
- Any `spotbugs` already on `PATH` is also used, but it must have the Find Security Bugs jar in the `plugin` directory of its installation. A run whose report does not list Find Security Bugs as loaded fails, with the install command in the message, instead of passing with the security detectors missing.

## What is scanned

SpotBugs reads bytecode, not source. The scanner looks in the target for compiled code and hands SpotBugs what it finds:

- every `.jar`, `.war` and `.ear` file, as it is;
- every directory of `.class` files, as the class root: the directory that holds the top of the package tree, worked out from the package name inside the class file (`target/classes` for `target/classes/org/example/App.class`).

A tree with none of these has nothing for SpotBugs to read. The scanner then does not start SpotBugs and logs one INFO line saying so. That is not a failure and not a finding. ASH does not compile your code: build first, then scan, or scan the build output directory.

Links are never followed and never inputs. ASH's own output directory inside the tree is skipped. A jar or class directory in the tree that holds libraries (a `lib/` directory) is analyzed as your code, and its findings are reported; narrow the scan target to your own build output to avoid that.

SpotBugs prints source-style paths such as `org/example/App.java`, not the class file or archive it read. When exactly one source file in the tree ends with that path, ASH rewrites the result to it, so suppressions and reports point at a real file. When none or more than one match, the path stays as SpotBugs wrote it.

SpotBugs can report that it needed classes it did not find (the libraries your code calls, which are not in the scan). That is normal for an application, the run still succeeds, and findings that depend on those classes can be missed.

## Configuration

```yaml
scanners:
  spotbugs:
    enabled: true
    options:
      # The lowest confidence reported: high, medium or low. medium is SpotBugs's own default.
      confidence: medium
      # Analysis effort: min, less, default, more or max. max finds more and can need more memory.
      effort: default
      # Keep only results from detectors in SpotBugs's SECURITY category.
      # Off keeps every SpotBugs result, style and performance included.
      security_only: true
      # Seconds for the whole SpotBugs scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

No option names a path, a filter file or a configuration file, so none can be set from the scanned tree to hide findings. ASH passes none of SpotBugs's `-include`, `-exclude`, `-excludeBugs` or `-userPrefs` options. SpotBugs's own `@SuppressFBWarnings` annotation is read from the bytecode by SpotBugs and cannot be turned off by ASH.

SpotBugs's default heap is 768 MB. A large application at `effort: max` can need more. The plugin declares the strict sandbox default and no environment variables of its own. The baseline environment passes `JAVA_HOME` in under `--sandbox` but not `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS` or the `fb_maxheap` heap setting. A SpotBugs run under `--sandbox` has not been measured.

## Severity

SpotBugs writes a SARIF level for each result from the bug rank. ASH keeps the level and sets the ASH severity to agree with it:

| SARIF level | ASH severity |
|---|---|
| `error` | HIGH |
| `warning` | MEDIUM |
| `note` | LOW |
| `none` | INFO |

`error` is HIGH and not CRITICAL: a SpotBugs result is a code pattern, not a confirmed exploitable path. A result with no level is MEDIUM, and a level that is not in the table is HIGH, so nothing is under-reported. With ASH's default `severity_threshold` of `MEDIUM`, `error` and `warning` results fail the scan.

By default only security results are kept. SpotBugs also reports style, performance, bad-practice and multithreading results, which are about code quality and, on a real library, outnumbered them about twenty to one in a measured run over one library (528 results, 25 of them security). Set `scanners.spotbugs.options.security_only: false` to keep them.

## Exit status

ASH passes `spotbugs -exitcode`, which makes the exit status a bit set: 1 when bugs were found, 2 when classes the analysis needed were missing, 4 on a serious analysis error. Exit codes 0 to 3 are runs that finished. Exit code 4 or above fails the scan even when a report is on disk, for example when none of the inputs could be opened. SpotBugs's log is kept in the scan's output directory and is not quoted in the failure message, because it names classes from the scanned tree.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner:

```yaml
global_settings:
  suppressions:
    - rule_id: XXE_XMLREADER
      path: src/main/java/org/example/io/Validator.java
      line_start: 67
      line_end: 67
      reason: the parser is configured with external entities off in the factory
```

Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

SpotBugs and the plugin read only the files they are given, and the detectors are in the installed jars, so a scan behaves the same offline. Install both before going offline.

## License

SpotBugs is licensed under the LGPL-2.1 and Find Security Bugs under the LGPL-3.0. ASH does not include or modify either: it downloads the pinned release files at install time and runs them as a separate process.
