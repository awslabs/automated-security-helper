# Changelog

The headings here are not version numbers, and that is deliberate. `cz bump`
rewrites `package.json`'s `version` so the extension tracks ASH's release, but it
does not and should not rewrite this file: a changelog gains a section per release
rather than having its newest section renamed. A version-numbered heading would sit
one release behind `package.json` from the first bump onward and read as drift.

## A scan that does not block the editor

- The scan runs asynchronously under a progress notification with Cancel, so the
  extension host is no longer frozen for the length of the scan. The `--version`
  probe before it is asynchronous as well, with a one-minute limit.
- `ash.scanTimeoutSeconds` (default 1800, `0` to wait indefinitely) stops a scan
  that runs too long. Cancel and the timeout both stop the scan's whole process
  tree, including a scanner that ignores SIGTERM after ASH has exited.
- A failed, stale, cancelled or otherwise unusable scan clears the previous
  findings instead of leaving them on screen. `incomplete` still publishes.
- `ash.extraArguments` is machine-scoped, like `ash.executablePath`. ASH takes
  command-line options as the operator's (`--sandbox off`, `--config-overrides`,
  `--ash-plugin-modules`), so a repository's `.vscode/settings.json` could pass it
  what ASH refuses from the repository's own config. A value set there is now
  ignored; set it in user settings, or choose scanners in `.ash/.ash.yaml`.

## Exit codes, coverage and the ashx entry point

- Exit 1 with results is reported `incomplete` and its findings are published,
  instead of being treated as a failed scan. Exit 1 with no report is a crash.
- A scan is also `incomplete` when `ash_aggregated_results.json` names a coverage
  gap, by the rule ASH uses for `coverage_complete`, so the gap shows even with
  `fail_on_incomplete_scanners` off.
- Results ASH suppressed are no longer shown as diagnostics, and results whose
  `kind` is not `fail` are no longer shown either.
- SARIF locations relative to a `uriBaseId`, `file:` URIs in every form, Windows
  paths and grype's scan-root-absolute paths resolve to the right file; one with no
  local file is counted and reported.
- The previous run's reports are deleted before each scan, and a report this run
  did not write is refused.
- `ash.executablePath` defaults to empty, which runs `ashx` and falls back to `ash`
  with a one-time notice. It is machine-scoped.
- An integration suite inside a real VS Code, run in CI under Xvfb.

## Initial release

Runs the `ash` CLI over the open workspace folder and reports its SARIF findings in
the Problems panel.

- `ASH: Scan workspace` and `ASH: Clear findings` commands.
- `ash.executablePath`, `ash.outputDirectory` and `ash.extraArguments` settings.
- A check that the configured executable really is ASH before every scan, for hosts
  where a bare `ash` resolves to MSYS2's Almquist shell instead.
- No runtime dependencies, and a check over the built `.vsix` that fails if it ever
  carries anything but this extension's own output.
