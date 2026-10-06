# Snapshot tests for the VS Code extension

Everything the extension shows a user is pinned by a snapshot, so a change to it
fails CI until someone updates the snapshot on purpose and says why. There are two
suites, and one rule for changing either.

## Changing a snapshot

1. Make the change and run the suites. A changed or missing snapshot fails:

   ```
   npm run snapshots -- all
   ```

2. Read the failure. jest prints the text diff; the pixel suite names the
   scenario and the number of pixels that differ, and with
   `--artifacts <dir>` it leaves the capture and a diff image there.
3. If the change is intended, rewrite the snapshots:

   ```
   npm run snapshots -- --snapshot-update structural   # or visual, or all
   ```

4. Review `git diff` (for a PNG, open it), then commit the snapshot in the same
   commit as the change, with a trailer saying why the output changed:

   ```
   git commit --trailer "Snapshot-Update: the incomplete-scan warning names the scanner"
   ```

`--snapshot-update` is the same flag core ASH's snapshot suite uses, and like that
suite's it is refused when `CI` or `GITHUB_ACTIONS` is `true`.
`test/snapshot-policy.test.ts` fails if any file under `.github/` passes it, or jest's
`--updateSnapshot`, `-u` or `--ci=false`, or sets `ASH_SNAPSHOT_UPDATE`. jest itself
is configured with `ci: true`, so a plain `npm test` never writes a snapshot, not
even a new one.

The `editor-snapshots` job runs `.github/scripts/check-editor-snapshot-trailers.py`
over the commits of the push (`before..after`) or the pull request (fork point to
head). It fails when a file under an `editors/**/__snapshots__/` directory changed
and no commit that touched it carries `Snapshot-Update: <reason>`. A separate commit
that only adds the trailer does not count, and the placeholder
`<why the output changed>` is not a reason. The error message prints the
`git commit --amend` or `git rebase --exec` command that fixes it. The same job's
`--orphans` step fails a `.snap` file whose test file is gone, a PNG that no
scenario in `scenarios.json` names, a scenario with no PNG, and any other file in
a `__snapshots__` directory.

## Structural snapshots (`test/ui-snapshots.test.ts`)

jest snapshots of the text and structure of every surface the extension has:

- the `contributes` block of `package.json` (commands, settings with their
  descriptions and defaults) and the untrusted-workspace capability text;
- what activation registers: the commands, the diagnostic collection's name, the
  output channel's name, and the Clear command's output;
- for each of 27 scan outcomes: the diagnostics (file, range, severity, message,
  source, code), every notification in the order raised with its severity, the
  progress notification's title and Cancel button, and the output channel's text.
  The outcomes include exit 0, exit 2, exit 1 with partial results (the
  incomplete-scan warning), exit 1 with no report, every refused setting, every
  executable lookup failure, and the `ashx` to `ash` fallback notice shown and
  already shown.

The extension has no tree view, CodeLens, hover provider, status bar item, quick
pick, input box, webview, custom editor, code action, terminal or task. A test in
the same file fails when `src/` calls the API that would add one, or `package.json`
gains a contribution point other than `commands` and `configuration`, so a new
surface cannot arrive without a snapshot.

Notifications and the log go through `createScanHost`, the object `activate()`
builds; only the process and the filesystem are replaced. The workspace is the fixed
path `/workspace`, printed as `<workspace>`.

## Pixel snapshots (`test/visual/`)

`test/visual/run.ts` starts a real VS Code with the extension loaded and drives it,
through the extension's own command and VS Code's commands, into four states. Each
is captured from the X server and compared with its PNG in `__snapshots__/`:

| Baseline | What it shows |
|---|---|
| `fallback-notice.png` | the one-time notice when `ashx` is not on PATH and `ash` runs, expanded |
| `problems-panel.png` | the Problems panel after a scan with findings, `planted_secret.py` open |
| `diagnostic-hover.png` | the hover over the finding's line: message, source, rule code |
| `incomplete-scan-notification.png` | the exit 1 (ScanIncompleteExit) warning, expanded |

The extension has no tree view and no webview, so there is no picture of either.

The CLI is `test/integration/ash-stub.ts` replaying the scans captured under
`test/fixtures/scans/`.

### What is pinned, and where

A pixel baseline is a picture of its environment as much as of the extension, so
everything that can move a pixel is fixed:

- `Dockerfile`: the base image by digest; every Debian package (Xvfb, fontconfig,
  FreeType, ImageMagick, the GTK and NSS libraries) from snapshot.debian.org at one
  instant; DejaVu as the only font family installed, checked at build time; VS Code
  1.140.0, the version the integration job also runs, verified against the SHA-256
  its update service publishes.
- `run.ts`: a 1280x800x24 screen at 96 DPI, `--force-device-scale-factor=1`,
  software rendering (`--disable-gpu`), the Default Dark Modern theme, DejaVu Sans
  Mono at 14px with a 20px line height, a solid caret, reduced motion, and every
  setting that would open something on its own or draw something time-dependent
  turned off. The workspace is always `/tmp/ash-visual/sample-project`, because its
  name is in the title bar.

The image is built from the Dockerfile on each run and is never pushed.

### Threshold and determinism

The threshold is zero: `compare -metric AE` with no fuzz, so one changed pixel
fails. That is justified by measurement, not assumed. The suite was run three
times in a row in the container on the same commit, and every capture of every
scenario was byte-identical across the three runs and to the baselines. With no
variance measured there is nothing for a tolerance to absorb, and a tolerance
would only be room for a styling change to pass.

Each state is captured repeatedly until four consecutive captures have the same
pixel signature, rather than after a fixed delay. A fixed delay is a guess that a
slow runner loses, capturing a half-drawn frame; something that never stops
changing fails with a timeout instead of producing a baseline that depends on when
it was taken.

One limit is known. The renderer is Chromium's software rasterizer, which picks
SIMD code paths from the CPU it runs on. The three identical runs were on one
machine, so they do not show that a runner with a different CPU draws the same
pixels. CI is the first cross-host check; if it differs, the fix is to measure the
difference across runners, not to raise the threshold.

### Running it

Docker is the only requirement. `npm run snapshots -- visual` compiles, builds the
image and runs the suite in it, as the invoking user so the files it writes in the
tree are yours. Add `--artifacts <dir>` to keep the captures.
