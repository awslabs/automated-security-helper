# Interface checks

Build the documentation, generate local fixture reports and terminal screens, run browser checks, and inspect the image gallery. These tools review the real renderers without running security scanners or posting GitHub comments.

Run from the repository root with the project's development dependencies and Node.js installed:

<!-- doctest: illustrative reason="runs in a checkout of this repository and needs Node.js and a browser" -->
```sh
uv sync --locked --group dev
uv run --group dev mkdocs build --clean --strict
uv run --group dev python scripts/preview_interfaces.py
cd docs/ui-tests
npm ci
npx playwright install chromium
npm test
npm run capture
```

Open `.previews/index.html` for interactive reports and source Markdown/text/SVG artifacts. Open `.previews/gallery.html` for desktop/mobile, light/dark, report, comment, and terminal images. Preview artifacts, browser traces, and installed Node dependencies are ignored by Git.

The generated examples use the snapshot fixtures and their pinned clock. They include a single project with actionable/suppressed findings, a workspace with a skipped project, and an empty result. Bedrock tests use stubbed AWS clients; the preview command makes no model calls.

TUI screenshots honor `NO_COLOR`. To review the color palette on macOS/Linux, scope the change to the preview command:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```sh
env -u NO_COLOR TERM=xterm-256color uv run --group dev python scripts/preview_interfaces.py
```

Use `npm run capture -- --skip-tui` for a browser-only preview. `--output /path/to/previews` changes the artifact destination.

## Browser configuration

| Variable | Purpose |
| --- | --- |
| `ASH_UI_CHROME` | Use an existing Chrome/Chromium executable |
| `ASH_UI_BASE_URL` | Review an already served site instead of starting the local server |
| `ASH_UI_PREVIEWS` | Directory containing generated report and terminal artifacts |
| `ASH_UI_PYTHON` | Python executable used for the local static server |

Without `ASH_UI_BASE_URL`, the test suite serves `public/` on loopback port 8849. The capture tool uses an available loopback port and closes its server after capture.

For example:

<!-- doctest: illustrative reason="runs in a checkout of this repository and needs Node.js and a browser" -->
```sh
ASH_UI_CHROME=/usr/bin/google-chrome npm test
ASH_UI_CHROME=/usr/bin/google-chrome npm run capture
```

`npm run report` opens the Playwright test report. Failures retain screenshots and traces. `npm run test:headed` is useful for inspecting keyboard flows.

Playwright and Axe are development tools. The homepage loads a local, reduced
Anime.js 4.5.0 module (MIT). Reports and documentation pages use native browser
controls without the animation module.

Rebuild the vendored animation module and its license notice with:

<!-- doctest: illustrative reason="runs in a checkout of this repository and needs Node.js" -->
```sh
npm run vendor:motion
```

## Review loop

1. Make the source change and rebuild the site or regenerate the report fixtures.
2. Run the checks affected by the change.
3. Capture the gallery and inspect the relevant screens at full size.
4. Exercise keyboard focus, long paths, empty views, coverage warnings, and the next action.
5. Review intentional rendered-output changes in the existing snapshot suite.

The browser suite checks responsive overflow, accessibility, keyboard tabs/search,
command copying, task navigation, tablet contents, modal focus and dismissal,
combined filters, reduced motion, embedded offline fonts, clipboard failure,
printing, and no-JavaScript fallbacks. Its accessibility assertions supplement
inspection of visual hierarchy and keyboard behavior.

The GitHub comment preview uses local approximate styles. Review the generated `.md` file as the source; GitHub applies its own final typography, disclosure, and alert styles.

## README previews

After generating the fixtures, refresh the README's real report and terminal
images from this directory:

<!-- doctest: illustrative reason="runs in a checkout of this repository and needs Node.js and a browser" -->
```sh
npm run capture -- --readme
```

This also captures the regular review gallery. The report images use a bounded
desktop viewport; the terminal image uses the 80-column fixture. Review these
committed images when changing the corresponding interfaces.

Record the vector scan and include playback in the gallery:

<!-- doctest: illustrative reason="downloads a browser tool over the network and needs Node.js" -->
```sh
npx playwright install ffmpeg
npm run capture -- --motion
```

## Python and golden checks

Use the existing snapshot review policy in `DEVELOPMENT.md`. Update only intentional changes, review their diffs, and include the required `Snapshot-Update` trailer when committing. CI compares snapshots and never rewrites them.

Relevant suites:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```sh
uv run --group dev pytest tests/unit/cli/inspect tests/unit/reporters -n 0
uv run --group dev pytest tests/unit/core/test_metrics_table_rendering.py tests/unit/core/test_progress_display_coverage.py -n 0
uv run --group dev pytest tests/snapshot -n 0
```

Editor changes originate in `ash-agent-plugins/agentic-coding/transpiler/_base/`. Regenerate the tool reference and all backends, then check them:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```sh
uv run python scripts/generate_mcp_tool_reference.py
uv run --project ash-agent-plugins/agentic-coding/transpiler agentic-plugins build
uv run --project ash-agent-plugins/agentic-coding/transpiler agentic-plugins check
```
