# Interface design

Shared theme: Cloudscape colors, Open Sans, flat containers, labeled status, and blue actions.

See [the interface review](interface-review.md) for the surface inventory and
[the design and UX review](high-end-design-review.md) for the applied skills,
navigation architecture, and motion vocabulary.

## Visual language

| Role | Dark | Light |
| --- | --- | --- |
| Background | `#0f141a` | `#f9f9fa` |
| Surface | `#161d26` | `#ffffff` |
| Text | `#dedee3` | `#0f141a` |
| Muted text | `#b4b4bb` | `#424650` |
| Action and focus | `#42b4ff` | `#006ce0` |
| Critical and error | `#ff7a7a` | `#db0000` |
| High severity | `#fe6e73` | `#ce3311` |
| Medium severity | `#f89256` | `#855900` |
| Low severity | `#f2cd54` | `#855900` |
| Information | `#42b4ff` | `#006ce0` |
| Success | `#2bb534` | `#00802f` |

`automated_security_helper/utils/ui_theme.py` is the terminal palette and theme adapter. The site and offline report styles declare their corresponding CSS variables in `ash.css` and `ash-report.css`. Check all three surfaces when changing a semantic color.

Open Sans is hosted locally under the SIL Open Font License. Reports embed the
font and its license. Terminals use the operator's font; GitHub uses native typography.

Light Phosphor icons and Anime.js 4.5.0 use MIT licenses. The homepage loads a
reduced local animation module; other pages and reports do not load it.
Run `npm run vendor:motion` in `docs/ui-tests` to rebuild the module and its notice.

Use one page title, sentence-case headings, 16px reading text, and labels of at
least 12px. Containers use 16px corner radii; inputs use 8px. Reserve shadows for
overlays and fixed controls. Use blue for actions and focus. Keep severity colors
separate from action colors.

The landing display uses 48/56px on desktop and 32/40px on phones.
Documentation and reports use the 24/30px page-heading scale.

Navigation uses a full-width 64px header. The handbook groups tasks into Start
here, Scan & triage, Integrate ASH, Extend ASH, Reference, Contribute & maintain,
and Help. Preserve page URLs when regrouping content. Long paths, rules, and
scanner messages wrap; wide tables and snippets use deliberate scroll regions.

## Outcome and evidence

| State | Presentation | Next action |
| --- | --- | --- |
| Actionable findings | Review required; severity counts and context | Review the highest severity findings |
| Partial coverage | Scan incomplete; visible coverage notices | Resolve missing scanners, targets, converters, or rules and scan again |
| Stale content database | Scan needs attention; database notice | Review freshness and refresh the affected scanner |
| No completed scanners | No scanners completed | Check configuration, dependencies, and execution logs |
| Completed coverage with no actionable findings | No actionable findings | Review coverage and findings below the gate |
| Suppressed finding | Explicit Suppressed label and justification | Inspect the recorded decision |
| Filter with no matches | No findings match this view | Clear the search or reset the filters |

Color reinforces these labels. It does not replace them. A zero finding count cannot establish complete coverage.

`ReportContentEmitter.get_scan_summary()` supplies the factual outcome for human reports. Coverage comes from the existing scan completeness helpers. HTML, Markdown, plain text, console summaries, and Bedrock report introductions show the relevant facts before detailed analysis.

Human finding severity uses the same SARIF resolver as scanner totals and the gate: an explicit `issue_severity` takes precedence over the SARIF level. Human reports copy the flat presentation data rather than changing the cached flat export.

The existing flat export representation and MCP filtering contracts remain compatible. In particular, MCP's `actionable_only` excludes suppressed findings; use its severity filter when selecting specific severity levels. This is distinct from the threshold-based Actionable count in human reports.

## Interaction patterns

### Documentation

- Use real links for navigation and buttons for actions.
- Keep installation methods in an ARIA tab list with arrow, Home, and End controls.
- Keep command text selectable and provide feedback after copying.
- Provide a visible focus indicator and a skip link.
- Open search with its button or Ctrl/Command + K. Keep focus in the open dialog, and restore it on Escape.
- Keep mobile navigation usable with touch and keyboard.
- Provide a documentation Contents control at tablet widths when the sidebar is hidden.
- Keep focus in open navigation and contents dialogs; return it to their trigger on Escape.
- Keep installation commands, navigation, and core content available without JavaScript.

The homepage scan illustration and terminal replay are examples. They do not run scanners or imply that a visitor's project has been scanned.

### Findings explorer

The table prioritizes severity and the finding. At narrower widths, scanner and location move into the selected finding preview and detail screen. The active selection survives sorting, resizing, and returning from details.

Severity, scanner, suppression, and search filters compose. Escape clears the search input and returns focus to the table. The empty state describes a shortcut that works with the current focus.

Suppressions show the finding, configuration destination, and reason. The reason
field receives initial focus. Cancel and Save remain visible outside the scrolling
dialog body. Validation and save failures preserve the entered values. Saving
gives visible confirmation.

Render scanner-controlled labels with literal `Text` cells. Escape metadata before putting it in Markdown, and select a code fence longer than any fence in a scanner snippet.

### Reports and GitHub

HTML reports are self-contained. Finding cards expose context on demand, combine filters, announce result counts, and recover from empty views. All findings remain available without JavaScript. Printing includes findings hidden by a screen filter and expands their details.

Generated GitHub comments and Actions summaries use the Markdown reporter. Lead with the outcome and next action. Keep coverage notices visible in compact mode. Collapse detailed findings and explanations so the first screen remains useful.

The scanner table retains its established ten columns because workflow consumers parse it. Detailed findings are ordered by severity and bounded by the existing report option. Indicate when more findings exist and point to the complete report or findings explorer.

Bedrock summaries show the deterministic scan outcome and coverage before generated analysis. Preserve finding indices so a suggestion can be traced to its evidence. Escape report metadata and protect scanner code fences.

### CLI and automation

Group help by the decision a user is making: scan scope, reports, exit policy, execution, workspace, CI, containers, configuration, or output. Keep option names, defaults, exit codes, and machine output stable when changing presentation.

Console summaries put the verdict and report locations before the reference guide. Finished progress rows stop their running indicators. Respect `NO_COLOR` and provide readable monochrome output.

MCP clients stop polling on `completed`, `incomplete`, `failed`, or `cancelled`. Completed and incomplete scans have readable results. An incomplete scan needs coverage review; failed and cancelled scans need status/error review before retrying.

Edit the canonical editor workflow under `ash-agent-plugins/agentic-coding/transpiler/_base/` and rebuild the integrations. Generated copies should never diverge from their source.

## Motion and resilience

The homepage example connects files, scanners, findings, and report formats.
File selection highlights the corresponding tools and evidence.
Step buttons allow direct inspection; Play, Pause, and Replay control the timeline.

Use the shared custom easing curves and role-based timings: 160ms feedback,
320ms menu entrance, 180ms exit, 40ms stagger, and 240ms section reveal.
Animate opacity and transforms, and use IntersectionObserver for reveals.
State changes and focus must succeed independently of transition events.
The scan example plays once. It pauses outside the viewport, in hidden tabs, and
when keyboard focus enters its controls.

The footer's pause setting persists. Reduced motion and global pause render the
complete example. File selection and step controls work with reduced motion.
All labels, findings, formats, and installation commands remain available without JavaScript.

Local storage, clipboard access, and JavaScript are enhancements. Their failure should leave the content usable. Clipboard failures offer a manual copying path. Offline reports fetch no external resources.

## Reviewing a change

The local workflow is documented in `docs/ui-tests/README.md`. Generate fixture previews, build the documentation strictly, run the browser suite, and inspect the gallery before accepting a visual change.

Review narrow and wide screens, both themes, keyboard focus, long text, empty results, suppressed findings, missing dependencies, incomplete coverage, and printing. Automated accessibility checks help find defects; visual and keyboard review remain necessary.

Rendered output is also covered by `tests/snapshot/`. Follow the snapshot review and commit trailer policy in `DEVELOPMENT.md` when intentionally updating those outputs.

## Sources and credit

- [Cloudscape colors](https://cloudscape.design/foundation/visual-foundation/colors/)
- [Cloudscape typography](https://cloudscape.design/foundation/visual-foundation/typography/)
- [Cloudscape visual style](https://cloudscape.design/foundation/visual-foundation/visual-style/)
- [AWS trademark guidelines](https://aws.amazon.com/trademark-guidelines/)
- [Writing review reference](https://en.wikipedia.org/wiki/Wikipedia:Signs_of_AI_writing)

Text identity: ASH. Footer: `Build with <3 at Amazon Web Services`.
