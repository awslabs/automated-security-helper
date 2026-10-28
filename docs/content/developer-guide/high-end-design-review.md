# Design, UX, and developer experience review

Review date: October 14, 2026.

Applied skills: high-end-visual-design, animation-vocabulary, ui-ux-pro-max.
Scope: every interaction surface in ASH. The
[surface inventory](interface-review.md) records the implementation and contract
of each interface. The [design system](interface-design.md) is the source of
truth for future changes.

## Direction

Cloudscape sets the colors, typography, containers, controls, and status roles.
The requested AWS direction overrides the visual skill's generic font, border,
and floating-navigation defaults.

- Open Sans for the website and HTML reports; native fonts in terminals and GitHub.
- Neutral surfaces, blue actions, separate severity colors.
- Flat 16px containers and 8px inputs; shadows on overlays.
- Text identity without a custom logo.
- Short labels, commands, factual bullets, and sentence-case headings.
- `Build with <3 at Amazon Web Services` in human-facing footers.

The homepage uses Anime.js 4.5.0 (MIT) for local SVG motion. Phosphor icons use
MIT; Open Sans uses the SIL Open Font License. Licenses ship with the assets.

## Navigation architecture

The homepage has four routes: **Overview**, **Documentation**, **Scanners**, and
**Integrations**. Search, theme, and GitHub are separate utilities. At narrower
widths, a native navigation dialog supplies the same routes, a close action, and
access to the complete documentation drawer.

The handbook groups pages by the reader's task:

| Group | Reader's question | Destination |
| --- | --- | --- |
| Start here | How do I get my first scan? | Installation, concepts, language coverage, local execution, migration |
| Scan & triage | What ran, what matters, and how do I respond? | Configuration, reports, suppressions, scanner and reporter catalogs |
| Integrate ASH | Where does this fit in my workflow? | CI, pre-commit, AI assistants, MCP, AWS destinations |
| Extend ASH | How do I add a capability? | Plugin architecture, development, examples, community plugins |
| Reference | What is the exact command or interface? | CLI, generated options, Python API, glossary |
| Contribute & maintain | How do I change ASH safely? | Contribution, design, metrics, validation, testing |
| Help | How do I recover? | FAQ, troubleshooting, uv installation, support |

All 78 pages in the previous navigation are retained at their original paths.
The MCP tool reference, HTTP transport guide, integration landing page, general
troubleshooting guide, and this review are explicitly discoverable.
Nested groups are reserved for a real family of tasks; users do not need to
know the plugin implementation to find a scan or a report.

The README follows the same journey: first scan, review results, integrate,
configure, then discover the complete scanner and tool inventories.
Reports navigate between findings, scanner coverage, workspace projects when
present, and the scan record. The findings explorer makes the current selection,
active filters, and available keyboard actions visible.

## Skill review

| Criterion | Application | Platform adaptation |
| --- | --- | --- |
| Strong typography and hierarchy | Display titles, readable body text, selected mono labels, outcome before evidence | Terminals and GitHub use native typography; hierarchy uses headings, spacing, labels, and disclosure |
| Asymmetric composition | Primary workflow gets a larger panel; secondary tasks support it | Metrics remain comparable; findings stay in an ordered list |
| Containers and controls | Flat Cloudscape surfaces, blue controls, readable spacing | Terminal panels use Cloudscape colors; Markdown uses native headings and details |
| Primary actions | Blue buttons with short labels and optional fine icons | Report controls and terminal key labels remain explicit |
| Navigation | Full-width header and task-based handbook | Native documentation drawer and terminal footer retain their platform behavior |
| Fine icon language | Light Phosphor SVGs replace thick icon families in the site shell and homepage | Severity and status remain readable text; terminal Unicode has a monochrome fallback |
| Motion with purpose | Menu origin, staggered routes, press feedback, one-time reveals, illustrative scan sequence | No ambient motion in offline reports, README, findings, or Markdown |
| Accessible targets and focus | Primary web controls have 44px targets, visible focus, skip links, contained dialogs | Dense secondary controls retain at least the 24px WCAG target; keyboard remains complete |
| Mobile readability | 16px reading and report input text, wrapping paths, bounded panels | Wide tables have named focusable scroll regions; only their content scrolls horizontally |
| Honest status and recovery | Incomplete coverage, unavailable scanners, suppressed findings, and empty filters have distinct next steps | Views cannot turn partial execution into a successful scan |
| Progressive enhancement | Core content, navigation, install commands, and full reports remain usable without JavaScript | Clipboard and storage failures do not erase content or block reading |
| Developer reproducibility | Canonical templates, fixture reports, snapshots, browser checks, gallery, package verification | Generated editor content and machine contracts keep their existing checks |

## Every surface

| Surface | Design and interaction review |
| --- | --- |
| README | Text title, short task navigation, first scan before inventories, real report and terminal previews, expandable references |
| Homepage | Interactive vector scan, file groups, scanners, findings, formats, install commands, execution requirements, catalog, local/CI/MCP routes |
| Handbook pages | Reading measure, heading rhythm, code, tables, breadcrumbs, side navigation, previous/next, back-to-top, footer |
| Desktop header | Four destinations, current route, flat header, keyboard theme/search utilities |
| Mobile navigation | Native dialog, explicit close, Escape, focus containment and return, backdrop dismissal, task routes, drawer handoff |
| Search | Indexed results, input/paste, keyboard shortcut, keyboard results, focus containment, Escape, long result content |
| 404 | Clear missing-page message and primary routes back to the handbook and overview |
| Installation | Python/runtime prerequisites, reproducible release references, pipx/uvx/pip alternatives, readable copied commands |
| Root CLI and scan help | Purpose-based option groups, defaults, scope, execution, workspace, report, exit policy, output |
| Container and Nix wrappers | Consistent human summary, forwarded options, runtime errors and verdict; wrapper contracts remain intact |
| Progress and logs | Visible phase and status, completed indicators stop, literal descriptions, readable monochrome output |
| Scan summary | Outcome, actionable count, coverage, report destinations, next action before the detailed reference |
| Configuration commands | File destination, overwrite/refusal, validation, proposed edits, dry run, repair choice and error recovery |
| Dependency installation | Tool and host context, per-tool success/failure, readable result table and next step |
| Plugin discovery | Scanner/converter/reporter/event inventory, meaningful names, defaults and configuration context |
| Findings explorer | Cloudscape colors across header, filters, table, detail, suppression dialog, and footer; adaptive 60/80/120-column table |
| Finding details | Severity, status, rule, location, explanation and evidence; Back remains the relevant footer action |
| Suppression dialog | Finding and destination context, initial reason focus, stationary Cancel/Save, validation, scrollable body, preserved values on failure |
| SARIF field inspection | Field discovery, summaries, input errors and output destination; literal data stays separate from formatting |
| Report command | Human format selection, stdout/file output, missing results, unsupported formats and clear destinations |
| Merge | Union and shard errors, incomplete/actionable/clean verdicts; shared summary and stable return policy |
| GenAI guide and entrypoint errors | Discoverable guidance, local/fetched text, dependency/import failures and write diagnostics |
| GitHub PR comment | Outcome and next action, visible coverage, compact summary, bounded evidence disclosures, native Markdown semantics |
| GitHub Actions summary | Same concise renderer, useful first screen, traceable findings, compatible scanner table |
| Standalone HTML | Embedded Open Sans, Cloudscape light/dark themes, flat containers, composed filters, evidence details, copy fallback, print and offline reading |
| Text and Markdown artifacts | Factual summary first, labeled counts, coverage, workspace projects, scanner table and traceable detail |
| Bedrock summaries | Deterministic outcome before analysis, canonical severity, finding indices, rule IDs, safe snippets and tables |
| MCP lifecycle | Start/progress/results/cancel, terminal states, bounded polling guidance, partial coverage and scan-ID errors |
| MCP discovery | Installation, scanners, resolved config, validation, finding explanation, suppression draft and result diff |
| MCP workspace/session | Project plan, per-project verdict, profiles, Git/zip source delivery, clear-source actions and error messages |
| MCP resources/prompts | Discoverable help, status, exit codes, schemas and analysis instructions |
| Editor and agent integrations | One canonical workflow, generated platform rules and commands, correct threshold/filter distinction and incomplete-scan handling |
| Contributor documentation | Quick entry routes, template ownership, visual fixture workflow, reviewable outputs and intentional snapshot policy |
| Issue and pull-request entry points | Clear problem/context/validation prompts; security reporting follows the existing private reporting path |
| Structured reporters and host integrations | Review names, attribution, severity, escaping and consumer compatibility; preserve the format consumed by the host |

The final row includes **all nineteen shipped reporters**: HTML, Markdown, text,
Bedrock summaries, CSV, flat JSON, SARIF, GitHub GHAS, GitLab SAST, CycloneDX,
GitLab CycloneDX, SPDX, JUnit XML, OCSF, YAML, unused suppressions, Security Hub,
CloudWatch Logs, and S3.
GitHub code scanning, GitLab, AWS consoles, IDE annotations, and CI test viewers
own their rendering. ASH supplies useful and compatible data to those surfaces.

## Animation vocabulary and behavior

These definitions are reproduced verbatim from animation-vocabulary:

| Term | Definition | ASH behavior |
| --- | --- | --- |
| Purposeful animation | Motion should serve a function — orient, give feedback, show relationships — not just decorate. | Navigation, feedback, and a labeled example scan |
| Cubic-bezier | A custom easing curve you define for precise control. | Shared curves; no default linear or ease-in-out browser motion |
| Stagger | Animate several items one after another with a small delay between each, creating a cascade. | 40ms route offsets in the navigation dialog |
| Orchestration | Deliberately timing multiple animations so they feel like one coordinated motion. | Example scan steps and their completed state |
| Line drawing | An SVG path that draws itself in, like an invisible pen tracing it. | File-to-scanner and scanner-to-finding routes |
| Press / Tap feedback | A subtle scale-down when an element is clicked, so it feels physical. | Brief primary and utility button feedback |
| Morph | One shape smoothly turns into another shape, e.g. Dynamic Island. | The menu glyph changes from two lines to a close symbol |
| Scroll reveal | Elements fade or slide into place as they enter the viewport. | Once per section, using IntersectionObserver |
| Origin-aware animation | An element animates out of its trigger, like a popover growing from the button that opened it instead of from its own center which is the default in CSS. | Menu opens from the upper right, near its trigger |
| Interruptible animation | An animation that can be smoothly redirected mid-flight instead of finishing first. | Reopening cancels the pending close; state does not depend on animationend |
| Reduced motion | Respecting the user's prefers-reduced-motion setting by toning down or removing motion. | OS preference, persistent pause control, complete static content |

| Role | Timing | Behavior |
| --- | --- | --- |
| Press/copy feedback | 160ms | Transform or opacity, custom easing |
| Menu entrance | 320ms | Opacity and transform from its origin |
| Menu exit | 180ms | Faster dismissal; canceled safely on reopening |
| Route stagger | 40ms | Small cascade with a bounded total duration |
| Section reveal | 240ms | Once, with 40ms sibling offsets |
| Vector scan | 10s | File packets, scanner progress, severity packets, report assembly; plays once |

Long-lived motion has a persistent pause control and respects a live OS
preference change. Reduced motion and JavaScript-disabled views show complete
content immediately. Report actions update state without staged transitions.
No scroll handler performs layout work.

## Verification

The repeatable workflow is in `docs/ui-tests/README.md`. Review the gallery
after generating the source fixtures and building the site.

Checks cover both themes, narrow and wide screens, keyboard-only paths, search
and navigation, rapid modal dismissal, clipboard/storage failure, offline font
loading, no JavaScript, printing, empty/suppressed/incomplete/workspace results,
the real Textual app, canonical document generation, and packaged report assets.
Human reporter snapshots and the existing machine/protocol goldens check the
rendered output and consumer contracts.

Automated accessibility results supplement visual and keyboard inspection.
The GitHub comment preview approximates GitHub's native styling. Live AWS
uploads, model calls, and actual container/Nix execution remain the responsibility
of the existing integration jobs.
