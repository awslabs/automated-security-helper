# Interface review

Review date: October 14, 2026.

Scope: discovery, setup, scanning, triage, remediation, reports, automation, and
contribution. Theme: Cloudscape colors, Open Sans, flat containers, semantic status,
and a vector scan example.

The [interface design guide](interface-design.md) explains the resulting patterns. `scripts/preview_interfaces.py` and `docs/ui-tests/` make the human interfaces reproducible from repository fixtures.

## Findings addressed

| Finding | User impact | Resolution |
| --- | --- | --- |
| The homepage presented documentation before a clear starting path | New users had to infer what ASH does and how to begin | A dedicated overview, installation tabs, mode-specific commands, scanner catalog, and laptop/CI/MCP paths |
| Separate visual styles across the site, terminal, and reports | Users had to relearn hierarchy and severity presentation | Shared palette, outcome language, typography hierarchy, and restrained borders |
| Search did not refresh reliably after pasted input | A query could appear to produce no results | Bridge input changes to the indexed search update |
| Search allowed keyboard focus to leave its open dialog | Keyboard users could interact with obscured controls | Focus containment, inactive background, and Escape focus restoration |
| Framework controls appeared after their accessibility labels were assigned | Dynamic code controls and search snippets could fail navigation checks | Label new controls and make overflowing code reachable after rendering |
| Theme switching depended on hidden framework labels | Keyboard activation and focus behavior were unreliable | A native button reflects and updates the framework's saved theme state |
| Reduced motion could leave illustrated content invisible | The accessible preference removed useful content | Complete static illustration and demo, with persistent motion controls |
| The findings table overflowed narrow terminals | Important content and keyboard controls were difficult to read | Responsive columns reserve scrollbar space; literal two-line rows, selected finding preview, and a stationary footer fit at 60 columns |
| Filters replaced one another | A scanner filter could discard a severity or suppression choice | Independent criteria that compose |
| Search state and active selection were lost or confusing | Clearing, resizing, or sorting interrupted triage | Clear the actual input, explain empty states, and preserve the selected finding |
| Suppression failures dismissed or obscured the decision | Users could lose their explanation or destination context; save controls could fall below a short terminal | Focus the reason field, preserve values, show inline errors and destination context, and keep Cancel/Save visible outside the scrolling body |
| Detail views exposed parent-screen shortcuts | Hidden filters could change while reviewing a finding | Show and enable only actions available on the current screen |
| Human severity could disagree with scanner totals and the gate | A critical threshold finding could be missing from detailed review | Use the canonical SARIF severity resolver in human views without mutating flat exports |
| Empty and incomplete reports could imply successful coverage | A missing scanner or failed converter could look clean | Outcome-first presentation with scanner, target, converter, rule, workspace, and freshness notices |
| Long legends preceded the scan decision | Users had to scroll to understand the result | Put outcome, counts, and next action first; move reference material later or into details |
| GitHub comments expanded every detail at once | A pull request became difficult to scan | Compact outcome, stable scanner table, actionable hotspots, and expandable finding details |
| Offline HTML reports lacked a cohesive review workflow | Filtering, long paths, printing, and mobile reading were awkward | Responsive cards, combined filters, copy fallback, clear/reset, themes, no-JavaScript support, and complete printing |
| Finished progress rows still showed running indicators | Completion appeared ambiguous | Freeze completed summary timers and indicators |
| Editor guidance omitted the terminal `incomplete` state | An agent could poll indefinitely after a finished partial scan | Correct the canonical workflow and regenerate every editor integration |
| MCP scan guidance used `is_complete` alone | Cancellation could leave a polling loop running | Name all terminal states in the tool description and returned guidance |
| Editor examples confused the severity gate with result filtering and suppressions with ignored paths | Users could rescan unnecessarily or edit the wrong setting | Correct threshold, filtering, scanner-name, and suppression guidance |
| Bedrock detail views used SARIF levels as severity and lost some rule IDs | Generated advice was harder to trace to the actual finding | Canonical severity, `ruleId` fallback, safe tables/fences, and individual finding disclosures |
| Version checks read generated HTML as installation examples | Building the site could make an otherwise valid source checkout fail its DevEx checks | Check source files, exclude generated artifacts, and verify the copied installation command against the displayed release |

## Surface inventory

The source paths below identify the implementation reviewed. The corresponding snapshot and browser suites exercise the rendered states.

| Surface | Interactions and states reviewed | Result and evidence |
| --- | --- | --- |
| Homepage | Vector scan, file selection, scan steps, Play/Pause/Replay, install tabs, mode selection, copy, scanner filters, FAQs | `home.html`, `ash-scan.js`, `ash.css`, `ash.js`; responsive, theme, keyboard, reduced-motion, and fallback browser checks |
| Documentation shell | Breadcrumbs, side navigation, mobile drawer, tables, code, copy controls, section navigation, previous/next, footer, and 404 | Custom header and pagination with the existing documentation engine; strict build and browser review |
| Documentation search | Button, Ctrl/Command + K, typing, pasted queries, result links, scrolling code, Tab/Shift+Tab, Escape | Indexed Material search with progressive accessibility enhancements; browser interaction tests |
| Installation and mode choice | pipx, uvx, pip, container/local/precommit requirements, release version, no-JavaScript content | Explicit prerequisites and selectable commands; version template tests and browser copy/tab tests |
| Root CLI and `scan` | Help, option groups, command defaults, JSON input, quiet/verbose/debug, local/container/precommit, workspace and sharding | Help grouped by purpose; CLI snapshots and unit coverage preserve invocation and verdict behavior |
| `build-image`, container/Nix wrappers | Forwarded options, runtime errors, host verdict recomputation, return codes | Reviewed through existing container snapshots; shared terminal summary changes propagate; real runtime tests remain in their existing CI legs |
| Scan progress and logs | Initialization, active phases, completed/failed/warning rows, monochrome, handler cleanup, literal task descriptions | Shared terminal theme and clearer status indicators; progress and Rich log tests plus final-frame snapshots |
| Scan results and next steps | Scanner totals, severity gate, partial targets, stale databases, missing dependencies, report paths, quiet output | Verdict first, readable results table, concise guide and literal paths; metrics/summary snapshots and exit-policy tests |
| `config init/get/update` | Initial file creation, overwrite refusal, resolved config, invalid edits, dry run, paths | Consistent console theme and literal paths; config snapshots preserve file and prompt behavior |
| `config wizard/validate/lint/validate-plugin-dependencies` | Existing/default config, validation, repairs, declined writes, unused suppressions, dependency errors | Reviewed through the existing config and error snapshots; theme and hierarchy aligned |
| `dependencies install` | Success, partial failure, supported host variants, dependency result table | Consistent terminal presentation; all recorded host variants retain their install commands |
| `plugin list` | Scanner/converter/reporter/event inventory, config/default values, long plugin names | Shared console theme; plugin list and registry snapshots |
| `inspect findings` | Selection, sorting, resizing, severity/scanner/suppression filters, search, empty results, suppressed rows, detail view, snippet, return/quit | Responsive explorer and reliable state; real headless Textual tests at 60/80/120 columns and screen snapshots |
| Suppression dialog | Rule and path context, configuration destination, reason validation, cancel, save, save failure | Preserved input and inline feedback; real dialog regression tests |
| `inspect sarif-fields` | Field inventory, summaries, missing/invalid SARIF, output destinations | Reviewed through SARIF-field and error snapshots; structured content retained |
| `report` | Format selection, stdout, file output, missing results, invalid formats | Human formats redesigned; machine formats remain compatible; report command snapshots and output-format tests |
| `merge` | Results union, invalid shard sets, incomplete scan, actionable findings, clean verdict | Existing union semantics retained and checked by merge/error snapshots; shared terminal results styling |
| `get-genai-guide` and entrypoint errors | Local/fetched guide, write failures, dependency/import failures, CLI refusals | Reviewed through error snapshots; established diagnostic and return behavior retained |
| GitHub pull request comment | Outcome, completion count, scanner table, hotspots, finding disclosures, context snippets, compact mode | Uses `MarkdownReporter`; the workflow continues to consume `reports/ash.summary.md` |
| GitHub Actions job summary | Same report in the job summary; partial coverage and stale notices | Same renderer as the pull request comment; table column compatibility preserved |
| Offline HTML | Desktop/mobile, themes, scope/severity/scanner/search filters, suppressed reasons, zero matches, copy failure, JavaScript disabled, printing | Self-contained `HtmlReporter` assets; offline browser tests include network/request checks |
| Plain text and Markdown files | Scan record, outcome, counts, coverage, scanner table, hotspots, finding details | Shared factual summary; reporter snapshots cover single-project, workspace, and skipped-project models |
| Bedrock main/executive/technical Markdown | Deterministic outcome, no selected findings, generated analysis, traceable indices, severity, rule IDs, raw details and snippets | Shared outcome and coverage introduction; AWS is stubbed in tests; no live model calls are needed for review |
| MCP lifecycle | Start, progress, results, summary, active scans, cancellation, missing scan IDs, incomplete coverage | Corrected client guidance; lifecycle snapshots and a real Inspector handshake |
| MCP discovery and configuration | Installation, scanners, config read/validation, finding explanation, suppression suggestion, result diff | Registry/result snapshots and tool-reference freshness tests |
| MCP workspace and session interfaces | Resolve/run workspace, missing projects, source delivery by Git/zip, profiles, clear source, errors | Existing contracts reviewed and retained; session/workspace snapshots and schema parity checks |
| MCP resources and prompts | Help, status, exit codes, configuration/suppression schemas, security-analysis prompts | Resource/prompt snapshots and protocol surface golden |
| Editor/agent integrations | Scan command, security scanner workflow, canonical skill, troubleshooting, tool reference, generated platform variants | Edit `_base/`, regenerate all integrations, and run the transpiler drift/validation check |
| Contributor workflow | Build, fixture preview, browser checks, image gallery, package assets, intentional snapshot changes | `scripts/preview_interfaces.py`, `docs/ui-tests/`, and the interface check workflow make review repeatable |

## Reporter and integration contracts

Every shipped reporter is covered by the explicit reporter catalog in `tests/snapshot/support/reporter_catalog.py`. Each is exercised with single-project, workspace, and skipped-project models. The review distinguishes human layout from formats consumed by another application.

| Reporter | Consumer | Review decision |
| --- | --- | --- |
| `html` | Browser / printable artifact | Redesigned, self-contained review interface |
| `markdown` | GitHub comment, Actions summary, Markdown reader | Redesigned, concise outcome and expandable evidence |
| `text` | Terminal, file, stdout | Redesigned information hierarchy |
| `bedrock-summary-reporter` | Main, executive, technical Markdown | Factual outcome and coverage first; traceable and safely formatted details |
| `csv` | Spreadsheet / ingestion | Preserve columns and escaping |
| `flat-json` | Scripts / agents | Preserve wire fields and cached data |
| `sarif` | SARIF consumers | Preserve schema and finding data |
| `github-ghas` | GitHub code scanning | Preserve host integration contract |
| `gitlab-sast` | GitLab vulnerability UI | Preserve schema and attribution |
| `cyclonedx` | SBOM consumers | Preserve component/relationship data |
| `gitlab-cyclonedx` | GitLab dependency UI | Preserve SBOM integration contract |
| `spdx` | SBOM consumers | Preserve document contract |
| `junitxml` | CI test result viewers | Preserve suite/case and failure representation |
| `ocsf` | Security data consumers | Preserve event mapping |
| `yaml` | Structured report readers | Preserve serialization |
| `unused-suppressions` | Suppression maintenance | Preserve the configuration-oriented output |
| `aws-security-hub` | Security Hub findings | Preserve upload payload and mapping |
| `cloudwatch-logs` | CloudWatch Logs | Preserve event payload |
| `s3` | Object storage / ingestion | Preserve uploaded aggregate data |

MCP retains tool names, input/output schemas, resources, prompts, response fields, and transport behavior. Its reviewed golden changes the scan-start description; runtime guidance text changes to name all terminal states.

## Verification and practical limits

The browser matrix checks the homepage at 320, 390, 820, and 1440 pixels in both themes; it checks documentation navigation, indexed search, command copying, keyboard tabs, filters, motion, and no-JavaScript behavior. Report checks cover single-project, workspace, and empty models; responsive layout, both themes, offline operation, filtering, clipboard fallback, printing, and no-JavaScript behavior.

Textual tests use the real app and dialogs. Python coverage also checks reporter compatibility, output escaping, critical threshold detail visibility, incomplete converters/rules, terminal table rendering, progress, configuration flows, report stdout, and JSON-RPC stdout safety.

The snapshot suite reviews CLI help, diagnostics, config prompts, dependency installation, plugins, wrappers, terminal views, every reporter, and MCP results. Golden updates must be reviewed and committed under the repository's `Snapshot-Update` policy.

The package check builds a wheel, confirms all HTML/CSS/JavaScript report assets are included, and renders a report from the installed artifact.

Automated accessibility checks supplement keyboard and visual review. GitHub's exact native styling belongs to GitHub; the local comment preview is an approximation. Container/Nix execution and live AWS uploads are covered by their existing integration jobs rather than by the local visual preview. The flat export's legacy severity representation is retained for consumer compatibility; a versioned normalization change would require its own migration.
