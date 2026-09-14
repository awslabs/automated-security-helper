# Ferret-Scan Plugin Update Analysis

**Date:** 2026-09-13
**Author:** analysis prepared for the ferret-scan plugin v2 update
**Branch:** `feature/ferret-scan-plugin-v2-update` (cut from `origin/main`)
**Scope:** Bring the ASH `ash_ferret_plugins` integration into alignment with the
current ferret-scan release line (**v2.4.5**), identify new capabilities worth
surfacing, and enumerate incompatibilities that must be resolved.

---

## 1. Executive Summary

The ASH ferret-scan plugin was written against an early ferret-scan (`0.x`/`1.0`)
and declares a **hard compatibility ceiling of `<2.0.0`**. The upstream tool is now
at **v2.4.5** — the *entire* current release line is outside the plugin's supported
window, and `RECOMMENDED_VERSION = "1.0.0"` predates every 2.x feature.

The single highest-impact issue is the documented **`API_KEY_OR_SECRET` false-positive
incident** (ferret-scan v2.3.3): unquoted-assignment detection flags
`session: Optional[Session]` in generated Pydantic schemas at ~95% HIGH confidence.
This is what turns PRs red and is the practical reason a version bump was deferred.

This update is fundamentally a **version-window realignment** plus a small set of
**correctness fixes** (notably `--limit`), with an optional second track of
**feature surfacing** (new detectors and new CLI flags).

---

## 2. Sources Reviewed

**ASH-side (this repo):**
- `automated_security_helper/plugin_modules/ash_ferret_plugins/ferret_scanner.py` (implementation)
- `.../README.md`, `.../DEVELOPMENT.md`, `.../ferret-config.yaml`, `.../__init__.py`
- `CONTRIBUTING.md`, `DEVELOPMENT.md` (contribution + plugin-dev guidelines)
- Existing remote branch `origin/feature/ferret-scan-plugin-updates` (one prior commit,
  `435eba0 feat: update ferret scan plugin scanner, config, docs and tests` — based on a
  stale point far behind current `main`)

**Upstream ferret-scan (`/home/prabnik/dev/ash-workload/ferret-scan`, v2.4.5):**
- `CHANGELOG.md`, `git tag`/`git log`, `cmd/main.go` (flag surface), `config.yaml`
- `docs/configuration.md`, `docs/validators-new.md`, `docs/upstream-asks.md`,
  `docs/suppression-system.md`, `docs/social-media-configuration.md`, `THREAT_MODEL.md`
- Unmerged fix branches: `fix/661-sarif-helpuri-404`, `fix/662-sarif-descriptions`

---

## 3. Current Plugin State

| Aspect | Current value |
|---|---|
| `MIN_SUPPORTED_VERSION` | `0.1.0` |
| `MAX_SUPPORTED_VERSION` | `2.0.0` (exclusive) |
| `DEFAULT_VERSION_CONSTRAINT` | `>=0.1.0,<2.0.0` |
| `RECOMMENDED_VERSION` | `1.0.0` |
| Install path | `pip install ferret-scan<constraint>` via `get_installation_commands` |
| Output | always `--format sarif`, always `--no-color` |
| Flags emitted | `--format sarif`, `--output`, `--file`, `--confidence`, `--checks`, `--recursive`, `--config`, `--profile`, `--exclude` (single comma-joined), `--show-match`, `--enable-preprocessors`, `--debug` (via `ferret_debug`), `--verbose` (via `ferret_verbose`), `--no-color` |
| Supported plugin options | `confidence_levels, checks, recursive, config_file, use_default_config, profile, exclude_patterns, show_match, enable_preprocessors, ferret_debug, ferret_verbose, tool_version, skip_version_check` |
| Blocked options | `format, output_format, web, port, enable_redaction, redaction_output_dir, redaction_strategy, redaction_audit_log, memory_scrub, generate_suppressions, show_suppressed, suppressions_file, extract_text, debug, verbose` |
| Documented check list (README) | `CREDIT_CARD, EMAIL, INTELLECTUAL_PROPERTY, IP_ADDRESS, METADATA, PASSPORT, PERSON_NAME, PHONE, SECRETS, SOCIAL_MEDIA, SSN` (11) |
| Return contract | `SarifReport` / `True` (nothing to scan) / `False` (deps) / `None` (unparseable) / raw `dict` / `raise ScannerError` |

The plugin behaviour is otherwise solid: no `shell=True`, list-arg subprocess,
Pydantic-validated options, `Path.as_posix()` for Windows-safe args, exclude joined
into one comma-separated `--exclude`, and a pre-push validation script
(`scripts/validate_ferret_plugin.py`) that mirrors CI checks.

---

## 4. Upstream Release Delta (v2.0.0 → v2.4.5)

> **CHANGELOG caveat:** upstream's `CHANGELOG.md` version headers stop at `v1.7.0`;
> all 2.x work sits under one giant `[Unreleased]` block (git-chglog was removed).
> Version attribution below is from `git tag` + `git log` cross-checked against prose.

### 4.1 New detector / check types (all work today via `--checks`)
`BANK_ACCOUNT`, `OTP` (two-factor), `DATE_OF_BIRTH`, `PHYSICAL_ADDRESS`/`ADDRESS`,
`DRIVERS_LICENSE`, `MEDICAL_ID` (PHI), `VIN`, `CLOUD_RESOURCES` (AWS ARNs, Azure/GCP/
OCI/IBM/Alibaba IDs), plus AWS secret-access-key coverage inside
`SECRETS`. (`KEYWORD_MATCH` is an internal validator, not a selectable `--checks` value —
it does not appear in `ferret-scan --help checks`.) **The plugin's `checks` field is a
free-form string passed straight to `--checks`, so these already function** — but the
README/docs advertise only 11 of
~21 available checks. Authoritative list is `ferret-scan --help checks` (do NOT
hardcode).

### 4.2 New CLI flags in range (candidates to surface)
- `--limit <int>` (**default 200**) — truncates displayed findings by confidence.
  **Silent correctness gap** for ASH: large trees can drop findings unless we pass
  `--limit 0`.
- `--explain` — offline per-finding rationale + real/test/uncertain verdict +
  drafted suppression reason. Fully local, no network.
- `--fail-on-incomplete` — exit **3** when files couldn't be fully scanned
  (timeouts/budgets/unreadable). Integrity signal.
- `--disable-ip-types` — turn off IP sub-types (`copyright,patent,trademark,trade_secret,internal_url`).
- `--validator-budget NAME=DURATION` — per-validator time budgets (CI hardening).
- `--max-live-bytes` — memory ceiling for extracted content (constrained hosts).
- `--respect-gitignore` — opt-in `.gitignore` honoring (default off).
- `--stdin` / `--stdin-name`, `--preprocess-only`/`-p`, `--quiet`, `--pre-commit-mode`,
  `--list-profiles` — not relevant to ASH batch scanning.

### 4.3 Behavioural / breaking changes
- **SARIF empty results:** `null` → **empty array `[]`** (v2.3.1) when nothing found.
- **SARIF `file:` URI reshaped:** empty authority + percent-encoded path (v2.4.5, #634).
- **Validator panics** now surface as SARIF `toolExecutionNotifications` warnings +
  **exit code 3** under `--fail-on-incomplete` (v2.4.5, #658).
- **Text summary moved to bottom** of text output (v2.1.x) — irrelevant to us (SARIF).
- **Config discovery is now CWD-first:** ferret-scan searches the scanned tree for
  `config.yaml`/`ferret.yaml`/`ferret.yml`/`.ferret-scan.yaml` *before* the user config
  dir. A config file in the target tree now governs the scan (TM-13).
- **GenAI fully removed:** no Textract/Transcribe/Comprehend, no `--enable-genai`, no
  outbound AWS/HTTP calls anywhere. The tool is offline.
- **Web server** binds `127.0.0.1` by default now (`--bind` to change) + CSRF/headers.
- **Config schema tightened** (v2.2.x): dead documented options removed/renamed;
  unknown keys captured and warned.

### 4.4 Coming in the *next* release (unmerged, watch these)
- `fix/661-sarif-helpuri-404` — every finding's `helpUri` was a 404; being repointed to
  a generated anchored page → **helpUri values will change**.
- `fix/662-sarif-descriptions` — real descriptions written for every detection type in
  SARIF + gitlab-sast → rule/result descriptions populated where previously empty.

---

## 5. Incompatibilities & Discrepancies

### 5.1 Blocking — version window (P0)
`DEFAULT_VERSION_CONSTRAINT = ">=0.1.0,<2.0.0"` excludes **all** current releases.
`get_installation_commands` will install the newest release satisfying the constraint —
which no longer exists in that range against PyPI's current index, and
`_check_version_compatibility()` will warn on every real install. Must widen the window
and re-anchor `RECOMMENDED_VERSION`.

### 5.2 High — `API_KEY_OR_SECRET` false positives (P0)
ferret-scan v2.3.3 (`SECRETS` validator, commit `50bd9a7`, #395) added unquoted
`keyword: value` detection. `session` is a secret keyword stem, so generated
`session: Optional[Session]` → `API_KEY_OR_SECRET` at ~95% HIGH. Code-file context does
not demote it enough. Mitigations (pick one or combine):
- Ship `validators.secrets.disabled_types: [API_KEY_OR_SECRET]` in bundled
  `ferret-config.yaml` (disables just the generic type, keeps real secret detection).
- Scope `SECRETS` off generated-schema paths via `exclude_patterns`.
- Add suppressions (`.ash/.ash.yaml` **and** `.ash/.ash_community_plugins.yaml`).

### 5.3 High — `--limit 200` silently truncates findings (P1)
The plugin never passes `--limit`, so ferret-scan caps output at 200 findings by
confidence. On a large repo, findings are silently dropped. Fix: emit `--limit 0`
(or a large explicit value) by default.

### 5.4 Medium — `--exclude` semantics documented incorrectly (P2)
`DEVELOPMENT.md`/`README.md` state ferret-scan `--exclude` uses "simple name matching,
not glob patterns." Actual behaviour (`isExcluded`, `cmd/main.go`): Go
`filepath.Match` glob (`*`, `?`, `[abc]`) **is** supported (only `**` globstar is not),
**plus** a `strings.Contains` substring branch and a `dir/`-segment branch. The
single-comma-joined `--exclude` value the plugin builds is correct, but the docs are
wrong and the substring branch means a bare token (`test`, `build`) over-excludes any
path containing it. Update docs; keep the join behaviour.

### 5.5 Medium — config double-discovery / precedence (P2)
The plugin auto-discovers `ferret.yaml`/`.ferret.yaml`/`.ash/ferret*.yaml` in the source
dir and passes `--config`. Independently, ferret-scan v2.x now auto-discovers
`config.yaml`/`ferret.yaml` in the **scanned tree (CWD)** even without `--config`. With
ASH `os.chdir(source_dir)`, a stray config in the target could take effect and could
even **disable detection** (TM-13). Consider passing an explicit `--config` always, and
documenting the interaction. (No `--disable-config-discovery` CLI flag exists; that
control is API-only.)

### 5.6 Low — stale docs / bundled config drift (P3)
- Bundled `ferret-config.yaml` still carries `# GENAI_DISABLED:` blocks and GenAI
  profile stubs for features that **no longer exist** in the engine. Harmless (comments)
  but misleading; safe to prune when refreshing from upstream `config.yaml`. **Status:**
  consciously deferred (WL-6) — a config refresh, not a correctness issue. The `defaults`
  block's `format: text` / `recursive: false` only look wrong in isolation; CLI flags
  override them at runtime (verified — see §9.6).
- `DEVELOPMENT.md` edge-case note said empty dir yields `results: null` — upstream now
  emits `[]`. Fixed in A6.
- README documented 11 checks; **19** exist (`ferret-scan --help checks`). Fixed in A6.
  (An earlier draft of this doc referenced an `INTERNAL_URL_MIGRATION_GUIDE.md` in the
  bundled config — that reference is **no longer present** in the file, so this sub-point
  was itself stale and is retracted.)

### 5.7 Non-issue — GenAI block-list entries
The plugin blocks `enable_redaction`, `redaction_*`, `memory_scrub`,
`generate_suppressions`, `show_suppressed`, `suppressions_file`, `web`, `port`,
`extract_text`. **All of these still exist** as real ferret-scan flags, so the guards
remain valid. There is no `--enable-genai` option to guard (it was removed), so no new
GenAI block-list entry is needed. `extract_text` maps to `--preprocess-only`/`-p` today.

---

## 6. Recommended Changes (proposed)

### Track A — Realignment + correctness (required to unblock)
1. **Version constants** in `ferret_scanner.py`:
   - `MIN_SUPPORTED_VERSION` → `2.3.4` (first release past the FP-incident fixes) or
     keep `2.0.0` if broad support is desired.
   - `MAX_SUPPORTED_VERSION` → `3.0.0` (exclusive).
   - `DEFAULT_VERSION_CONSTRAINT` → e.g. `>=2.3.4,<3.0.0` (see open question).
   - `RECOMMENDED_VERSION` → `2.4.5`.
2. **`--limit 0`**: add an option (default emits `--limit 0`) so findings aren't
   truncated. Consider `finding_limit: int = 0`.
3. **API_KEY_OR_SECRET mitigation**: add `validators.secrets.disabled_types:
   [API_KEY_OR_SECRET]` to bundled `ferret-config.yaml`, and/or document the
   suppression + exclude approach. Update `scripts/validate_ferret_plugin.py` if the FP
   surface changes.
4. **Doc corrections** (§5.4, §5.6): fix `--exclude` semantics, empty-result note,
   check list, GenAI references.

### Track B — Feature surfacing (optional, additive)
5. New plugin options mapping to new flags: `explain` (`--explain`),
   `fail_on_incomplete` (`--fail-on-incomplete`), `disable_ip_types`
   (`--disable-ip-types`), `validator_budget` (`--validator-budget`), `max_live_bytes`
   (`--max-live-bytes`), `respect_gitignore` (`--respect-gitignore`).
6. Document the new detectors (`BANK_ACCOUNT, OTP, DATE_OF_BIRTH, PHYSICAL_ADDRESS,
   DRIVERS_LICENSE, MEDICAL_ID, VIN, CLOUD_RESOURCES`) in README's
   Available Checks section.
7. Handle exit code 3 (`--fail-on-incomplete`) sensibly in the return contract if
   adopted (currently `executionSuccessful = exit_code == 0`).

### Track C — Test + CI (accompanies A/B)
8. Update `tests/unit/plugin_modules/ash_ferret_plugins/test_ferret_scanner.py`
   (version-support tests, new-option tests, unsupported-option tests). Keep
   `EXPECTED_MIN_TESTS` / `TEST-COUNT` in sync.
9. Run `uv run python scripts/validate_ferret_plugin.py` and the ferret unit suite
   before pushing (mirrors CI `--ignore-suppressions` scan).
10. Per `DEVELOPMENT.md`, mirror any new suppressions into **both** `.ash/.ash.yaml`
    and `.ash/.ash_community_plugins.yaml`.

---

## 7. Files That Will Change (per DEVELOPMENT.md matrix)

| Change | Files |
|---|---|
| Version bump | `ferret_scanner.py`, `README.md`, `docs/.../ferret-scan-plugin.md` |
| New option | `ferret_scanner.py`, `README.md`, `docs/.../ferret-scan-plugin.md`, `test_ferret_scanner.py` |
| Bundled config | `ferret-config.yaml` |
| FP mitigation | `ferret-config.yaml`, `.ash/.ash.yaml`, `.ash/.ash_community_plugins.yaml`, `scripts/validate_ferret_plugin.py` |
| Docs | `README.md`, `DEVELOPMENT.md`, community `index.md` |

---

## 8. Open Questions (for the requester)

1. **Version window target:** pin conservatively to the tested current line
   (`>=2.3.4,<2.5.0`), allow the whole 2.x major (`>=2.3.4,<3.0.0`), or keep a wide
   floor (`>=2.0.0,<3.0.0`)? This drives `MIN/MAX_SUPPORTED_VERSION`.
2. **Scope:** Track A only (unblock + correctness), or A **and** B (surface new
   detectors/flags as plugin options)?
3. **Existing branch:** should the prior work on `origin/feature/ferret-scan-plugin-updates`
   (`435eba0`) be folded in, or is starting fresh from `main` correct? (I started fresh.)
4. **API_KEY_OR_SECRET policy:** disable the generic type globally in the bundled config
   (cleanest, loses generic-secret detection), or keep it and rely on
   suppressions/excludes (retains detection, more maintenance)?
5. **`--fail-on-incomplete`:** adopt it (surfaces partial-scan integrity as exit 3, needs
   return-contract handling), or leave it off for now?

---

## 9. Decisions & Findings — Resolved (2026-09-13)

### 9.1 Requester decisions (locked)
1. **Version window:** pin **conservatively to the tested current line** →
   `DEFAULT_VERSION_CONSTRAINT = ">=2.4.5,<2.5.0"`, `MIN_SUPPORTED_VERSION = "2.4.5"`,
   `MAX_SUPPORTED_VERSION = "2.5.0"`, `RECOMMENDED_VERSION = "2.4.5"`. (Narrower than the
   `>=2.3.4,<3.0.0` originally floated — chosen to guarantee we only claim support for a
   version we actually test against.)
2. **Scope:** deliver **Track A first**, then Track B.
3. **Old branch:** start fresh from `main` (done); mine
   `origin/feature/ferret-scan-plugin-updates` for carry-over (see §9.3).
4. **API_KEY_OR_SECRET:** **disable the generic type globally** in the bundled
   `ferret-config.yaml`; document as an explicit design decision in DEVELOPMENT.md and
   README.md. (Named secret patterns stay on.)
5. **`--fail-on-incomplete`:** **adopt it**, with exit-code-3 handling in the return path.

### 9.2 Posture updates (verified against the installed binary)
- ferret-scan **v2.4.5 is installed** in this environment; all findings below were
  confirmed against `ferret-scan --help` / `--help checks`, not just the docs.
- **Authoritative check list = 19 checks** (see work log). README documents 11 — the gap
  is real; A6/B6 will reconcile it. Never hardcode the list (upstream `upstream-asks.md`
  explicitly warns integrators about doc drift).
- `--limit` default **200** confirmed (`0` = unlimited) → A2 is a genuine correctness fix.
- `--exclude` help text itself shows glob usage (`--exclude '.git,*.log'`), confirming the
  plugin/README "simple names only" wording is wrong (§5.4).
- Baseline **69 unit tests pass**; `scripts/validate_ferret_plugin.py` `EXPECTED_MIN_TESTS`
  is **67** (stale-low vs the 69 present). DEVELOPMENT.md still cites "66 tests" in places —
  a stale assumption to correct as tests are added.

### 9.3 Old-branch carry-over analysis (`origin/feature/ferret-scan-plugin-updates` @ `435eba0`)
That branch is based on a commit **predating the current incident fixes on `main`**, so
its diff *removes* work we must keep. Classification:

**Do NOT carry (regressions relative to current `main`):**
- Deletion of `get_installation_commands` — this is the very fix that pins the install to
  the supported range (the anti-incident guard). Keep it.
- Deletion of `offline_strategy = OfflineStrategy.BUNDLED`. Keep it.
- Deletion of `_execute_scan` stub, removal of subprocess `timeout=self._effective_scan_timeout()`,
  and reverting `shlex.join(...)` → `" ".join(...)` for the SARIF `commandLine`. All are
  regressions; keep current `main` behaviour.
- Weakened "binary not found" error message. Keep current, richer guidance.

**Worth carrying (genuinely new, additive):**
- `respect_gitignore` → `--respect-gitignore` → **B1**.
- `disable_ip_types` → `--disable-ip-types` → **B2**.
- Block-list additions `preprocess_only`, `pre_commit_mode`, `list_profiles` → **A5**
  (cheap, safe, correct — pulled forward into Track A).
- Always append `--quiet` (progress output is noise ASH captures on stderr) → folded into
  **A5** as a low-risk convention change.

### 9.4 Revised file-change map (supersedes §7 where they differ)
- A1 version pin also touches the install-command test's inline comment (it references
  "2.3.3 past MAX_SUPPORTED_VERSION", which is no longer true once MAX=2.5.0).
- A3 records design decision **DD-1** in DEVELOPMENT.md + README.md, edits
  `ferret-config.yaml`, and re-checks `scripts/validate_ferret_plugin.py` (the
  SUPPRESSION-COVERAGE check may need no change since we disable at the tool level, not via
  ASH suppressions — to be confirmed when A3 lands).
- A4 adds return-contract handling for exit code 3; DEVELOPMENT.md "Scanner Return Contract"
  section gets a note that `--fail-on-incomplete` can make ferret-scan exit 3 with valid SARIF.

### 9.5 ⚠️ Assumption invalidated — API_KEY_OR_SECRET cannot be disabled via config (2026-09-13)

**Original assumption (analysis §5.2, and the sub-agent recommendation):** the bundled
`ferret-config.yaml` could disable the generic finding type with
`validators.secrets.disabled_types: [API_KEY_OR_SECRET]`. **This is false for ferret-scan
v2.4.5.**

**Evidence (tested against the installed binary):**
- `disabled_types` is honored **only by the `intellectual_property` validator**. Source:
  `internal/validators/intellectualproperty/disabled_subtypes.go` and
  `docs/configuration.md`: *"A `disabled_types` block under a validator that does not read
  it — every validator except `intellectual_property` — is correctly silent."* The
  `secrets` validator's own help says *"No additional configuration is required."*
- Empirical scan of a Pydantic-style file (`session: Optional[Session] = None`) with
  `--checks SECRETS`:
  - Without config: **4 `API_KEY_OR_SECRET` findings**, the `session` line at **93 (HIGH)** —
    the incident pattern **still reproduces in v2.4.5** (it was not fixed after v2.3.3).
  - With `validators.secrets.disabled_types: [API_KEY_OR_SECRET]`: **still 4 findings** —
    the config block is silently ignored, exactly as the source predicts.

**Consequence:** decision #4 ("disable the generic type globally in the bundled config")
is **not implementable as stated** — the tool provides no such knob. The requester's
*intent* (API_KEY_OR_SECRET must not redden PRs / flood FPs, off by default, documented)
is still achievable, but only via a different mechanism.

**Working mechanisms (in order of fidelity to the intent):**
1. **Plugin-level post-filter (recommended):** drop `API_KEY_OR_SECRET` results from the
   `SarifReport` before returning, gated by a new option (e.g.
   `suppress_generic_secret: bool = True`). Fully within the plugin's control, default-on,
   documentable as DD-1, and keeps every *named* secret pattern (AWS keys, GitHub tokens,
   etc.) active. Downside: post-processing filter rather than a tool-native disable.
2. **ASH suppression** (`rule_id: API_KEY_OR_SECRET` in `.ash/.ash.yaml` +
   `.ash_community_plugins.yaml`): fixes ASH's *own* CI self-scan (the red-PR symptom) but
   does not change behaviour for downstream plugin users.
3. **Drop `SECRETS` from default checks:** rejected — loses all secret detection.

**Status:** RESOLVED (2026-09-13). Requester chose to **keep `API_KEY_OR_SECRET` enabled
and rely on suppressions/excludes** (not the post-filter). Implemented as A3:
- Scanning the repo at v2.4.5 with the plugin's config (`SECRETS`, high confidence)
  surfaced **6 high-confidence `API_KEY_OR_SECRET` false positives** — all the incident
  shape (a `session`/`secret` keyword next to an assignment): the two generated OCSF
  model fields, the MCP `sessions.py` local, the Fargate `manage_auth_secret` local, and
  two `test_sessions.py` locals. The config's old "ferret-scan contributes nothing"
  comment was **stale** (true for the pre-2.x binary only) and has been corrected.
- Added path-scoped `API_KEY_OR_SECRET` suppressions to `.ash/.ash_community_plugins.yaml`
  (OCSF generated schema, `cli/mcp/sessions.py`, `fargate/main.tf`, `tests/**`), with
  reasons paraphrased so they don't re-trigger the detector on the YAML itself.
- Documented as a design decision in DEVELOPMENT.md ("Design decision: API_KEY_OR_SECRET
  stays ENABLED") and README.md (user-facing note + suppression recipe).
- **Verified end-to-end:** `ash scan --scanners ferret-scan --config
  .ash/.ash_community_plugins.yaml` → ferret-scan **PASSED, 0 actionable** (8 findings, all
  suppressed). Unit tests 79 green; `validate_ferret_plugin.py` 10/10; the new doc/reason
  text produces 0 self-findings; `ash config validate` passes.

  *(Update per WL-10: the `tests/**` suppression above was later narrowed to the single
  real FP file `tests/unit/cli/mcp/test_sessions.py`.)*

### 9.6 ⚠️ Assumption invalidated — bundled config does NOT override CLI `--exclude` (2026-09-14)

**Original claim (DEVELOPMENT.md gotcha §10, README note, and the `CONFIG-OVERRIDE-EXCLUDES`
validation check):** with the bundled `ferret-config.yaml` loaded via `--config`, ferret-scan
overrides CLI args, so ASH's `--exclude` may be "silently ignored" unless
`use_default_config: false`. **This is backwards for v2.4.5.**

**Evidence (tested against the installed binary):**
- `--config <bundled> --exclude skipdir` (recursive) → `skipdir` **is** excluded; only the
  other dirs are scanned. CLI `--exclude` wins.
- `--config <bundled> --recursive` → nested files **are** found, even though the bundled
  config's `defaults` set `recursive: false`. CLI `--recursive` wins.

**Consequence:** ASH's `exclude_patterns` + `global_ignore_paths` (folded into `--exclude`)
are honoured **regardless of `use_default_config`** — a security-relevant guarantee (ignore
paths are respected). `use_default_config` only governs whether the bundled validator/profile
patterns load. **Resolution:** corrected DEVELOPMENT.md §10, the README + registration
`use_default_config` notes, and **removed** the `CONFIG-OVERRIDE-EXCLUDES` check (it enforced
the false premise) — the validation script now has **9** checks, all passing. Caveat: a
hand-written config that *itself* declares excludes could add to the CLI value; the bundled
config declares none.
