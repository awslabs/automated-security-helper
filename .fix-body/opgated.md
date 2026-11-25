## Adopt `_operator_gated` across the remaining scanners

Follow-up to #1009, which added `ScannerPluginBase._operator_gated(key, wanted, default, refusal)` and moved gitleaks and betterleaks onto it.

Four scanner options still carried their own copy of "operator's value, else the safe default with one warning": zizmor `online_audits` and `honor_inline_ignores`, cfn-lint `honor_inline_ignores`, and the trivy `scanners` set. They now call the base method, and the per-scanner once-flags (`_online_refusal_logged`, `_ignores_refusal_logged`) are gone. Warning text is unchanged.

Direct `set_by_operator` calls left, each a different shape from the base method, pinned by `tests/unit/plugin_modules/test_operator_gated_adoption.py`:

- actionlint `_integration_executable` raises on refusal.
- cfn-guard `_operator_rule_sets` and cfn-lint `_operator_option` substitute the operator's own value, not a fixed default.
- guarddog `_hit_limit` returns a `(value, may_lower)` pair and warns only for a truthy value.

Count of direct `set_by_operator(` calls in `plugin_modules`: 8 before, 4 after (the pin test also covers the planted case).

Verification: on dev-dsk-d14420e2 (`-n 8`, `env -i`), the plugin_modules, base, and hoisted-mechanism families plus the refused-settings and off-host-plugin tests ran on origin/main 84771d0aa4f and on this tip. Failing-id delta against main is 0 new failures (5 existing failures on both). The new pin test is red on main and green here.

### Known difference: trivy warns once per instance

The trivy `scanners` refusal used to warn on every call that saw the refused set. It now goes through `_operator_gated`, which warns once per option per instance. Warning text is unchanged; only the repetition drops. Left as is (LOW).
