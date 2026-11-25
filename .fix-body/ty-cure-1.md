## ty: clear the diagnostics in cli, config, workspace and interactions

`ty check automated_security_helper/` (ty 0.0.84, the version CI pins) reported 1308 diagnostics on main. This clears the four modules ranked 5 to 8 by count (cli, config, workspace, interactions): 117 diagnostics, now 0. The package total falls from 1308 to 1191, and the set of diagnostics outside those modules is unchanged (no new one appears anywhere).

| module | before | after |
|---|---|---|
| cli/ | 74 | 0 |
| config/ | 23 | 0 |
| workspace/ | 11 | 0 |
| interactions/ | 9 | 0 |

### What changed

Type fixes, not blanket ignores:

- Optional parameters annotated as optional (`str | None = None`, `Optional[List[str]]`) where the default was `None`; `ExecutionStrategy` defaults given as the enum member rather than its `.value`.
- `ash config update`: the body that rebinds the config path from `str` to `Path` moved into its own function that takes a `Path`, so no parameter changes type mid-function.
- Narrowing where an invariant already held but the checker could not see it: `Optional` results checked before use (`path containment`, the omitted-source-directory resolution, the overlay's refuse-env, the baseline in the staged-scan check), with a `RuntimeError` on the branch that cannot be reached.
- Literal types carried through instead of widened to `str`: plugin kinds (`PluginKind`), the sandbox mode (`SandboxModeName`), the workspace results status, `_PLUGIN_TYPES`.
- In workspace policy, the `type: ignore` on the suppressions tuple becomes a `cast` to `tuple[AshSuppression, ...]` (the entries keep their class through `model_copy`), and the project prefix is handed to the pattern converter as text or a POSIX path, which is what it accepts.
- `anyio.to_thread` is imported as `from anyio import to_thread`, which the checker resolves.
- The MCP scan-monitor task set is a module-level set instead of an attribute stuck on the tool function.
- Where an attribute is attached to an object that does not declare it (a YAML node, a `CompletedProcess`), `setattr` with a comment says so.

Per-line suppressions that remain: the DataTable row key in the findings inspector (the handlers read the integer index back; Textual accepts any hashable key although its annotation says `str`), and the twelve MCP progress-monitor logging calls marked `ty: ignore[deprecated]`. The MCP logging capability is deprecated (SEP-2577), but this server's clients read those notifications as the scan's progress narrative, so the calls stay; the existing guard tests require each one to sit inside the guarded send, which a shared helper would break.

`run_command` in utils now accepts `list[str] | str` for `args`, which is what a one-line `shell=True` command already passed.

### Verification

- ty, same pinned version, same invocation, on a clean desk checkout: 1308 before, 1191 after; the four modules read 0; a before/after diff of every diagnostic line (position stripped) shows nothing added.
- ruff check and ruff format --check pass on the package.
- Unit suite (tests/unit, 40 workers, env -i, per-lane basetemp) on the same desk, main against this branch: 82 failed and 65581 passed on both, and the failing ids are the same set (0 new failures).
