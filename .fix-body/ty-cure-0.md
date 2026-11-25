## Clear the ty diagnostics in plugin_modules/, base/, utils/ and core/

### Why

`ty check automated_security_helper/` exits 1 on main (1308 diagnostics at ty 0.0.84, tip 84771d0aa4f), and the CI step that runs it carries `continue-on-error: true` only because of that. The four largest modules hold 1170 of the 1308. This change brings those four to zero so the flag can be removed once the remaining 138 (cli/, config/, workspace/, interactions/, schemas/, models/, plugins/, express/) are cured.

### What changed

Most of the count came from five typing gaps, fixed once each at the source:

- The plugin bases declared `config` as `T | XConfigBase | None` and `context` as `PluginContext | None`, so every `self.config.options.x` and `self.context.source_dir` read as an unguarded Optional (about 640 diagnostics). Each base now declares the narrowed type under `TYPE_CHECKING` only (`config: T`, `context: PluginContext`, plus `results_dir: Path` on scanner and converter bases). The runtime pydantic fields are unchanged, so schemas and behavior are the same.
- `UVToolMixin` did not declare the attributes it reads from `PluginBase` (`command`, `uv_tool_package_name`, `errors`, `_plugin_log`, `_process_command_response`; about 170 diagnostics). They are declared under `TYPE_CHECKING`, and a `_tool_command()` helper gives a `str` where a tool name is required.
- `is_exit_code` is now a `TypeGuard[int]`; `OutputPreference` is a named Literal shared by the subprocess runner, the uv runner and the plugins' `_run_subprocess` overrides.
- SARIF `Message(text=...)` / `PhysicalLocation(...)` calls in npm-audit and detect-secrets construct the RootModel members explicitly (`Message(root=Message1(...))`).
- `logging.VERBOSE` / `logging.TRACE` (added at runtime by `addLoggingLevel`) are replaced by the existing `VERBOSE_LEVEL` / `TRACE_LEVEL` constants.

The rest are individual fixes: `= None` defaults annotated Optional, Optional results guarded where a value is dereferenced, `EnginePhase._execute_phase` drops the `python_based_plugins_only` positional that no subclass shared, `scan_set` accepts a Path (normalized with `os.fspath`), `result_message_text` is overloaded so a call with a default returns `str`, and similar.

### Behavior notes

- `ScannerPluginBase._pre_scan` skips `results_dir.mkdir` when no results directory is set (it raised AttributeError before).
- `uv_tool_mixin` reads the tool name through a module function, not a method, because its arms also run against duck-typed stand-ins.
- `ensure_directories`, the detect-secrets collection read and the cdk-nag wrapper call raise a named error where they used to raise AttributeError or TypeError on None.
- `sarif_utils` builds `Tool(driver=...)` where `Tool()` would have failed validation.

### Suppressions

33 per-line `# ty: ignore[rule]` comments, each with a reason comment beside it. They cover: Windows-only ctypes/winreg attributes, `Future` attributes set by the executor, pydantic fields declared non-optional with a `None` default (`PluginContext.work_dir`, `.config`, `PluginConfigBase.name`; changing them would change the generated JSON schemas), a typeshed gap (`tarfile.EOFHeaderError`), botocore's TypedDict response, `extra="allow"` property bags, rich's `Console(file=...)`, and the `TYPE_CHECKING` constructor defaults on the plugin bases. No file-level or blanket ignores.

### Tests

`tests/unit` on dev-dsk-d14420e2 (env -i, `--basetemp` in the lane, 36 workers, the same desk and flags for both sides): main 642 failed / 65023 passed; branch 625 failed / 65040 passed. Failing ids present only on the branch: one timing-sensitive test (`test_fixture_git_retries_a_runner_timeout`, passes alone on both trees); ids failing only on main: 17 signal-handling tests (load-dependent). Delta 0 regressions. The 600-odd shared failures come from the desk environment and fail identically on main. A first branch run found two real regressions (`safe_scan` called `scan` positionally; the mixin called a method on duck-typed stand-ins), both fixed in the last commit.

### Measured

ty 0.0.84, `uv run --group dev --with 'ty==0.0.84' ty check automated_security_helper/`, same invocation as CI.

| module | before | after |
|---|---|---|
| plugin_modules/ | 760 | 0 |
| base/ | 216 | 0 |
| utils/ | 109 | 0 |
| core/ | 85 | 0 |
| other modules (untouched) | 138 | 138 (diagnostic list identical, line numbers removed) |
| total | 1308 | 138 |

### Not done

- The other eight modules (138 diagnostics) and removing `continue-on-error` from the CI step belong to the ratchet unit.
- Licensing and legal files are untouched.
