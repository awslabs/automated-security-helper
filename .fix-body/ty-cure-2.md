## ty burn-down: schemas, models, plugins, express

Clears every `ty` diagnostic in the four smallest top-level modules (ranks 9-12 by count). Measured with the CI invocation (`ty==0.0.84`, project environment) against `origin/main` at 84771d0aa4f.

| module | before | after |
|---|---|---|
| schemas/ | 9 | 0 |
| models/ | 6 | 0 |
| plugins/ | 5 | 0 |
| express/ | 1 | 0 |

Whole package: 1308 -> 1287 diagnostics. Every diagnostic outside these four modules is unchanged (file and rule list diffed before/after).

### What changed

- `schemas/generate_schemas.py`: `resp` is a `dict[str, Any]` for the whole function. The file mode used to set `resp = None` inside the loop and then the next iteration indexed it. The file mode still returns `None`, now by an explicit `return None if output == "file" else resp`; the return type is annotated.
- `schemas/sarif_schema_model.py`: `invocation_details: dict | None`, `expand(..., base_id: Optional[str])` (the loop already tested it for `None`). The five enum fields whose default is deliberately a plain string (see the module header) carry a per-line `# ty: ignore[invalid-assignment]` with that reason; ty reads pydantic's `Field("warning")` as a `dataclasses.Field` and cannot see the `use_enum_values` conversion. Typing those fields differently would change the generated JSON schemas, so the ignore is the honest form.
- `models/frame_model.py`: `_field_column`, `_knows` take `type[BaseModel]` instead of bare `type`; the four `# type: ignore[attr-defined]` / `[union-attr]` comments they needed are gone (mypy's `warn_unused_ignores` flagged two of them as unused already). The computed-column branch narrows its entry with `isinstance(..., Computed)` and raises `FrameSpecError` otherwise.
- `models/flat_vulnerability.py`: `_extract_message_text` reads each attribute once into a local before testing it for `None`.
- `models/asharp_model.py`, `express/daemon.py`: `setattr` for the two assignments the type system cannot express (a function attribute pydantic reads; `atexit.register` replaced for the span of a block).
- `plugins/loader.py`: the plugin-module name check builds a `List[str]`. A non-string entry is read by its text (and refused as a misnamed path) where it used to fail on `.split`; a falsy non-string entry is dropped, as before.

### Verification

- ty on the four modules: 21 -> 0 (`All checks passed!`).
- `ruff check` and `ruff format --check`: clean. mypy: the two remaining errors (`utils/cdk_nag_wrapper.py:2050`, `checkov_scanner.py:599`) are outside these modules and unchanged.
- Unit tests of the touched families (847 files that reference the touched modules, 22,336 tests): 2 failed, 20,459 passed, 1,875 skipped. Both failures (`test_client_delegation.py::TestClassification::test_the_non_scan_list_matches_the_registered_cli`, `test_scan_baseline_option.py::test_baseline_options_do_not_shift_existing_positional_arguments`) fail identically on `origin/main` on the same desk: delta 0.
