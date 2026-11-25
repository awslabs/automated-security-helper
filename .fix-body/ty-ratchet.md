## ty count ratchet

The ty step in `lint` exits 1 today (1308 diagnostics at ty 0.0.84: 1290 errors, 18 warnings), so it runs with `continue-on-error` and new diagnostics can land unnoticed. This adds a gate that can always pass at the ceiling.

- `scripts/ty_ceiling.txt` pins the ceiling (1308).
- `scripts/check_ty_ratchet.py` reads the saved ty output, takes the total from ty's closing `Found N diagnostics` line, and exits 1 above the ceiling. A run with no total (a crash) exits 2, never a pass.
- A new `lint` step, without `continue-on-error`, runs ty and then the script. Cure PRs lower the ceiling in the same change.
- Flag-delete condition: when the count reaches 0, delete the informational ty step's `continue-on-error` and the ratchet step.

Tests: `tests/unit/test_check_ty_ratchet.py`.
