# zizmor fixtures

`repo/` is a small tree with known positives and negatives for the zizmor
scanner. Nothing here is executed; GitHub only runs workflows from the
repository's own top-level `.github/workflows`.

Positives: `repo/.github/workflows/vulnerable.yml` (template injection,
dangerous triggers, unpinned uses, credential persistence, default permissions)
and `repo/actions/greet/action.yml` (template injection in a composite action).

Negatives: `clean.yml`, `actions/clean/action.yaml`, the vendored copy under
`node_modules/` (excluded by ASH), `nested/not-a-workflow.yml` (not a workflow
location) and `other/action.yml` (not an Actions definition).

`zizmor-1.30.1.sarif` is real zizmor output for the four files ASH selects,
captured from a copy of the fixture root outside any git repository (inside
one, zizmor writes URIs relative to the repository root instead) with:

    zizmor --format sarif --no-exit-codes --no-progress --color never \
      --persona regular --offline -- \
      .github/workflows/clean.yml .github/workflows/vulnerable.yml \
      actions/clean/action.yaml actions/greet/action.yml other/action.yml
