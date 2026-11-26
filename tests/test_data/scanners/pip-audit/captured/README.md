# pip-audit captured fixtures

- `requirements.txt`: the input, two exact pins (`pyyaml==5.3`, `idna==3.7`).
- `pip-audit-2.10.1.json`: the report from a networked run (content unedited; the
  repository's json formatter re-indented it) of
  `uv tool run --from pip-audit==2.10.1 pip-audit --format=json
  --vulnerability-service=pypi --progress-spinner=off --desc=on --aliases=on
  --no-deps --disable-pip --requirement=requirements.txt`
  (exit status 1, which pip-audit uses for "vulnerabilities found"). Both
  dependencies carry advisories, so this capture holds no clean dependency.
  The service returned `PYSEC-2021-142` and `PYSEC-2020-96` twice under
  `pyyaml`, and `PYSEC-2026-215` twice under `idna`; the converter keeps one
  result per package and advisory.
- `positive.sarif`: `convert_pip_audit_json` over that report with
  `uri="requirements.txt"`. The facets corpus gate reads it.

The advisory set changes as the service adds records, so a re-capture will not
be byte-equal; the tests assert shape and counts for this capture only.
