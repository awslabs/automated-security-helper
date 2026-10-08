#!/usr/bin/env bash
# Body of "Validate GitLab SAST Report Schema Compliance" in action.yml, moved here
# unchanged so that step can choose which bash runs it. On the Windows python-local
# leg, setup-ruby's MSYS2 directories are first on PATH for the rest of the job, so
# `shell: bash` would resolve to MSYS2's bash; the step launches Git Bash by
# absolute path instead. Run from the workspace root, with `-eo pipefail` like a
# `shell: bash` step.
echo "Validating GitLab SAST report schema compliance..."
GITLAB_REPORTS=$(find .ash/ash_output -name "*.gl-sast-report.json")
if [ -z "$GITLAB_REPORTS" ]; then
  echo "ERROR: GitLab SAST report not found in .ash/ash_output"
  exit 1
fi
echo "Found GitLab SAST reports to validate:"
echo "$GITLAB_REPORTS"

# Both network operations below used to be unretried, and the npm one took the
# job down: on pull request #582, run 35177045049, job 105060929678,
# `npm install -g ajv-cli` hit `ECONNRESET` reaching registry.npmjs.org and the
# step's `-e` ended the job before a single report was validated. Nothing about
# that failure concerned the code under test.
#
# Same retry shape as the tool-install step in action.yml. Redefined
# rather than shared because each `run:` block is its own shell, so a function
# defined in another step is not in scope here.
retry() {
  local attempts=3 n=1
  until "$@"; do
    if [ "$n" -ge "$attempts" ]; then
      echo "::error::'$*' failed after ${attempts} attempts"
      return 1
    fi
    echo "::warning::'$*' failed (attempt ${n}/${attempts}); retrying in $((n * 10))s"
    sleep $((n * 10))
    n=$((n + 1))
  done
}

# ajv-cli pinned to a major. Unpinned, this step validated against whatever
# validator was newest, so a breaking ajv release could fail the gate on
# reports that had not changed -- the same class of problem as the floating
# schema below, one layer up.
retry npm install -g ajv-cli@5

# The schema is fetched at the version the reporter DECLARES conformance to,
# not from `master`. It was `master`, which made this gate validate against
# whatever GitLab had merged most recently: measured 2026-09-17, `master` was
# schema 15.2.5 while the reporter emits 15.2.2, a 1,030-byte difference with a
# different digest. A gate whose contract can change without a commit here can
# start failing for reasons unrelated to the code, which is the defect.
#
# Read from the reporter so the two cannot disagree, in the same shape as the
# ferret-scan constraint lookup in action.yml.
SCHEMA_VERSION="$(python -c 'from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import GITLAB_SAST_SCHEMA_VERSION as v; print(v)')"
if [ -z "${SCHEMA_VERSION}" ]; then
  echo "::error::Could not read GITLAB_SAST_SCHEMA_VERSION from the GitLab SAST reporter. Refusing to validate against an unpinned schema."
  exit 1
fi
echo "Validating against GitLab security-report schema v${SCHEMA_VERSION} (the version the reporter emits)"

# `-f` matters now that the URL contains a version: without it curl exits 0 on
# a 404 and writes GitLab's error page to the file, and ajv then fails with a
# parse error that says nothing about the tag being wrong. The upstream tags
# carry a `v` prefix; a bare `15.2.2` is a 404.
retry curl -sSfL -o gitlab-sast-schema.json \
  "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v${SCHEMA_VERSION}/dist/sast-report-format.json"
VALIDATION_FAILED=false
for report in $GITLAB_REPORTS; do
  echo "Validating $report..."
  if ajv validate -s gitlab-sast-schema.json -d "$report" --strict=false --all-errors; then
    echo "PASS: $report passed schema validation"
  else
    echo "FAIL: $report failed schema validation"
    VALIDATION_FAILED=true
  fi
done
if [ "$VALIDATION_FAILED" = true ]; then
  echo "ERROR: One or more GitLab SAST reports failed schema validation"
  exit 1
else
  echo "SUCCESS: All GitLab SAST reports passed schema validation"
fi
