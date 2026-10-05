"""Names, paths and limits the operator holds constant.

Everything here is either a Kubernetes identifier the CRDs and the controller
must agree on, or a path baked into the volume layout. The paths are *not*
user-configurable, and that is deliberate: ``ash scan`` checks source/output
collision by equality only (``cli/scan.py`` compares the two absolute paths),
while ``ash merge`` checks equality **or** ancestry and its own docstring says so.
So ``--output-dir /src`` with ``--source-dir /src/app`` passes the scan check, and
the symptom is a green scan reporting zero findings rather than an error. Letting
an adopter set these paths would hand them that trap; owning them removes it by
construction. :mod:`ash_operator.volumes` still asserts the invariant, because a
guard nobody can trigger is the only kind worth having here.
"""

from __future__ import annotations

# ── The ASH command-line program ─────────────────────────────────────────────
# The one place the operator names the binary it runs inside the scan image, for
# `scan`, `merge` and `mcp` alike. Every argv builder, the MCP capability probe and
# the e2e harness read it from here, so renaming the CLI is a one-line change.
ASH_CLI = "ash"

# ── API surface ──────────────────────────────────────────────────────────────
# Reverse of the Maven/Java coordinate the project already chose for its CDK
# constructs (``io.github.awslabs.ash``), so the API group is not a new
# namespace invented here.
GROUP = "ash.awslabs.github.io"
VERSION = "v1alpha1"

SCAN_KIND = "AshScan"
SCAN_PLURAL = "ashscans"
SCAN_SINGULAR = "ashscan"

MCP_KIND = "AshMcpServer"
MCP_PLURAL = "ashmcpservers"
MCP_SINGULAR = "ashmcpserver"

# ── Volume layout ────────────────────────────────────────────────────────────
# Siblings under one parent, so neither is an ancestor of the other. See the
# module docstring for what an ancestor relationship costs.
WORKSPACE_ROOT = "/workspace"
SOURCE_MOUNT = f"{WORKSPACE_ROOT}/src"
OUTPUT_MOUNT = f"{WORKSPACE_ROOT}/out"
CONFIG_MOUNT = f"{WORKSPACE_ROOT}/config"
RESULTS_MOUNT = f"{WORKSPACE_ROOT}/results"
# A mount path inside a container, not a path this process writes to. The pod backs
# it with an emptyDir, so it is private to one pod and gone when the pod is; the
# symlink attacks S108 is about need a shared /tmp on a host.
TMP_MOUNT = "/tmp"  # noqa: S108

CONFIG_FILENAME = ".ash.yaml"
CONFIG_PATH = f"{CONFIG_MOUNT}/{CONFIG_FILENAME}"

SHARD_ENTRYPOINT_FILENAME = "shard-entrypoint.sh"
COLLECT_ENTRYPOINT_FILENAME = "collect-entrypoint.sh"

# ── Result addressing (see ash_operator.attempts) ────────────────────────────
ATTEMPTS_DIRNAME = "attempts"
SELECTED_DIRNAME = "selected"
RESULTS_FILENAME = "ash_aggregated_results.json"
EXIT_CODE_FILENAME = ".shard-exit-code"
ATTEMPT_MARKER_FILENAME = ".attempt-complete"
PARTIAL_SUFFIX = ".partial"

# ── Labels ───────────────────────────────────────────────────────────────────
LABEL_PREFIX = GROUP
LABEL_SCAN_NAME = f"{LABEL_PREFIX}/scan-name"
LABEL_SCAN_UID = f"{LABEL_PREFIX}/scan-uid"
LABEL_ROLE = f"{LABEL_PREFIX}/role"
LABEL_MCP_NAME = f"{LABEL_PREFIX}/mcp-name"
LABEL_CONFIG_DIGEST = f"{LABEL_PREFIX}/config-digest"

ROLE_SHARD = "shard"
ROLE_COLLECT = "collect"
ROLE_MCP = "mcp"

# The index label the Job controller puts on every pod of an ``Indexed`` Job.
# Measured on the host this operator was developed against, not assumed.
JOB_COMPLETION_INDEX_LABEL = "batch.kubernetes.io/job-completion-index"
JOB_COMPLETION_INDEX_ENV = "JOB_COMPLETION_INDEX"

# ── Limits ───────────────────────────────────────────────────────────────────
# Parity with ``MAX_SHARD_COUNT`` in the CDK constructs package. Measured there:
# at 50 shards over a 5-scanner tree, 45 shards came back with an empty
# assignment and the merged findings matched one unsharded scan -- an over-large
# count is wasteful rather than wrong. The ceiling exists so a typo in the CR
# fails loudly instead of scheduling hundreds of empty pods.
MAX_SHARD_COUNT = 50
MIN_SHARD_COUNT = 1

SEVERITY_LEVELS = ("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# ── Scanner status vocabulary ────────────────────────────────────────────────
# Classification tests membership of the COMPLETE set rather than absence from
# the incomplete one. ``ash merge`` makes the same choice and records why: it
# consumes results written by whatever ASH produced each shard, so a fan-out
# whose pods are mid-upgrade can hand it a status string neither set knows. "Is
# it one of the two bad ones" answers no for such a status and reports the shard
# complete. ``tests/test_results.py`` pins these against ASH's own enum, so a
# status added upstream fails a test here instead of being silently tolerated.
COMPLETE_SCANNER_STATUSES = frozenset({"PASSED", "FAILED", "SKIPPED"})
KNOWN_SCANNER_STATUSES = frozenset({"PASSED", "FAILED", "SKIPPED", "ERROR", "MISSING"})

# ── Terminal phases ──────────────────────────────────────────────────────────
# ``ash merge`` exits 0 for a clean scan, 2 for findings, and 1 for a scan that
# finished with partial coverage (ERROR or MISSING scanners, a converter that did
# not run, an unevaluated rule, a stale content database) -- the last only when
# ``fail_on_incomplete_scanners`` is on, which is ASH's default. Each of the three
# is a different answer, so each is its own phase. ``Refused`` is the operator
# declining to report an answer it does not have; see ``results.derive_phase``.
PHASE_CLEAN = "Clean"
PHASE_FINDINGS = "Findings"
PHASE_INCOMPLETE = "Incomplete"
PHASE_REFUSED = "Refused"
TERMINAL_PHASES = (PHASE_CLEAN, PHASE_FINDINGS, PHASE_INCOMPLETE, PHASE_REFUSED)
NON_TERMINAL_PHASES = ("Pending", "Scanning", "Merging")

# ``ash merge``'s exit codes, named. 1 also means "error during execution": the
# collector tells the two apart by whether a merged report was written and whether
# that report names a coverage gap.
EXIT_CLEAN = 0
EXIT_INCOMPLETE = 1
EXIT_FINDINGS = 2
