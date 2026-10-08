#!/usr/bin/env bash
# TEMPORARY (diagnostic, removed before merge): record what sandbox-exec'd scanners
# look up over Mach and execute, so the macOS profile can allow exactly that.
#
#   sandbox-exec-diag.sh probe      which SBPL forms parse; exports ASH_SANDBOX_EXEC_REPORT
#   sandbox-exec-diag.sh summarize  aggregate the Sandbox log since the job started
set -u

mode=${1:-}
diag_dir=${DIAG_DIR:-${RUNNER_TEMP:-.}/sandbox-exec-diag}
mkdir -p "$diag_dir"

try_profile() {
  local out
  if out=$(/usr/bin/sandbox-exec -p "$1" /usr/bin/true 2>&1); then
    echo "PARSES   $1"
    return 0
  fi
  echo "REJECTED $1 -> $out"
  return 1
}

if [ "$mode" = probe ]; then
  sw_vers
  # Local time, which is what `log show --start` reads.
  date '+%Y-%m-%d %H:%M:%S' >"$diag_dir/job-start"
  base='(version 1)(allow default)'
  try_profile "$base(allow mach-lookup (with report))" && suffix=1 || suffix=
  try_profile "$base(allow (with report) mach-lookup)" && prefix=1 || prefix=
  try_profile "$base(allow process-exec (with report))" || true
  try_profile "$base(allow (with report) process-exec)" || true
  try_profile "$base(debug deny)" || true
  try_profile "$base(deny mach-lookup (global-name \"com.apple.pasteboard.1\"))" || true
  try_profile "$base(deny mach-lookup (global-name-prefix \"com.apple.lsd.\"))" || true
  try_profile "$base(deny mach-lookup (global-name-regex #\"^com\\.apple\\.lsd\\.\"))" || true
  try_profile "$base(deny process-exec (subpath \"/Applications\"))" || true
  try_profile "$base(deny process-exec* (subpath \"/Applications\"))" || true
  if [ -n "$suffix" ]; then
    echo "ASH_SANDBOX_EXEC_REPORT=1" >>"$GITHUB_ENV"
  elif [ -n "$prefix" ]; then
    echo "ASH_SANDBOX_EXEC_REPORT=prefix" >>"$GITHUB_ENV"
  else
    echo "::error::no (with report) form parses"
    exit 1
  fi

  echo "--- session services, unsandboxed"
  before=$(pgrep -x TextEdit || true)
  /usr/bin/open -g -j -a TextEdit
  echo "open -a TextEdit exit $?; TextEdit pids before [$before] after [$(pgrep -x TextEdit || true)]"
  [ -z "$before" ] && pkill -x TextEdit || true
  printf 'diag-canary' | /usr/bin/pbcopy
  echo "pbcopy exit $?; pbpaste -> [$(/usr/bin/pbpaste)]"

  echo "--- report format"
  /usr/bin/sandbox-exec -p "$base(allow mach-lookup (with report))(allow process-exec (with report))" /usr/bin/pbpaste >/dev/null 2>&1 || true
  /usr/bin/sandbox-exec -p '(version 1)(allow default)(deny mach-lookup (global-name "com.apple.pasteboard.1"))' /usr/bin/pbpaste
  echo "pbpaste with the pasteboard denied: exit $?"
  sudo log show --last 2m --predicate 'sender == "Sandbox"' --style compact | tail -40
  exit 0
fi

if [ "$mode" = summarize ]; then
  start=$(cat "$diag_dir/job-start" 2>/dev/null || date -v-90M '+%Y-%m-%d %H:%M:%S')
  # shellcheck disable=SC2024 # the runner user writes the file; sudo is for reading the log
  sudo log show --start "$start" --predicate 'sender == "Sandbox"' --style ndjson \
    >"$diag_dir/sandbox-log.ndjson"
  python3 - "$diag_dir" <<'EOF'
import collections
import datetime
import json
import re
import sys
from pathlib import Path

diag = Path(sys.argv[1])
phases = []
stdout_log = diag / "parity-stdout.log"
if stdout_log.exists():
    for line in stdout_log.read_text(errors="replace").splitlines():
        stamp, _, rest = line.partition(" ")
        if rest.startswith("$ ") and " scan " in rest:
            mode = re.search(r"--sandbox (\S+)", rest).group(1)
            net = "offline" if "--offline" in rest else "online"
            when = datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc
            )
            phases.append((when, f"{net}/{mode}"))
pattern = re.compile(
    r"^Sandbox: (?P<proc>.+?)\((?P<pid>\d+)\) (?P<verdict>allow|deny)(?:\(\d+\))? "
    r"(?P<op>\S+)(?: (?P<arg>.*))?$"
)
table = collections.defaultdict(lambda: [0, set()])
unparsed = collections.Counter()
for raw in (diag / "sandbox-log.ndjson").read_text(errors="replace").splitlines():
    try:
        event = json.loads(raw)
    except ValueError:
        continue
    message = (event.get("eventMessage") or "").strip()
    m = pattern.match(message)
    if not m:
        unparsed[message[:160]] += 1
        continue
    try:
        when = datetime.datetime.strptime(
            event["timestamp"], "%Y-%m-%d %H:%M:%S.%f%z"
        )
    except (KeyError, ValueError):
        when = None
    phase = "-"
    for start, label in phases:
        if when is not None and when >= start:
            phase = label
    key = (m["verdict"], m["op"], (m["arg"] or "").strip(), phase)
    table[key][0] += 1
    table[key][1].add(re.sub(r"\d+(\.\d+)*$", "", m["proc"]))
lines = []
for (verdict, op, arg, phase), (count, procs) in sorted(table.items()):
    lines.append(f"{verdict:5} {op:22} {phase:22} {count:6}  {arg}  [{', '.join(sorted(procs))}]")
report = "\n".join(lines)
(diag / "summary.txt").write_text(report + "\n")
print(report)
print("\n--- unparsed messages (most common 40)")
for message, count in unparsed.most_common(40):
    print(f"{count:6}  {message}")
EOF
  exit 0
fi

echo "usage: $0 probe|summarize" >&2
exit 2
