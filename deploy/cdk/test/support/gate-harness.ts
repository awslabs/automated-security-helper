/**
 * Run the CodeCommit gate handler for real, with the AWS and git edges replaced.
 *
 * WHY THE HANDLER IS RUN AND NOT PATTERN-MATCHED
 * ---------------------------------------------
 * The handler is a Python string inside a TypeScript template literal, so a
 * `toContain` check on it passes whether or not the code it names ever runs. These
 * tests execute `CODECOMMIT_GATE_HANDLER` itself, as the Lambda image does, under
 * the host's `python3`, and observe what it hands to `ash scan`: the argv, the
 * config file ASH would read, and the environment.
 *
 * WHAT IS REPLACED, AND HOW
 * -------------------------
 * - `boto3`: a module on PYTHONPATH that records every client call to a file and
 *   answers SSM `get_parameter` with a value this harness chooses. No request leaves
 *   the process, whatever credentials are in the environment.
 * - `git`: a script on PATH that "clones" by copying a fixture tree, which stands in
 *   for the pull request's source.
 * - `ash`: a script on PATH that records what it was given and exits with a chosen
 *   code. It resolves the config ASH would use the way ASH does: `--config`/`-c`
 *   wins, and otherwise `ASH_CONFIG` (cli/scan.py declares it as that option's
 *   envvar); with neither, ASH discovers a config inside the source tree
 *   (interactions/run_ash_scan.py, `_discovered_config_path`).
 *
 * The record paths and the exit code are written INTO the fake scripts rather than
 * passed through the environment, so a handler that scrubs the scan environment
 * (which is what one of these tests asks for) cannot make the fakes go quiet.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { CODECOMMIT_GATE_HANDLER } from '../../lib/ash-container-scripts';

/**
 * Stand-ins for the credentials the Lambda runtime puts in the function's environment.
 * Built from the variable names rather than written as literals, so nothing here
 * looks like a credential to a secret scanner.
 */
export const FUNCTION_CREDENTIALS: Record<string, string> = Object.fromEntries(
  ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'].map((name) => [
    name,
    `function-role-${name.toLowerCase().replace(/_/g, '-')}`,
  ]),
);

/** Every variable through which a child process could pick up AWS credentials. */
export const CREDENTIAL_VARIABLES = [
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'AWS_SECURITY_TOKEN',
  'AWS_CONTAINER_CREDENTIALS_FULL_URI',
  'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',
  'AWS_CONTAINER_AUTHORIZATION_TOKEN',
  'AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE',
  'AWS_WEB_IDENTITY_TOKEN_FILE',
  'AWS_ROLE_ARN',
  'AWS_PROFILE',
  'AWS_SHARED_CREDENTIALS_FILE',
  'AWS_CONFIG_FILE',
];

/** The config the pull request under scan commits. Its marker must never reach ash. */
export const PULL_REQUEST_CONFIG_MARKER = 'pull-request-chose-this-config';
export const PULL_REQUEST_CONFIG = [
  `project_name: ${PULL_REQUEST_CONFIG_MARKER}`,
  'fail_on_findings: false',
  'global_settings:',
  '  ignore_paths:',
  '    - path: "**"',
  '      reason: "the pull request does not want to be scanned"',
  '',
].join('\n');

/** What `ash` recorded about one invocation. */
export interface AshRecord {
  readonly argv: string[];
  readonly cwd: string;
  /** The value of `--source-dir`: the directory, in the subject-less `ash scan`. */
  readonly source_dir: string | null;
  /** The PATH right after `ash scan fs`: the directory, in ASH 3.9's form. */
  readonly scan_path: string | null;
  readonly config_arg: string | null;
  readonly env_config: string | null;
  readonly effective_config: string | null;
  readonly effective_config_exists: boolean;
  readonly effective_config_content: string | null;
  readonly env: Record<string, string | null>;
}

export interface Boto3Call {
  readonly service: string;
  readonly method: string;
  readonly kwargs?: Record<string, unknown>;
}

export interface GateRun {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  /** The last invocation's return value, or `{ error }` when it raised. */
  readonly outcome: Record<string, unknown>;
  /** Every invocation's, in order: one entry unless `invocations` asked for more. */
  readonly outcomes: Record<string, unknown>[];
  readonly ash: AshRecord[];
  readonly boto3: Boto3Call[];
  readonly gitCalls: string[][];
  /** Where the fake clone landed; the pull request's tree. */
  readonly cloneDir: string | null;
}

export interface GateRunOptions {
  /** The function's environment, normally resolved from the synthesized template. */
  readonly env: Record<string, string>;
  /** Exit code `ash` returns. */
  readonly ashExit?: number;
  /** What SSM `get_parameter` returns as the parameter value. Unset: the call raises. */
  readonly ssmValue?: string;
  /** Extra files in the pull request's tree, relative path to content. */
  readonly repoFiles?: Record<string, string>;
  /** How `ash scan --help` answers; see `AshScanHelp`. Default `listed`. */
  readonly ashScanHelp?: AshScanHelp;
  /** Which ASH the stand-in answers as; see `AshRelease`. Default `with-subject`. */
  readonly ashRelease?: AshRelease;
  /**
   * How many pull-request events the one handler module is given, in order. More
   * than one is a warm Lambda execution environment, whose module-level state
   * (what the handler learned about its ASH) outlives the first pull request.
   * Default 1.
   */
  readonly invocations?: number;
}

/**
 * How the stand-in `ash` answers the scan's help (`ash scan fs --help` and
 * `ash scan --help`):
 * - `listed`: lists `--fail-on-incomplete-scanners`, as this repository's ASH does;
 * - `missing`: omits it, as every release up to v3.7.1 does;
 * - `coloured`: lists it styled the way rich prints it when colour is forced, each
 *   dash of the name in its own ANSI span, so the plain name does not appear;
 * - `fails`: exits non-zero.
 */
export type AshScanHelp = 'listed' | 'missing' | 'coloured' | 'fails';

/**
 * Which ASH the stand-in `ash` answers as:
 * - `with-subject`: ASH 3.9 and later, as this repository's is. A directory is
 *   scanned with `ash scan fs PATH` and results are merged with `ash results merge`,
 *   and only their help prints those command paths;
 * - `without-subject`: ASH 3.8 and earlier. `ash scan fs --help` shows the
 *   subject-less scan's help, since click reads `--help` before it refuses the extra
 *   argument, and there is no `results` command, so `ash results merge --help` is a
 *   usage error;
 * - `without-subject-refusing`: as `without-subject`, except that `ash scan fs --help`
 *   refuses the word `fs` with the usage error click gives an extra argument (exit 5,
 *   "Got unexpected extra argument (fs)") instead of showing help;
 * - `new-spellings-crash`: `ash scan fs --help` and `ash results merge --help` die with
 *   a traceback (exit 1) while `ash scan --help` answers as without the subject. A
 *   caller that read the first failure as "this ASH lacks the command" would pick the
 *   older spelling, and the second probe would let it;
 * - `first-probe-crashes`: the first help probe the stand-in is asked, whichever it is,
 *   dies with a traceback, and every later one answers as an ASH with the subject. A
 *   transient failure, for a handler that stays warm between pull requests.
 */
export type AshRelease =
  | 'with-subject'
  | 'without-subject'
  | 'without-subject-refusing'
  | 'new-spellings-crash'
  | 'first-probe-crashes';

let cachedPython: string | undefined;

/** The absolute path of the host's python3, for the fakes' shebangs. */
export function python3(): string {
  if (cachedPython === undefined) {
    const probe = spawnSync('python3', ['-c', 'import sys; print(sys.executable)'], {
      encoding: 'utf-8',
    });
    if (probe.status !== 0 || !probe.stdout.trim()) {
      throw new Error(`python3 is required to run the gate handler: ${probe.stderr}`);
    }
    cachedPython = probe.stdout.trim();
  }
  return cachedPython;
}

const FAKE_BOTO3 = (logFile: string, ssmValue: string | undefined) => `"""Recording stand-in for boto3. Written by test/support/gate-harness.ts."""
import json

_LOG = ${JSON.stringify(logFile)}
_SSM_VALUE = ${ssmValue === undefined ? 'None' : JSON.stringify(ssmValue)}


def _record(entry):
    with open(_LOG, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, default=str) + "\\n")


class _Exceptions:
    class PullRequestCannotBeApprovedByAuthorException(Exception):
        pass

    class ParameterNotFound(Exception):
        pass


class _Answer(dict):
    """A response whose missing keys read as a placeholder rather than raising."""

    def __missing__(self, key):
        return "fake-" + str(key)


class _Client:
    def __init__(self, service):
        self._service = service
        self.exceptions = _Exceptions()

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def call(*args, **kwargs):
            _record({"service": self._service, "method": name, "kwargs": kwargs})
            if self._service == "ssm" and name == "get_parameter":
                if _SSM_VALUE is None:
                    raise _Exceptions.ParameterNotFound(kwargs.get("Name"))
                return {"Parameter": {"Name": kwargs.get("Name"), "Value": _SSM_VALUE}}
            if self._service == "ssm" and name == "get_parameters":
                names = kwargs.get("Names") or []
                if _SSM_VALUE is None:
                    return {"Parameters": [], "InvalidParameters": names}
                return {"Parameters": [{"Name": n, "Value": _SSM_VALUE} for n in names]}
            return _Answer()

        return call


def client(service, *args, **kwargs):
    _record({"service": service, "method": "__client__"})
    return _Client(service)


class session:
    class Session:
        def __init__(self, *args, **kwargs):
            pass

        def client(self, service, *args, **kwargs):
            return client(service)
`;

const FAKE_GIT = (python: string, logFile: string, source: string) => `#!${python}
import json, shutil, sys
args = sys.argv[1:]
with open(${JSON.stringify(logFile)}, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(args) + "\\n")
if args and args[0] == "clone":
    shutil.copytree(${JSON.stringify(source)}, args[-1])
sys.exit(0)
`;

/**
 * A stand-in for `ash` that records what it was given, with its record path baked in.
 *
 * The help probes (`ash scan fs --help`, `ash scan --help`, `ash results merge
 * --help`) are answered rather than recorded: they ask what this ASH is, they are
 * not scans. See `AshScanHelp` and `AshRelease` for how they answer.
 */
export const fakeAshScript = (
  python: string,
  recordFile: string,
  exitCode: number,
  scanHelp: AshScanHelp = 'listed',
  release: AshRelease = 'with-subject',
) => `#!${python}
import json, os, sys

argv = sys.argv[1:]
CREDENTIAL_VARIABLES = ${JSON.stringify(CREDENTIAL_VARIABLES)}
HELP = ${JSON.stringify(scanHelp)}
RELEASE = ${JSON.stringify(release)}
PROBES_FILE = ${JSON.stringify(`${recordFile}.probes`)}


def scan_help(usage):
    if HELP == "fails":
        sys.exit(1)
    print(usage)
    for line in ("--source-dir PATH", "--output-dir PATH", "--config PATH", "--min-severity TEXT"):
        print("  " + line)
    if HELP == "listed":
        print("  --fail-on-incomplete-scanners / --no-fail-on-incomplete-scanners")
    elif HELP == "coloured":
        print("\\x1b[1;36m-\\x1b[0m\\x1b[1;36m-fail\\x1b[0m\\x1b[1;36m-on-incomplete-scanners\\x1b[0m")
    sys.exit(0)


def crash():
    """Die as an ASH does when it cannot start: a traceback on stderr and exit 1."""
    print("Traceback (most recent call last):", file=sys.stderr)
    print('  File "/usr/local/bin/ash", line 3, in <module>', file=sys.stderr)
    print("MemoryError", file=sys.stderr)
    sys.exit(1)


def probes_asked_before_this_one():
    """How many help probes this stand-in was asked before the one now answering."""
    try:
        with open(PROBES_FILE, encoding="utf-8") as handle:
            asked = int(handle.read() or "0")
    except FileNotFoundError:
        asked = 0
    with open(PROBES_FILE, "w", encoding="utf-8") as handle:
        handle.write(str(asked + 1))
    return asked


SCAN_FS_PROBE = argv[:3] == ["scan", "fs", "--help"]
SCAN_PROBE = argv[:2] == ["scan", "--help"]
MERGE_PROBE = argv[:3] == ["results", "merge", "--help"]

if SCAN_FS_PROBE or SCAN_PROBE or MERGE_PROBE:
    # What this probe meets: the release, or what a transient failure does this time.
    kind = RELEASE
    if RELEASE == "first-probe-crashes":
        kind = "crash" if probes_asked_before_this_one() == 0 else "with-subject"
    if kind == "crash" or (kind == "new-spellings-crash" and not SCAN_PROBE):
        crash()
    if SCAN_FS_PROBE and kind == "without-subject-refusing":
        print("Usage: ash scan [OPTIONS]", file=sys.stderr)
        print("Try 'ash scan --help' for help.", file=sys.stderr)
        print("Error: Got unexpected extra argument (fs)", file=sys.stderr)
        sys.exit(5)
    if SCAN_FS_PROBE or SCAN_PROBE:
        # With the subject, the subject-less form shows the subject's help too.
        scan_help("Usage: ash scan fs [OPTIONS] [PATH]" if kind == "with-subject" else "Usage: ash scan [OPTIONS]")
    if kind == "with-subject":
        print("Usage: ash results merge [OPTIONS]")
        sys.exit(0)
    print("Error: No such command 'results'.", file=sys.stderr)
    sys.exit(2)


def option(names):
    found = None
    for index, arg in enumerate(argv):
        for name in names:
            if arg == name and index + 1 < len(argv):
                found = argv[index + 1]
            elif name.startswith("--") and arg.startswith(name + "="):
                found = arg[len(name) + 1:]
            elif name == "-c" and arg.startswith("-c") and not arg.startswith("--") and len(arg) > 2:
                found = arg[2:].lstrip("=")
    return found


config_arg = option(["--config", "-c"])
env_config = os.environ.get("ASH_CONFIG") or None
effective = config_arg if config_arg is not None else env_config
exists = bool(effective) and os.path.isfile(effective)
content = None
if exists:
    with open(effective, encoding="utf-8", errors="replace") as handle:
        content = handle.read(65536)

record = {
    "argv": argv,
    "cwd": os.getcwd(),
    "source_dir": option(["--source-dir"]),
    "scan_path": argv[2] if argv[:2] == ["scan", "fs"] and len(argv) > 2 and not argv[2].startswith("-") else None,
    "config_arg": config_arg,
    "env_config": env_config,
    "effective_config": effective,
    "effective_config_exists": exists,
    "effective_config_content": content,
    "env": {name: os.environ.get(name) for name in CREDENTIAL_VARIABLES + ["HOME", "PATH"]},
}
with open(${JSON.stringify(recordFile)}, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record) + "\\n")
sys.exit(${exitCode})
`;

const DRIVER = `import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("ash_gate_handler", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
event = json.loads(sys.argv[2])
outcomes = []
# One module for every event, as a warm execution environment has it: what the
# handler remembered about its ASH after one pull request is there for the next.
for _ in range(int(sys.argv[4])):
    try:
        outcomes.append(module.handler(event, None))
    except BaseException as exc:  # recorded, not swallowed: the test reads it
        outcomes.append({"error": repr(exc)})
with open(sys.argv[3], "w", encoding="utf-8") as handle:
    json.dump(outcomes, handle, default=str)
`;

/** A pull request event as EventBridge delivers it. */
export const PULL_REQUEST_EVENT = {
  detail: {
    event: 'pullRequestSourceBranchUpdated',
    pullRequestId: '7',
    repositoryNames: ['gated-repo'],
    sourceCommit: 'a'.repeat(40),
    destinationCommit: 'b'.repeat(40),
    sourceReference: 'refs/heads/feature',
    revisionId: 'rev-1',
  },
};

/** Parse a file of JSON lines; a missing file is an empty list. */
export function readLines<T>(file: string): T[] {
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf-8')
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line) as T);
}

/** Remove a directory the handler created, only if it is where the handler puts them. */
function removeHandlerWorkdir(cloneDir: string | null): void {
  if (!cloneDir) return;
  const workdir = path.dirname(cloneDir);
  const roots = [os.tmpdir(), '/tmp'].map((root) => path.resolve(root));
  const resolved = path.resolve(workdir);
  if (roots.includes(resolved)) return;
  if (roots.some((root) => resolved.startsWith(root + path.sep))) {
    fs.rmSync(resolved, { recursive: true, force: true });
  }
}

export function runGateHandler(options: GateRunOptions): GateRun {
  const python = python3();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-gate-run-'));
  try {
    const bin = path.join(dir, 'bin');
    const pythonPath = path.join(dir, 'py');
    const repo = path.join(dir, 'pull-request');
    fs.mkdirSync(bin);
    fs.mkdirSync(path.join(pythonPath, 'boto3'), { recursive: true });

    const files: Record<string, string> = {
      'app.py': 'print("scanned")\n',
      '.ash/.ash.yaml': PULL_REQUEST_CONFIG,
      '.ash.yaml': PULL_REQUEST_CONFIG,
      ...(options.repoFiles ?? {}),
    };
    for (const [relative, content] of Object.entries(files)) {
      const target = path.join(repo, relative);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, content);
    }

    const boto3Log = path.join(dir, 'boto3.jsonl');
    const gitLog = path.join(dir, 'git.jsonl');
    const ashLog = path.join(dir, 'ash.jsonl');
    const resultFile = path.join(dir, 'result.json');

    fs.writeFileSync(path.join(pythonPath, 'boto3', '__init__.py'), FAKE_BOTO3(boto3Log, options.ssmValue));
    fs.writeFileSync(path.join(bin, 'git'), FAKE_GIT(python, gitLog, repo), { mode: 0o755 });
    fs.writeFileSync(
      path.join(bin, 'ash'),
      fakeAshScript(
        python,
        ashLog,
        options.ashExit ?? 0,
        options.ashScanHelp ?? 'listed',
        options.ashRelease ?? 'with-subject',
      ),
      { mode: 0o755 },
    );
    const handlerFile = path.join(dir, 'ash_gate_handler.py');
    fs.writeFileSync(handlerFile, CODECOMMIT_GATE_HANDLER);
    const driver = path.join(dir, 'driver.py');
    fs.writeFileSync(driver, DRIVER);

    const searchPath = `${bin}:${process.env.PATH ?? '/usr/bin:/bin'}`;
    const result = spawnSync(
      python,
      [driver, handlerFile, JSON.stringify(PULL_REQUEST_EVENT), resultFile, String(options.invocations ?? 1)],
      {
        encoding: 'utf-8',
        // A minimal environment, so nothing from the developer's shell or the CI
        // runner reaches the handler: in particular no real AWS credential.
        env: {
          PATH: searchPath,
          PYTHONPATH: pythonPath,
          PYTHONDONTWRITEBYTECODE: '1',
          HOME: dir,
          AWS_REGION: 'us-east-1',
          AWS_EC2_METADATA_DISABLED: 'true',
          AWS_ENDPOINT_URL: 'http://127.0.0.1:9',
          // The Lambda image records its PATH here (Dockerfile.lambda), and the
          // handler restores it for the scan.
          ASH_IMAGE_PATH: searchPath,
          ...FUNCTION_CREDENTIALS,
          ...options.env,
        },
      },
    );

    const outcomes = fs.existsSync(resultFile)
      ? (JSON.parse(fs.readFileSync(resultFile, 'utf-8')) as Record<string, unknown>[])
      : [{ error: 'the driver wrote no result' }];
    const gitCalls = readLines<string[]>(gitLog);
    const clones = gitCalls.filter((call) => call[0] === 'clone').map((call) => call[call.length - 1]);
    const cloneDir = clones.length > 0 ? clones[0] : null;
    const run: GateRun = {
      status: result.status,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
      outcome: outcomes[outcomes.length - 1],
      outcomes,
      ash: readLines<AshRecord>(ashLog),
      boto3: readLines<Boto3Call>(boto3Log),
      gitCalls,
      cloneDir,
    };
    for (const clone of clones) removeHandlerWorkdir(clone);
    return run;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Whether `child` is `parent` or inside it, by real path semantics rather than string prefix. */
export function isInside(child: string, parent: string): boolean {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}
