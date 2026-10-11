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
  readonly source_dir: string | null;
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
  /** The handler's return value, or `{ error }` when it raised. */
  readonly outcome: Record<string, unknown>;
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
}

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

/** A stand-in for `ash` that records what it was given, with its record path baked in. */
export const fakeAshScript = (python: string, recordFile: string, exitCode: number) => `#!${python}
import json, os, sys

argv = sys.argv[1:]
CREDENTIAL_VARIABLES = ${JSON.stringify(CREDENTIAL_VARIABLES)}


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
try:
    outcome = module.handler(event, None)
except BaseException as exc:  # recorded, not swallowed: the test reads it
    outcome = {"error": repr(exc)}
with open(sys.argv[3], "w", encoding="utf-8") as handle:
    json.dump(outcome, handle, default=str)
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
    fs.writeFileSync(path.join(bin, 'ash'), fakeAshScript(python, ashLog, options.ashExit ?? 0), { mode: 0o755 });
    const handlerFile = path.join(dir, 'ash_gate_handler.py');
    fs.writeFileSync(handlerFile, CODECOMMIT_GATE_HANDLER);
    const driver = path.join(dir, 'driver.py');
    fs.writeFileSync(driver, DRIVER);

    const searchPath = `${bin}:${process.env.PATH ?? '/usr/bin:/bin'}`;
    const result = spawnSync(python, [driver, handlerFile, JSON.stringify(PULL_REQUEST_EVENT), resultFile], {
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
    });

    const outcome = fs.existsSync(resultFile)
      ? (JSON.parse(fs.readFileSync(resultFile, 'utf-8')) as Record<string, unknown>)
      : { error: 'the driver wrote no result' };
    const gitCalls = readLines<string[]>(gitLog);
    const clone = gitCalls.find((call) => call[0] === 'clone');
    const cloneDir = clone ? clone[clone.length - 1] : null;
    const run: GateRun = {
      status: result.status,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
      outcome,
      ash: readLines<AshRecord>(ashLog),
      boto3: readLines<Boto3Call>(boto3Log),
      gitCalls,
      cloneDir,
    };
    removeHandlerWorkdir(cloneDir);
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
