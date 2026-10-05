# ASH Kubernetes operator

Two custom resources. `AshScan` runs one sharded scan as an indexed Job plus a
collector. `AshMcpServer` runs ASH's own MCP server as a Deployment behind a
Service. They share only the config-delivery mechanism, which is why they are two
kinds and two reconcilers rather than one kind with a mode field.

```
kubectl apply -f generated/          # the CRDs
kubectl apply -f manifests/          # namespace, RBAC, operator Deployment
```

You must build the operator image yourself (`Dockerfile`), and you must supply an
ASH image in `spec.image`. Neither is published anywhere, for the same reason ASH
publishes no container image: installing ASH by distribution name is actively
unsafe, because the name `automated-security-helper` on PyPI is an unrelated
placeholder package. A name-based install succeeds, leaves no `ash` on `PATH`, and
puts a third party's code in the container that scans your source.

## Why it looks like this

ASH has no Python interface for remote execution — no abstract base class, no plugin
hook, no registry of execution targets. What it has is a **CLI plus filesystem
contract**: a command line, and a directory layout. Reusing the shard-and-merge
pattern the two existing CDK backends implement means implementing that contract,
not importing anything.

```
per shard:   ash scan --source-dir  /workspace/src \
                      --output-dir  /workspace/out \
                      --shard-index K --shard-count N \
                      --no-fail-on-findings --no-progress --simple
             config:  a file, pointed at by the ASH_CONFIG environment variable
             verdict: none. exit 0 after publishing, even with findings.

collector:   walk 0..N-1 by index; refuse a short set; then
             ash merge --results <one per shard> --output-dir ... --min-severity ...
             verdict: this exit code, and only this one.
```

The partition is a pure function of `(sorted, deduplicated, lower-cased scanner
names, index, count)`, so pods never coordinate. The only thing distributed is two
integers.

### Five things that produce a silently wrong scan if you get them wrong

Each of these was measured, not reasoned about, and each one fails *green* — a scan
that reports no findings and exits 0.

**1. Run `ash scan` unmodified, so `ScanPhase` stamps the provenance.** Each shard's
results carry a `ShardAssignment` with `assigned_scanners`, `candidate_scanners` and
`selected_scanners`. The middle one is load-bearing: in a split-brain roster case
where two pods partition different scanner sets without overlapping, the merge
refuses when `candidate_scanners` is present on every shard and **accepts, with a
scanner never having run anywhere, when it is absent**. A backend that synthesised
its own provenance, or that reimplemented scanning, would forfeit the only check
that can see that hole. Nothing in this operator rewrites the argv after the fact or
post-processes the results.

**2. Do not cache anything per shard index.** The partition reshuffles by sort
*position*, not by count. Measured over the ten built-in scanners at
`shardCount=4`: adding a scanner whose name sorts first moves **10 of 10** scanners
to a different shard; adding one that sorts last moves **0**. A cache keyed on
`(shardIndex, image)` is therefore wrong for every scanner after a config change
that adds an early-sorting name. Nothing here is keyed on the index except
`JOB_COMPLETION_INDEX`, read fresh inside the pod, and the results path, which is
scoped to one run's UID.

**3. Retry-safe result addressing.** `ash merge` refuses a duplicate shard index
arriving as two `--results` entries — "merging does not deduplicate" — but has no
defence against **one** file that a retry overwrote. No CodeBuild backend faces
this. A Kubernetes pod can be OOMKilled, evicted, preempted or drained, and the
retry gets the same `JOB_COMPLETION_INDEX` and therefore the same natural output
path. This operator addresses results by *(shard index, attempt id)* and publishes
by directory rename. The scheme, and what it does and does not guarantee, is
documented in full at the top of `ash_operator/attempts.py`. The short version:

* a retry cannot replace a completed attempt;
* a partial upload is never visible as complete;
* a missing shard is a refusal naming the index, never a merge over a subset;
* two attempts both finishing is recorded in `.status`, not silent;
* it assumes `rename(2)` is atomic on the results volume, detects truncation in
  transit but not a pod that lies, and does not garbage-collect discarded attempts.

**4. No shared command builder exists, so this one builds its own argv.** The two
CDK backends do not share command construction with each other:
`deploy/cdk/lib/ash-distributed-pipeline-stack.ts` imports nothing from
`deploy/cdk-constructs/`, and `cdk-constructs/src/private/commands.ts` scopes itself
to "every ASH command line *this package* emits". `ash_operator/contract.py` is this
backend's own, built from the contract, with the properties the contract requires
asserted in `tests/test_contract.py` — including a table run against ASH's own
`validate_shard_selection` so the two cannot disagree about what is acceptable.

**5. The output directory must not be inside or above the source.** `ash scan`
checks source/output collision by **equality only**; `ash merge` checks equality
**or ancestry** and its docstring says so. So `--output-dir /src` with
`--source-dir /src/app` passes the scan's check, and the symptom is not untidiness:
`apply_suppressions_to_sarif` excludes findings whose location resolves inside the
output directory, which when the output directory is an ancestor is *every* finding.
Measured before the merge-side relocation existed: three shards carrying five
findings merged to `Findings: 0 | Actionable: 0` at exit 0.

So the volume layout is fixed by the operator and not configurable:

| Path | Volume | Mode |
|---|---|---|
| `/workspace/src` | whatever `spec.source` names | read-only |
| `/workspace/out` | `emptyDir` | writable, node-local |
| `/workspace/config` | the run's ConfigMap | read-only |
| `/workspace/results` | PVC | writable, shared |
| `/tmp` | `emptyDir` | writable |

Four siblings. None is an ancestor of another, and `ash_operator/volumes.py` asserts
that on every Job it builds — a guard that is currently impossible to trip, which is
the point: it is what stands between a future patch making the paths configurable
and a silently clean scan.

## The CRD is generated from ASH's own models

`spec.config` is derived from `AshConfig.model_json_schema()` by
`ash_operator/crd_schema.py` and written by
`python -m ash_operator.generate_manifests`. Hand-writing a parallel schema would
drift from the models the scan actually validates against; `--check` holds the
committed copies to what the generator emits.

`--check` compares bytes **in memory** and writes nothing. It used to shell out to
`git status --porcelain --untracked-files=all`, which was the wrong oracle in both
directions: that query omits *ignored* paths, so an ignore rule touching `generated/`
would have made the gate print "match byte for byte" over a directory whose content had
been replaced wholesale — measured in a scratch repo — while an untracked but
byte-identical file reported drift that no amount of regenerating could clear. It also
called `write_all()` before asking, overwriting the evidence. Git answers about
tracking state; a content gate has to ask about content. A CRD generated but never
committed is still caught, because it is absent from a clean CI checkout and the
comparison reports it missing.

Pydantic emits JSON Schema 2020-12; `apiextensions.k8s.io/v1` accepts a restricted
subset. Every transformation between the two is recorded in
`generated/config-schema-translation.json`, so "what could not be expressed" is a
measured list rather than a claim. As committed: 67 entries — 65 plugin-map nodes,
one reference cycle, one mixed-type union — plus 64 `Optional[T]` collapses, 26
`const`→`enum` rewrites, one numeric exclusive bound converted, and 297 defaults and
330 titles dropped on purpose. The two CRDs render to 98,497 and 90,988 bytes, both
inside the 262,144-byte annotation cap that plain `kubectl apply` needs, which
`tests/test_crd_schema.py` pins so the number is not discovered in a pipeline.
In detail:

* **Reference cycles.** `AshConfig` reaches itself through
  `build.custom_scanners[].context.config`. A structural schema cannot hold a cycle,
  so that one subtree accepts any object and ASH validates it at scan time.
* **One mixed-type union.** `build.custom_scanners[].args.extra_args[].value` is
  `str | int | float | bool`; a structural schema needs one type outside the
  junctor, so that leaf is unvalidated by the API server.
* **Plugin maps, 65 nodes.** `scanners`, `reporters` and `converters` each declare
  the built-ins *and* a schema for anything a plugin module registers, which a
  structural schema cannot express together; so does every per-plugin config object
  beneath them. The built-ins stay validated and unknown keys gain
  `x-kubernetes-preserve-unknown-fields: true` so they are **preserved rather than
  pruned** — without that, a custom scanner's config would be deleted by the API
  server and the scan would run the plugin with its defaults.
* **Defaults are dropped, deliberately.** Keeping them would have the API server
  write ASH's entire default config into every CR at admission, freezing those
  defaults at creation time: upgrade the ASH image to a version that changed one and
  the CR keeps overriding it invisibly. A CR carries only what its author wrote; ASH
  supplies the rest.

Keys inside `spec.config` keep ASH's own spelling — `snake_case`, and one hyphenated
`mcp-resource-management`. That breaks the Kubernetes camelCase convention on
purpose and only there, because the block is written verbatim into the ConfigMap
that becomes `.ash.yaml`: a key spelled differently in the CR than in the file would
mean the operator rewriting an adopter's config, and a config the operator rewrites
cannot be diffed against ASH's documentation. Everything the *operator* owns is
camelCase.

One limit worth stating: `ash_plugin_modules` is passed through, but the operator
cannot install a Python module into your ASH image. A custom plugin has to be baked
into the image you name in `spec.image`.

## Status

`.status` reports per-scanner completeness unconditionally. It survives the shard
boundary because `_adopt_owning_shard_results` keeps only the *owning* shard's entry
for each scanner, keyed on `assigned_scanners`, so the merged report distinguishes
"not in my shard" from "ran and failed".

Note that ASH's `fail_on_incomplete_scanners` defaults to **False**. A scanner that
did not run therefore does **not** fail your scan unless you set
`spec.failOnIncompleteScanners: true`. `.status.incompleteScanners` names them
either way, which is the point of surfacing it: an adopter who turns the gate on and
then sees an opaque failure is a support burden whether or not the status was there.

`phase: Refused` is distinct from `phase: Failed`. Failed means the scan ran and the
findings crossed the threshold — an answer. Refused means the operator does not have
an answer and is declining to synthesise one: a missing shard, a merge that wrote no
report, a collector summary it could not read, **or shards that recorded no
`candidate_scanners`**.

That last one is the case worth spelling out. If no shard stamped
`candidate_scanners`, `ash merge` does **not** refuse — it skips the union check
entirely. A mid-rollout state where two executors partitioned different scanner sets
without overlapping then merges into a report that reads as a complete scan of the
whole tree, with a scanner having run nowhere, and nothing downstream can see it. The
operator is the only thing positioned to catch it, so `derive_phase` returns `Refused`
whenever `.status.merge.candidateRosterAgreed` is not `true`, and the refusal names
the likely cause: a `spec.image` whose ASH predates `ShardAssignment` stamping, which
is a configuration this operator otherwise supports.

For a while the collector detected exactly that condition, wrote
`candidateRosterAgreed: false` into `.status`, and the operator reported `Succeeded`
anyway. Detecting a coverage hole and then reporting success is worse than not
detecting it. `tests/e2e/Dockerfile.ash-nostamp` builds an ASH with the stamping
removed — verifying at build time that the substitution actually applied, so a patch
matching nothing cannot produce a vacuous pass — and
`TestProvenanceAbsentIsRefused` runs a real scan with it and asserts the refusal,
plus that the shards did run and the merge did execute, so the refusal is about
provenance rather than about a broken image. A missing `candidateRosterAgreed` key
refuses too, and `write_termination_message` is documented never to shed it.

The collector reports through its pod's **termination message**, which the operator
reads from `pod.status.containerStatuses[].state.terminated.message`. That needs no
ServiceAccount token on the scan pods and no shared volume mounted into the
operator. The kubelet caps it at 4 KiB, so the collector sheds detail explicitly and
sets `omittedFromStatus` rather than being truncated into invalid JSON — a truncated
summary reads as "unknown", never as clean.

## MCP: what "MCP server instances" means here

ASH's MCP configuration surface (`AshMcpConfig`, `MCPResourceManagementConfig`, the
JSON-Patch allowlist in `RuntimeOverridesConfig`) is about ASH **serving** MCP over
streamable HTTP. ASH is not a client of other MCP servers: there is no outbound MCP
transport, no server registry, nothing that consumes a peer's address.

So the operator **launches** ASH MCP server instances. It does not connect to
existing ones — there is nothing in ASH to connect with, and adding an MCP client to
a security tool along with credentials for third-party endpoints is a different
feature request. It does not pass addresses through either, because nothing in ASH
would read them. This is the narrowest option that does anything at all rather than
a preference among three, and the CRD deliberately has no field implying otherwise.

### The auth header value, and a bypass this operator shipped

`auth.headerName` with `auth.valueFrom.secretKeyRef` is the single-tenant header
check. The value reaches the pod as a `secretKeyRef` the kubelet resolves, and the
`--auth-header-value` flag is appended **by the pod's entrypoint script**, which reads
the variable at run time.

It is worth knowing why it is not simply put in argv, because the obvious-looking
middle road is a security hole and this operator shipped it. An earlier version placed
the literal string `${ASH_MCP_AUTH_HEADER_VALUE}` in argv and ran
`sh -c 'exec "$0" "$@"' <argv>`, expecting the shell to expand it. **A positional
parameter's value is never re-expanded.** So `ash mcp` received those 28 characters and
`hmac.compare_digest`'d every incoming header against them. The auth model inverts:
anyone sending the literal `${ASH_MCP_AUTH_HEADER_VALUE}` — a constant in a public
repository, also readable with `kubectl get deploy -o yaml` — authenticates, and the
holder of the real secret gets 401. Nothing upstream rescues it: `ash mcp`'s
`--auth-header-value` option declares no `envvar=`, so setting the variable alone
supplies no value.

A test asserted the literal was *present* in the rendered manifest, so the suite passed
only while the bypass existed. `tests/test_manifests.py::TestMcpAuthIsNotBypassable`
now asserts the opposite, executes the emitted command with a known value in the
environment and checks what `ash` would actually receive, and requires that an empty
Secret key makes the container exit 78 rather than start without auth. Reintroducing
the bug in a scratch copy turns seven of those tests red, which is how they were
checked for vacuity.

The same misreading of `sh -c` positional parameters had also been written into
`contract.shell_arg`'s docstring, which claimed the shard entrypoint "renders arguments
into a shell command". It does not — `build_shard_job` emits
`command: [/bin/sh, <script>]` with `args:`, and the script runs `"$@"`, so nothing on
that path re-parses argv. The guard is kept, because a path containing a newline still
has no business in an argv and because a future change that *does* add a `-c` wrapper
should not silently become exploitable; but its stated reason is now what it actually
does.

Two other things the `AshMcpServer` reconciler does that are easy to omit:

* **A capability probe as an init container.** It runs `COLUMNS=200 ash mcp --help`,
  fixed-string-greps for `--stateless-http`, and **refuses to start with exit 65**
  when `statelessHttp` was requested and the image's ASH does not have the flag.
  Without it the server runs stateful, answers 404 to every session id the platform
  injects, and still passes its health check. `--allowed-host` warns rather than
  refusing, because an adopter behind a load balancer cannot know the hostname
  before the load balancer exists.
* **Allowed hosts are lower-cased.** A load balancer lower-cases `Host` while the
  MCP SDK matches it case-sensitively, so a mixed-case value yields 421 on every
  request.

`transport: stdio` is not offered: there is no socket for a Service to route to.

The probes are `tcpSocket`, not `httpGet`, and that is measured rather than a
preference. `ash mcp --transport streamable-http --mount-path /mcp` answers **401**
to a bare `GET /mcp`, and 401 to a well-formed `initialize` POST without a session —
the MCP SDK will not serve a request that is not a protocol handshake. A kubelet
`httpGet` probe treats only 200–399 as success, so an `httpGet` probe on the mount
path can never pass: the pod stays unready, the Deployment never becomes Available,
and the symptom is a rollout that times out while the server is working perfectly.
This operator's own e2e failed exactly that way before the probe was changed. A
probe that spoke MCP properly would need the auth header value — the shared secret —
in the probe definition, where `kubectl describe pod` shows it.

## The container's argv and environment contract

The image's `ENTRYPOINT` is:

```
kopf run --standalone -m ash_operator.main
```

A deployment **must append `--namespace <ns>` as `args`, or set `KOPF_RUN_NAMESPACE`**,
and must **not** set `command:` — that would replace the ENTRYPOINT and discard
`kopf run` entirely. `manifests/operator.yaml` does it with the downward API:

```yaml
args: ["--namespace", "$(WATCH_NAMESPACE)"]
env:
  - name: WATCH_NAMESPACE
    valueFrom: { fieldRef: { fieldPath: metadata.namespace } }
```

Omitting it does **not** default to the pod's own namespace. Measured on kopf 1.37.2:
with neither `-n` nor `-A`, kopf logs
`FutureWarning: Absence of either namespaces or cluster-wide flag will become an
error soon. For now, switching to the cluster-wide mode for backward compatibility.`
and then every watcher 403s against the namespaced Role —
`jobs.batch is forbidden ... at the cluster scope`, likewise `ashscans` and
`ashmcpservers`.

The observed symptom is worse than a crash. In a kind cluster with `args` and `env`
stripped, an AshScan still reached `phase: Scanning` and its shard Job ran to
`Complete 3/3` — and then **hung there with no collector and no verdict**, because the
Job watcher was dead. Restoring `args` made the operator create the collector
immediately and the run finished `Failed` with 12 actionable findings. So a missing
`--namespace` presents as a scan that appears to be working.

If you want cluster-wide operation instead, pass `--all-namespaces` and convert the
namespaced Role to a ClusterRole + ClusterRoleBinding. Picking one of those two without
the other is the failure above.

## RBAC

Named verbs on named resources, no `*` anywhere. What is deliberately *not* granted
matters more than what is:

* **`secrets`** — never read. An `AshMcpServer`'s auth value reaches its pod through
  a `secretKeyRef` that the kubelet resolves; the operator only copies the
  reference and cannot read the value.
* **`pods/log`** — not granted. The collector's verdict arrives in the termination
  message instead. A scanner's log contains the source it scanned, including
  anything the scan found.
* **`pods/exec`, `nodes`, `namespaces`, `clusterroles`, `rolebindings`, `escalate`,
  `bind`** — none. No rule can widen the operator's own privileges.

The scan pods use a ServiceAccount with **no rules at all**, and
`automountServiceAccountToken: false`. A pod running third-party scanners over
foreign source has no business holding an API credential, and nothing in the scan
path calls the API.

`readOnlyRootFilesystem` is set on the *operator* container and deliberately **not**
on the scan pods. It was measured elsewhere in this stack to make scanners report
clean: a tool that cannot write where it expects to comes back MISSING rather than
failing, and with `fail_on_incomplete_scanners` off by default a MISSING scanner
merges into a report that reads as a complete scan. A hardening flag that converts a
scanner into silence is worse than the write it prevents.

## Tests

```
# unit -- no cluster, no docker
PYTHONPATH=. python -m pytest tests -q

# end to end -- builds two images, creates and deletes a kind cluster
ASH_OPERATOR_E2E=1 PYTHONPATH=. python -m pytest tests/e2e -v

# the generated CRDs match what the generator emits
python -m ash_operator.generate_manifests --check

uvx ruff@0.16.7 check . && uvx ruff@0.16.7 format --check .
```

The e2e is skipped unless `ASH_OPERATOR_E2E=1`, and `pytest_report_header` prints
which mode a run is in, because a suite reporting "all passed" while never having
stood a cluster up is the same shape as a gate that proves nothing.

### The unit suite runs twice, and the second run is the one that matters

`lint-and-unit` runs the unit tests in two environments that differ in exactly one
variable: whether ASH is importable.

**Without ASH** is the operator's real runtime shape — it never imports ASH — and it is
the only run that can catch an operator dependency that only works because ASH happened
to pull it in. It also exercises `crd_schema.py`'s committed-schema fallback. In that
run five tests skip: `209 passed, 5 skipped`.

**With ASH**, via `uv run --with <repo> --with ".[test]"`, those five execute:
`214 passed`, no skips. They are the only arms that can detect a divergence from real
ASH — shard-selection acceptance compared against ASH's own `validate_shard_selection`,
the committed-vs-live schema digest, schema-source preference, full exposure of every
`AshConfig` field, and the `ScannerStatus` vocabulary. A suite that skips them is
confirming the operator against itself. Their skip messages say "a real gap in coverage,
not a pass" for exactly that reason, and the second run is what closes it.

`uv` provisions its own 3.12, so this does not depend on the runner's system Python —
ASH's floor is `>=3.10,<3.15` and a runner's `/usr/bin/python3` may be older.

Two guards, because each catches what the other misses. **Any** skip in the with-ASH run
fails the job: a skip there means ASH did not import and the arms did not execute. And
each of the five is asserted to *collect* by node id, because a skip-count guard is also
satisfied by deleting the tests — measured: renaming one of the five leaves the run at
`213 passed, 1 skipped` with no skip naming it, which the count guard accepts and the
node-id guard rejects.

Building that control turned up a second way one of the five can vanish.
`_COMMITTED_SCHEMA` is derived from `crd_schema.__file__` by walking up three parents,
which reaches the repository root only when `ash_operator` is imported from the
checkout. Import it from an installed wheel — which happens as soon as `PYTHONPATH`
stops putting the source tree first — and the path resolves somewhere meaningless and
the test skips for a reason that has nothing to do with ASH. The skip message now names
both causes and prints the resolved `__file__`, and the with-ASH step's zero-skip rule
means it cannot pass unnoticed.

What it asserts, and why each one is there:

* A tree with a **known** bandit finding and a **planted** credential reports them.
  Zero findings on that fixture fails the test — given point 5 above, a green scan
  of a dirty tree is reachable and is the failure that looks most like success.
* **A negative control**: a clean tree reports zero findings *and* succeeds, with
  both selected scanners `PASSED` and their dependencies satisfied. Without it, the
  first bullet shows only that the pipeline reports something.
* **Fan-out**, not just the final number: three pods with three distinct indices,
  each index read out of the shard's own results rather than out of the pod spec;
  and `bandit` and `detect-secrets` owned by *different* shards with findings from
  both in the merged report, which is direct evidence the fan-out contributed rather
  than merely ran.
* **A missing shard is refused.** Measured two ways. Deterministically: a run that
  already succeeded has one published shard removed and the collector re-run against
  it, asserting a non-zero exit, a refusal naming index `[1]`, and that no merged
  report was written. And through the real path: a running shard pod is deleted, and
  the run must end `Succeeded` having consumed every index, or `Refused` — never
  `Succeeded` over a subset.
* **Nothing keyed on index**: two runs with different rosters and shard counts must
  produce different scanner ownership, different ConfigMap names and different
  results prefixes.

`tests/e2e/Dockerfile.ash` builds a deliberately small ASH image carrying only the
two pure-Python scanners. It is not a substitute for the real image; it is enough to
prove the contract, and a scanner needing ruby or node would add minutes to the
build while testing nothing the operator is responsible for. Note the `ENV HOME`
line in it: Kubernetes' `runAsUser` overrides the image's `USER` but does not
consult `/etc/passwd` for a home directory, so an ASH image used with this operator
needs a writable `HOME` in its environment or scanners come back MISSING.

## Known limitations

**Two authenticated clients, not one.** kopf watches with its own session built from
an `@kopf.on.login` handler; the handlers create Jobs and ConfigMaps through the
official `kubernetes` client, which reads a process-global `Configuration`. Nothing
populates that global as a side effect of kopf logging in, so
`ash_operator.auth.configure_kubernetes_client()` is called at startup. Without it
every handler fails with `urllib3.exceptions.LocationValueError: No host specified.`
— a message naming neither Kubernetes nor authentication.

**kopf 1.37.2 cannot read the in-cluster token the `kubernetes` client 36.0.3
writes.** `kubernetes.config.incluster_config` stores the bearer token under
`api_key['BearerToken']`; kopf's `login_via_client` reads
`get_api_key_with_prefix('authorization')`, which the in-cluster loader never sets.
The result is an operator that logs `Activity 'login_via_client' succeeded` and then
sends every request as `system:anonymous`, so the failure reads as an RBAC problem
and no amount of widening the Role fixes it. `ash_operator/auth.py` reads the three
projected files directly instead, and `tests/test_auth.py` pins the incompatibility
so an upgrade that fixes it is noticed rather than leaving the workaround forever.

**`nektos/act` runs `lint-and-unit` and `crd-drift`**, with `RUNNER_TOOL_CACHE` and
`AGENT_TOOLSDIRECTORY` redirected away from the root-owned `/opt/hostedtoolcache`, and
with `actions/upload-artifact` guarded by `!env.ACT`. `crd-drift` used to be impossible
under act — act's checkout leaves no usable `.git` in the job container, so the gate
failed with `fatal: not a git repository` — and that limitation dissolved when the gate
stopped asking git anything. Measured: both jobs now exit 0 under act, `crd-drift`
printing `3 generated file(s), 219418 bytes, match byte for byte`.

`e2e-kind` is docker-in-docker and needs both
`--container-daemon-socket /var/run/docker.sock` and
`--container-options "--group-add <docker socket gid>"` — without the second, every
docker call inside the job fails with `permission denied while trying to connect to
the Docker daemon socket` — plus `--network host`, because kind writes a kubeconfig
pointing at `127.0.0.1:<port>` and inside a job container that address is the
container. Two workflow bugs were found *by* act and fixed: `/usr/local/bin` is not
writable in act's images, and `pytest -q` emits **no** `N passed` line at all when
stdout is not a TTY — the count you see in a terminal is a TTY-only rewrite — so a
`grep '[0-9]+ passed'` guard reported failure on a run where 173 tests passed.
Measured across the flag matrix: `-q`, `-q -rs`, `-q --color=no` and
`-q --no-header --tb=no` all produce no count line to a file or pipe; without `-q`,
with or without `-v`, the line is there. The workflow therefore does not use `-q`.

**`resolve_results_file` and shared filesystems.** The attempt-qualified layout
assumes `rename(2)` is atomic within the results volume. That holds for one POSIX
filesystem and server-side on NFS, but an NFS client's cached directory listing can
lag another client's rename; the collector re-reads the directory on every reconcile,
which narrows but does not close that window. On a volume that is not a single
filesystem the rename degrades to copy-and-unlink, and the operator does not detect
it.

**`ash_plugin_modules` is passthrough only.** The operator cannot install a Python
module into the ASH image you name in `spec.image`. A custom plugin must be baked in.

**Two `AshScan` objects with the same name are two runs.** The results prefix is
keyed on the CR's UID rather than its name, which is what stops a recreated CR
landing on the previous run's attempts. But a terminal `AshScan` is not re-run when
re-applied; create a new object to scan again.
