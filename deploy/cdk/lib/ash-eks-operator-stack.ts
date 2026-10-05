/**
 * Installs the ASH Kubernetes operator into an EKS cluster the adopter already
 * runs.
 *
 * WHY THIS STACK EXISTS, AND WHY IT IS NOT AN EKS ADD-ON
 * -----------------------------------------------------
 * A real Amazon EKS add-on is published through AWS Marketplace as a container
 * product -- the Marketplace container product policies carry a "Requirements for
 * Amazon EKS add-on products" section -- and `AWS::EKS::Addon` can only name an
 * add-on that is already in the catalogue. Publishing one would oblige ASH to push
 * a container image to a public registry, which
 * `docs/content/docs/building-your-own-image.md` refuses on a stated trust
 * argument. So the add-on route is closed by a decision this repository has
 * already taken, not by a technical gap, and this stack takes the operator image
 * as a required parameter pointing at the ADOPTER'S OWN registry instead.
 *
 * (`AWS::EKS::Addon` is still the right resource for installing an AWS-authored
 * add-on such as the Pod Identity agent. That is a different use of the same
 * resource type and is not what was ruled out. This stack does not install one --
 * see the preconditions below for why.)
 *
 * WHAT MECHANISM ACTUALLY APPLIES THE MANIFESTS, AND WHAT WAS MEASURED
 * -------------------------------------------------------------------
 * CloudFormation has no native Kubernetes resource type. Three candidates were
 * checked against primary sources before this was written:
 *
 * 1. THE `AWSQS::Kubernetes::*` PUBLIC REGISTRY EXTENSIONS. REJECTED, MEASURED
 *    DEAD. `AWSQS::Kubernetes::Helm` and `AWSQS::Kubernetes::Resource` are still
 *    listed in the CloudFormation public third-party registry, and
 *    `DescribeType` reports `DeprecatedStatus: LIVE` for both -- which is exactly
 *    why listing them is not enough to conclude they work. The same call also
 *    reports `ProvisioningType: NON_PROVISIONABLE` and a schema whose only
 *    property is a read-only `ID`, and a description reading "This project has
 *    been retired, and will no longer be supported or maintained after March 31,
 *    2023 ... USE AT YOUR OWN RISK". Their `sourceUrl` repositories return 404.
 *    They are tombstones: registered, named, and incapable of provisioning
 *    anything. A template cannot use them.
 * 2. A LAMBDA-BACKED CUSTOM RESOURCE THAT TALKS TO THE KUBERNETES API. WHAT IS
 *    IMPLEMENTED. See the applier below.
 * 3. `AWS::EKS::Addon`. Ruled out above.
 *
 * WHY THE APPLIER USES NEITHER kubectl NOR THE `kubernetes` PIP PACKAGE
 * --------------------------------------------------------------------
 * Both would have to arrive from somewhere. A kubectl binary means a Lambda layer
 * or a download at cold start; the `kubernetes` client means a packaged
 * dependency. Either one turns this template into a CDK ASSET, and an asset means
 * `cdk bootstrap` and a staging bucket -- which `ashSynthesizer` in
 * `lib/ash-config.ts` exists specifically to avoid, because these templates are
 * launched from the console in accounts that were never bootstrapped. Every one of
 * the five committed templates is asset-free today and this one stays that way.
 *
 * So the applier is inline Python using only the Lambda runtime's own boto3 and
 * the standard library, and it speaks HTTPS to the cluster's API server directly.
 * `Code.fromInline` writes the source into the template's `ZipFile`, which
 * CloudFormation documents as capped at 4MB -- ample for this.
 *
 * HOW THE LAMBDA IS ALLOWED INTO A CLUSTER IT DID NOT CREATE
 * ---------------------------------------------------------
 * This is the part that makes the whole approach possible, and it is the reason
 * this stack could not have been written before 2023. Authentication and
 * authorization are separate problems:
 *
 *   AUTHENTICATION is a bearer token the applier mints itself: a presigned STS
 *   `GetCallerIdentity` URL carrying the cluster name in an `x-k8s-aws-id` header,
 *   base64url-encoded behind a `k8s-aws-v1.` prefix. This is the same token
 *   `aws eks get-token` produces, and the EKS best-practices guide describes it as
 *   "a pre-signed URL-based bearer token" used to authenticate to the
 *   kube-apiserver. No AWS CLI is involved, which matters because
 *   `test/ash-no-aws-cli.test.ts` holds this repository to boto3.
 *
 *   AUTHORIZATION is `AWS::EKS::AccessEntry`. Before access entries, mapping a new
 *   IAM role into a cluster meant editing the `aws-auth` ConfigMap -- which needs
 *   cluster access already, so a template starting from nothing could not do it.
 *   An access entry is a plain AWS API call, so CloudFormation can grant the
 *   applier's role Kubernetes permissions without anyone ever having had a
 *   kubeconfig.
 *
 * THE COST OF THAT, STATED PLAINLY RATHER THAN BURIED
 * --------------------------------------------------
 * The access entry associates `AmazonEKSClusterAdminPolicy`, which is
 * cluster-admin. That is not a convenience: installing a CustomResourceDefinition
 * and a ClusterRole is itself cluster-admin-level work, and the narrower built-in
 * policies (`AmazonEKSAdminPolicy` and below) cannot create either. An installer
 * that creates cluster-scoped RBAC needs cluster-scoped RBAC permission, and
 * pretending otherwise would mean shipping a template that fails at deploy.
 *
 * What bounds it instead: the policy is attached to ONE role that only Lambda can
 * assume, that role holds no other Kubernetes access, and its AWS permissions are
 * `eks:DescribeCluster` on the named cluster plus its own log stream and nothing
 * else. An adopter who wants the grant gone after installation can delete the
 * access entry -- but CloudFormation owns it, so it will be recreated on the next
 * stack update. That is a real limitation, not a hypothetical one.
 *
 * WHY POD IDENTITY RATHER THAN IRSA FOR THE OPERATOR'S OWN AWS IDENTITY
 * --------------------------------------------------------------------
 * IRSA's trust policy has to name the cluster's OIDC issuer, which is
 * cluster-specific and unknowable at synthesis time. `bin/ash.ts` synthesizes with
 * `--no-lookups` and no credentials, so the issuer could only arrive as a further
 * required parameter -- and a wrong value there produces a role that nobody can
 * assume, with no error until a pod tries. EKS Pod Identity's trust policy is the
 * static service principal `pods.eks.amazonaws.com`, so it is correct in every
 * account and region with nothing for an adopter to look up. It is the successor
 * mechanism to IRSA and carries the same "no static credentials" property, which
 * is the property that actually matters here.
 *
 * The role ships with NO permissions attached. The Kubernetes RBAC the operator
 * needs is known and installed; what its scans need from the AWS API is not, and is
 * not derivable from the RBAC. Rather than invent an AWS permission set, the
 * identity is wired and empty for an adopter to extend. A role granting more than
 * its workload needs is the failure this stack is supposed to model well.
 *
 * "NEEDS NO AWS ACCESS" IS TRUE OF THE DEFAULTS ONLY, AND THAT IS WORTH STATING
 * BECAUSE AN EMPTY ROLE READS AS A CLAIM ABOUT THE OPERATOR RATHER THAN ABOUT ITS
 * CONFIGURATION.
 *
 * The default needs nothing, and that was measured rather than inferred from a source
 * search. Every boto3 user in ASH is confined to `plugin_modules/ash_aws_plugins/` —
 * six files, no scanner among them; nothing outside that directory references it; and
 * `pyproject.toml` declares NO `entry_points` at all, which is the check that matters
 * because setuptools auto-discovery is the one registration path a grep over `.py`
 * cannot see. Every other mention of the package is `[tool.mypy.overrides]` config.
 * Without the entry-points check the conclusion would have been an
 * absence-from-my-search claim rather than a measurement.
 *
 * THE OPT-IN IS COARSER THAN "ENABLE THE ONE YOU WANT". Adding `ash_aws_plugins` to a
 * custom resource's `spec.config.ash_plugin_modules` activates ALL FOUR reporters — S3,
 * Bedrock summary, CloudWatch Logs and Security Hub — because every one of them defaults
 * to `enabled = True`. So opting in needs either a role covering all four, or three
 * explicit `enabled: false` entries alongside the one that was wanted.
 *
 * AND THE FAILURE IS NON-FATAL BY DESIGN, WHICH IS WHAT MAKES A MISSING PERMISSION THE
 * QUIET KIND. ASH's report phase deliberately does not fail a scan because one output
 * format could not be produced; it logs at ERROR and continues. An adopter who opts in
 * without the matching IAM gets four ERROR lines and a pod that still exits 0 — so this
 * operator marks the scan Complete and the S3 copy simply never happened.
 *
 * SCOPE, STATED SO THIS IS NOT READ AS BIGGER THAN IT IS: none of that touches the
 * operator's own result collection, which reads the shared volume rather than S3. It
 * bites only an adopter who opted in expecting delivery to an AWS service.
 *
 * All of it is per-resource configuration, so no static IAM policy attached here could
 * anticipate it: the same installation is correct with an empty role and incorrect with
 * one, depending on a custom resource written after deployment. Hence empty by default
 * and documented rather than guessed at.
 *
 * THE SCAN SERVICE ACCOUNT GETS NO ASSOCIATION, AND TWO SEPARATE QUESTIONS GET
 * CONFUSED HERE. Only one of them is settled by the image-pull finding:
 *
 *   1. Does `ash-scan` need an association for the scan Jobs' OWN AWS calls? NO FOR
 *      THE DEFAULT PLUGIN SET, and that qualifier is load-bearing. Nothing outside
 *      `plugin_modules/ash_aws_plugins/` touches an AWS SDK and nothing auto-loads
 *      that module — the measurement is above. A scan that opts in through
 *      `spec.config.ash_plugin_modules` REOPENS this, which is why the answer is
 *      stated conditionally rather than as a closed question.
 *   2. Would an association have fixed an image-pull failure from a private registry?
 *      NO, AND NOT FOR THE SAME REASON. The kubelet pulls before any pod identity
 *      exists, so pod identity cannot be part of a pull path at all. That one is
 *      about `imagePullSecrets` and has nothing to do with this role.
 *
 * Neither answer implies the other. Writing (1) as unconditional next to the opt-in
 * caveat above would make the caveat the thing a reader disbelieves.
 *
 * PRECONDITIONS THIS TEMPLATE CANNOT CHECK, AND WHAT EACH ONE LOOKS LIKE WHEN
 * UNMET
 * -------------------------------------------------------------------------
 * - THE CLUSTER'S AUTHENTICATION MODE MUST INCLUDE THE EKS API, i.e. `API` or
 *   `API_AND_CONFIG_MAP`. A cluster still on `CONFIG_MAP` has no access-entry API
 *   and the `AWS::EKS::AccessEntry` resource fails. Changing the mode is a
 *   one-way cluster update an adopter has to make deliberately, so this stack does
 *   not attempt it.
 * - THE CLUSTER MUST MEET THE ACCESS-ENTRY PLATFORM VERSION (eks.6 on Kubernetes
 *   1.28, eks.1 on 1.29, eks.2 on 1.30; unlisted versions all support it).
 * - THE POD IDENTITY AGENT MUST BE INSTALLED for the operator's AWS identity to
 *   resolve. This stack does not install it, because `AWS::EKS::Addon` fails with
 *   `ResourceInUseException` when the add-on is already present, and guessing
 *   wrong either way turns a working cluster's deployment red. The association is
 *   still created and is harmless without the agent -- the operator simply gets no
 *   AWS credentials, which is indistinguishable from the empty-policy default it
 *   ships with.
 * - A PRIVATE-ONLY API ENDPOINT NEEDS `VpcSubnetIds` AND `VpcSecurityGroupIds`.
 *   With a private-only endpoint and no VPC configuration the applier cannot reach
 *   the API server and the custom resource fails on connect rather than on
 *   permissions.
 *
 *   A VPC-ATTACHED APPLIER NEEDS EGRESS TO THREE SERVICES, NOT TWO: EKS, STS, and
 *   **S3**. The third is the one that gets missed, and it fails worse than the other
 *   two. CloudFormation's response URL is a presigned S3 URL, so an applier with
 *   interface endpoints for EKS and STS but no route to S3 applies every manifest
 *   successfully and then cannot report that it did — the stack sits in
 *   CREATE_IN_PROGRESS until it times out, with the manifests already installed and
 *   no error raised anywhere. Either a NAT gateway, or interface endpoints for EKS
 *   and STS plus a `com.amazonaws.<region>.s3` endpoint. `respond()` logs this cause
 *   explicitly, because its log line is the only evidence that state produces.
 *
 * THE OPERATOR CONTRACT, AND WHY IT IS DATA RATHER THAN PROSE
 * ----------------------------------------------------------
 * The CRD names and the RBAC below are transcribed from the operator's own
 * `manifests/rbac.yaml` and `ash_operator/constants.py`. They are NOT guesses, and
 * they are not a summary of a summary: an earlier version of this file installed a
 * single kind `Scan` with plural `scans`, both invented here, which is a failure
 * mode worth naming because everything reports success -- the CRD installs, the
 * operator starts, and it watches a resource nobody ever creates.
 *
 * TWO CRDs (`AshScan`/`ashscans` and `AshMcpServer`/`ashmcpservers`) and TWO
 * ServiceAccounts (`ash-operator` for the operator, `ash-scan` for the Jobs it
 * launches). Creating one of either is the same class of silent failure.
 *
 * The contract lives in exported TypeScript constants — `ASH_OPERATOR_CRDS`,
 * `ASH_OPERATOR_CLUSTER_RULES`, `ASH_OPERATOR_NAMESPACED_RULES` — and is
 * interpolated into the applier, rather than being written directly into the Python.
 * That placement is the whole point: `test/ash-eks-operator-stack.test.ts` holds an
 * independent second copy of the same table and compares the two AS SETS, failing on
 * any difference in EITHER direction. A table embedded in the Python string could
 * only be checked by grepping, and "contains the required verbs" passes while an
 * extra verb sits next to them. Over-grant on RBAC installed by a cluster-admin
 * bootstrap matters as much as under-grant.
 *
 * WHAT THAT TEST IS NOT: it is not a check against the operator's own
 * `manifests/rbac.yaml`. Both copies in this repository are HAND TRANSCRIPTIONS of
 * it. The set comparison catches this stack drifting from its own transcription; it
 * cannot catch the transcription drifting from the operator. Re-verify by hand when
 * either moves.
 *
 * WHERE THE OPERATOR ACTUALLY IS: `deploy/kubernetes-operator/`, in this repository,
 * on this commit. An earlier revision of this comment said it "lives in a different
 * repository", which was false, and that false premise was the stated justification
 * for three separate decisions here — including installing a permissive CRD schema
 * rather than the real one. The real reason for the subset schema is a measured size
 * limit, not inaccessibility; see `crd()`. A transcription is still a transcription,
 * and nothing automated couples the two files, but the source is two directories away
 * and should be read rather than recalled.
 *
 * Four rules in that table are load-bearing and each is one a reader would
 * plausibly "correct" in the wrong direction: `pods` is READ-ONLY, `batch/jobs` has
 * NO `patch` (the author moved to stateless `on.event` specifically so kopf would
 * stop patching the watched Job), there is deliberately NO `leases` rule (measured
 * unused — see note 3 below), and the `.../status` subresources are separate grants
 * carrying the operator's entire reporting path.
 *
 * THE CONTAINER ARGV, WHICH IS SETTLED AND LOAD-BEARING: the Deployment passes
 * `args: ["--namespace", "$(WATCH_NAMESPACE)"]` with `WATCH_NAMESPACE` a fieldRef on
 * the pod's own namespace, and leaves `command` unset. Kubernetes APPENDS args to the
 * image ENTRYPOINT, which already carries `kopf run --standalone -m
 * ash_operator.main`, so `--standalone` is not repeated here and `--namespace` is the
 * one part that must come from the manifest. Removing it does not fail — kopf switches
 * to cluster scope and every watcher 403s against the namespaced Role, presenting as a
 * scan that reaches `Complete 3/3` and then hangs with no verdict. An earlier revision
 * of this comment said both flags were "gone"; that was written during the window when
 * they were, and it contradicted the code. See `deployment()` for the measurement.
 *
 * One replica, because `--standalone` in the ENTRYPOINT disables peering. Raising it is
 * a three-part change — drop `--standalone`, re-add the `leases` rule, then raise the
 * count — and any subset of the three is broken.
 */

import {
  Aws,
  CfnCondition,
  CfnOutput,
  CfnParameter,
  CustomResource,
  Duration,
  Fn,
  Stack,
  StackProps,
} from 'aws-cdk-lib';
import * as eks from 'aws-cdk-lib/aws-eks';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

import { AshCustomerKey, ashSynthesizer, diagnosticLogGroupProps } from './ash-config';
import { suppressEksInstallerRoleWildcards } from './ash-nag-suppressions';

/** The custom resource API group the operator owns. */
export const ASH_OPERATOR_API_GROUP = 'ash.awslabs.github.io';

/** The custom resource version. */
export const ASH_OPERATOR_API_VERSION = 'v1alpha1';

/** Default namespace. Overridable, because a cluster may already own this name. */
export const DEFAULT_OPERATOR_NAMESPACE = 'ash-system';

/** A `kubectl get` column, as the CRD declares it. */
export interface PrinterColumn {
  readonly name: string;
  readonly type: string;
  readonly jsonPath: string;
}

/** One custom resource definition the operator watches. */
export interface AshCrd {
  readonly kind: string;
  readonly listKind: string;
  readonly plural: string;
  readonly singular: string;
  readonly shortNames: string[];
  /** `spec` fields the operator cannot run without. */
  readonly required: string[];
  /**
   * `kubectl get` columns. NOT decoration: `Phase` is the field the missing-`--namespace`
   * regression is read from, so a CRD without it hides the symptom of the defect this
   * stack most recently shipped.
   */
  readonly printerColumns: PrinterColumn[];
}

/**
 * The two CRDs the operator watches. TWO, not one.
 *
 * Taken from the operator's own `constants.py` (`GROUP`, `SCAN_PLURAL`,
 * `MCP_PLURAL`). An earlier version of this stack installed a single kind `Scan`
 * with plural `scans`; both names were wrong and one of the two resources was
 * missing entirely. A wrong plural fails in the worst available way — the CRD
 * installs, the operator starts, and it watches a resource nobody ever creates.
 */
export const ASH_OPERATOR_CRDS: AshCrd[] = [
  {
    kind: 'AshScan',
    listKind: 'AshScanList',
    plural: 'ashscans',
    singular: 'ashscan',
    shortNames: ['ashscan'],
    required: ['image', 'shardCount', 'source'],
    printerColumns: [
      { name: 'Phase', type: 'string', jsonPath: '.status.phase' },
      { name: 'Shards', type: 'integer', jsonPath: '.status.shardCount' },
      { name: 'Actionable', type: 'integer', jsonPath: '.status.findings.actionable' },
      { name: 'Incomplete', type: 'string', jsonPath: '.status.incompleteScanners' },
      { name: 'Age', type: 'date', jsonPath: '.metadata.creationTimestamp' },
    ],
  },
  {
    kind: 'AshMcpServer',
    listKind: 'AshMcpServerList',
    plural: 'ashmcpservers',
    singular: 'ashmcpserver',
    shortNames: ['ashmcp'],
    required: ['image'],
    printerColumns: [
      { name: 'Phase', type: 'string', jsonPath: '.status.phase' },
      { name: 'Endpoint', type: 'string', jsonPath: '.status.endpoint' },
      { name: 'Age', type: 'date', jsonPath: '.metadata.creationTimestamp' },
    ],
  },
];

/**
 * The operator's own ServiceAccount.
 *
 * Also the subject of the Pod Identity association, because this is the identity
 * the operator process runs under.
 */
export const OPERATOR_SERVICE_ACCOUNT = 'ash-operator';

/**
 * The ServiceAccount the scan Jobs run under. A SECOND one, and it is not optional.
 *
 * The operator launches Jobs; those Jobs run as this account, not as the operator's.
 * A stack that creates only `ash-operator` leaves every Job the operator launches
 * with no identity. It is created with NO RBAC deliberately — the authoritative
 * table grants it none, because running a scan needs no Kubernetes API access.
 */
export const SCAN_SERVICE_ACCOUNT = 'ash-scan';

/** One RBAC rule, in the shape the Kubernetes API takes it. */
export interface RbacRule {
  readonly apiGroups: string[];
  readonly resources: string[];
  readonly verbs: string[];
}

/**
 * The ONLY cluster-scoped grant the operator gets: read CustomResourceDefinitions.
 *
 * Installed as ClusterRole `ash-operator-crd-reader`. Everything else the operator
 * does is namespaced, which is why this is one rule rather than a cluster-wide
 * mirror of the namespaced set.
 */
export const ASH_OPERATOR_CLUSTER_RULES: RbacRule[] = [
  {
    apiGroups: ['apiextensions.k8s.io'],
    resources: ['customresourcedefinitions'],
    verbs: ['get', 'list', 'watch'],
  },
];

/**
 * The namespaced Role `ash-operator`, complete and exact.
 *
 * TRANSCRIBED FROM THE OPERATOR'S OWN `manifests/rbac.yaml`. Four properties of this
 * set are load-bearing and each one is a rule someone would plausibly "fix" in the
 * wrong direction:
 *
 * 1. `pods` IS READ-ONLY. The operator reads pod state; it never creates pods, the
 *    Jobs do. Adding `create`/`delete` here grants reach the operator does not use.
 * 2. `batch/jobs` HAS NO `patch`, deliberately. The author moved off
 *    `kopf.on.field` to stateless `on.event` specifically so kopf would stop
 *    patching the watched Job. Granting `patch` re-enables something that was
 *    removed on purpose.
 * 3. THERE IS NO `leases` RULE, and that is the corrected state rather than an
 *    oversight. A previous revision granted it "for kopf peering" — a reason nobody
 *    had measured. The operator takes no leases: a full scan completes without the
 *    rule, `kubectl get leases` in the namespace returns nothing, and the e2e suite
 *    passes against the reduced set. Re-adding it is only correct together with
 *    dropping `--standalone`, never alone.
 * 4. `.../status` ARE SEPARATE SUBRESOURCES with their own verbs. A grant on
 *    `ashscans` alone does NOT cover status writes, and status patches are the
 *    operator's entire reporting path.
 *
 * `test/ash-eks-operator-stack.test.ts` compares this array against the same table
 * as a SET, failing on any difference in EITHER direction. A "contains everything
 * required" assertion would pass while silently keeping an over-grant such as
 * `jobs: patch`, and over-grant on something installed by a cluster-admin bootstrap
 * matters as much as under-grant.
 */
export const ASH_OPERATOR_NAMESPACED_RULES: RbacRule[] = [
  {
    apiGroups: [ASH_OPERATOR_API_GROUP],
    resources: ['ashscans', 'ashmcpservers'],
    verbs: ['get', 'list', 'watch', 'patch'],
  },
  {
    apiGroups: [ASH_OPERATOR_API_GROUP],
    resources: ['ashscans/status', 'ashmcpservers/status'],
    verbs: ['get', 'patch'],
  },
  {
    apiGroups: ['batch'],
    resources: ['jobs'],
    // No `patch`. See note 2 above.
    verbs: ['get', 'list', 'watch', 'create', 'delete'],
  },
  {
    apiGroups: [''],
    resources: ['pods'],
    // Read-only. See note 1 above.
    verbs: ['get', 'list', 'watch'],
  },
  {
    apiGroups: [''],
    resources: ['configmaps'],
    verbs: ['get', 'list', 'watch', 'create', 'delete'],
  },
  {
    apiGroups: [''],
    resources: ['persistentvolumeclaims'],
    verbs: ['get', 'list', 'watch', 'create', 'delete'],
  },
  { apiGroups: [''], resources: ['events'], verbs: ['create'] },
  { apiGroups: ['events.k8s.io'], resources: ['events'], verbs: ['create'] },
  {
    apiGroups: ['apps'],
    resources: ['deployments'],
    verbs: ['get', 'list', 'watch', 'create', 'patch'],
  },
  {
    apiGroups: [''],
    resources: ['services'],
    verbs: ['get', 'list', 'watch', 'create', 'patch'],
  },
  // NO `coordination.k8s.io/leases` RULE, AND ITS ABSENCE IS MEASURED RATHER THAN
  // ASSUMED. An earlier revision granted it on the stated reason "kopf peering needs
  // it". That reason was invented; the operator does not use leases. Measured against
  // the running operator: a full three-shard scan completed normally without the
  // rule, `kubectl get leases -n ash-system` returned no resources, the operator log
  // carried zero lease lines, and the end-to-end suite passed 38/0 against the
  // reduced manifest. It is being removed from the operator's own rbac.yaml for the
  // same reason.
  //
  // RE-ADD IT ONLY TOGETHER WITH DROPPING `--standalone`. More than one replica needs
  // peering, peering needs leases, and either change alone is broken: leases without
  // dropping standalone is an unused grant, and dropping standalone without leases
  // leaves peering unable to take a lock.
];

/**
 * Render a value as a literal that is valid in BOTH JSON and Python source.
 *
 * The RBAC and CRD contract is defined once, above, in TypeScript — so that the
 * test can compare it against the authoritative table as data rather than by
 * grepping prose — and is interpolated into the applier below. That works because
 * these structures hold only strings, arrays and objects, whose JSON spelling is
 * also their Python spelling.
 *
 * It STOPS working the moment a boolean or a null appears: JSON writes `true`,
 * `false` and `null` where Python needs `True`, `False` and `None`, and the result
 * would be a `NameError` inside a Lambda at deploy time — long after synth, and with
 * nothing in CI to catch it, because no tool in this repository parses the embedded
 * source. So this throws AT SYNTH TIME instead, which turns a deploy-time crash into
 * a failed build.
 */
export function pythonLiteral(value: unknown): string {
  // Indented, not single-line. Two reasons, one mechanical and one for readers: a
  // one-line array of eleven RBAC rules is a 1061-character line, which the repo's
  // 88-column Python width rejects; and the rules are the most security-relevant
  // thing in the emitted template, so they should be legible to someone reading
  // AshEksOperator.template.json rather than a wall of text. Indentation inside
  // brackets is insignificant in Python, so this stays valid.
  const json = JSON.stringify(value, null, 2);
  const offender = /\b(true|false|null)\b/.exec(json);
  if (offender) {
    throw new Error(
      `pythonLiteral cannot render ${offender[1]}: JSON spells booleans and null ` +
        'differently from Python, so interpolating this would produce a NameError inside ' +
        'the Lambda. Add an explicit conversion before extending this structure.',
    );
  }
  return json;
}

/**
 * The Kubernetes manifest applier, written into the template's `ZipFile`.
 *
 * WHY THE MANIFESTS ARE BUILT HERE RATHER THAN PASSED IN AS PROPERTIES
 * -------------------------------------------------------------------
 * CloudFormation renders custom resource properties as strings. A Deployment's
 * `replicas` has to be a JSON number and the API server rejects `"1"`, so a
 * manifest routed through `ResourceProperties` would arrive subtly malformed in
 * exactly the fields that are not strings. Passing only strings -- cluster name,
 * namespace, image, service account -- and constructing the documents here keeps
 * every type correct by construction. It also keeps the manifests reviewable as
 * Python literals instead of as a serialized blob inside a template.
 *
 * SERVER-SIDE APPLY, NOT CREATE-THEN-PATCH
 * ----------------------------------------
 * Every document is sent as a PATCH with `Content-Type:
 * application/apply-patch+yaml` (JSON is valid YAML, so the JSON body is
 * accepted). Server-side apply is create-or-update in one request, which makes a
 * stack UPDATE and a stack CREATE take the same code path and makes a retry after
 * a partial failure idempotent. The alternative -- POST, catch 409, PATCH -- has
 * two paths and only one of them gets exercised in practice.
 *
 * WHAT HAPPENS ON FAILURE
 * -----------------------
 * Any unhandled error is caught and reported to CloudFormation as FAILED with the
 * exception text, so the stack rolls back with a reason rather than sitting in
 * CREATE_IN_PROGRESS until its internal timeout. A DELETE tolerates 404 on every
 * document, so tearing down a stack whose install half-failed still completes.
 */
export const ASH_OPERATOR_APPLIER = `import base64
import json
import ssl
import tempfile
import time
import urllib.error
import urllib.request

import boto3
from botocore.signers import RequestSigner

# Interpolated at synth time from the TypeScript constants above, which are the
# single source of truth for what this stack installs.
#
# test/ash-eks-operator-stack.test.ts compares them AS A SET against a second copy
# of the same table, so an over-grant is caught as loudly as a missing grant.
#
# WHAT THAT TEST DOES NOT DO, STATED SO NOBODY RELIES ON IT: it does not read the
# operator's manifests/rbac.yaml. Both copies were TRANSCRIBED BY HAND from it, and
# nothing couples the two, so when the operator's real RBAC changes nothing in this
# repository will report that the transcription has gone stale. The file itself is at
# deploy/kubernetes-operator/manifests/rbac.yaml in this repository -- an earlier
# version of this comment said another repository, which was wrong -- so re-checking
# means opening it, not recalling it.
GROUP = "${ASH_OPERATOR_API_GROUP}"
VERSION = "${ASH_OPERATOR_API_VERSION}"
CRDS = ${pythonLiteral(ASH_OPERATOR_CRDS)}
CLUSTER_RULES = ${pythonLiteral(ASH_OPERATOR_CLUSTER_RULES)}
NAMESPACED_RULES = ${pythonLiteral(ASH_OPERATOR_NAMESPACED_RULES)}
OPERATOR_SA = "${OPERATOR_SERVICE_ACCOUNT}"
SCAN_SA = "${SCAN_SERVICE_ACCOUNT}"
CLUSTER_ROLE = "ash-operator-crd-reader"
ROLE = "ash-operator"
TOKEN_TTL_SECONDS = 60
ATTEMPTS = 5
# "Custom resource response -- the maximum amount of data that a custom resource
# provider can pass. 4,096 bytes", from the CloudFormation quotas page. The row does not
# say whether it counts the whole body or only Data, so respond() bounds the whole body.
RESPONSE_MAX_BYTES = 4096

LABELS = {
    "app.kubernetes.io/name": "ash-operator",
    "app.kubernetes.io/managed-by": "ash-cfn",
}

RBAC = "/apis/rbac.authorization.k8s.io/v1"


def cluster_token(session, cluster_name):
    """The bearer token the kube-apiserver accepts: a presigned STS URL.

    Identical in form to the token the EKS CLI's get-token helper emits, built
    here with boto3 because the Lambda runtime ships no CLI. The endpoint comes
    from the client rather than from an f-string so this stays correct outside
    the commercial partition.
    """
    client = session.client("sts")
    signer = RequestSigner(
        client.meta.service_model.service_id,
        session.region_name,
        "sts",
        "v4",
        session.get_credentials(),
        session.events,
    )
    url = signer.generate_presigned_url(
        {
            "method": "GET",
            "url": (
                client.meta.endpoint_url
                + "/?Action=GetCallerIdentity&Version=2011-06-15"
            ),
            "body": {},
            "headers": {"x-k8s-aws-id": cluster_name},
            "context": {},
        },
        region_name=session.region_name,
        expires_in=TOKEN_TTL_SECONDS,
        operation_name="",
    )
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8")
    # The padding is stripped because the authenticator's decoder rejects it.
    return "k8s-aws-v1." + encoded.rstrip("=")


def service_account(name, namespace):
    return {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": name, "namespace": namespace, "labels": LABELS},
    }


def subject(name, namespace):
    return {"kind": "ServiceAccount", "name": name, "namespace": namespace}


def crd(entry):
    """One CustomResourceDefinition, built from a CRDS entry.

    The metadata name MUST be plural.group or the API server rejects it with a
    name mismatch that reads like a schema error.

    THE SCHEMA IS A DELIBERATE SUBSET because the operator's own CRDs are ~98KB and
    ~91KB of YAML against a 50,688-byte template budget. It validates what the
    operator cannot run without and preserves unknown fields elsewhere.

    NOT VALIDATED HERE: everything deeper in spec.config. For full validation apply
    the operator's own generated CRD; this stack applies CRDs without force and will
    not overwrite it. See the stack header under THE OPERATOR CONTRACT.
    """
    crd_name = entry["plural"] + "." + GROUP
    spec_properties = {
        "image": {"type": "string", "minLength": 1},
    }
    if "shardCount" in entry["required"]:
        spec_properties["shardCount"] = {"type": "integer", "minimum": 1, "maximum": 50}
    if "source" in entry["required"]:
        spec_properties["source"] = {
            "type": "object",
            "x-kubernetes-preserve-unknown-fields": True,
        }
    schema = {
        "type": "object",
        "required": ["spec"],
        "properties": {
            "spec": {
                "type": "object",
                "required": entry["required"],
                "properties": spec_properties,
                "x-kubernetes-preserve-unknown-fields": True,
            },
            "status": {"type": "object", "x-kubernetes-preserve-unknown-fields": True},
        },
    }
    return {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": crd_name, "labels": LABELS},
        "spec": {
            "group": GROUP,
            "scope": "Namespaced",
            "names": {
                "plural": entry["plural"],
                "singular": entry["singular"],
                "kind": entry["kind"],
                "listKind": entry["listKind"],
                "shortNames": entry["shortNames"],
            },
            "versions": [
                {
                    "name": VERSION,
                    "served": True,
                    "storage": True,
                    "subresources": {"status": {}},
                    "additionalPrinterColumns": entry["printerColumns"],
                    "schema": {"openAPIV3Schema": schema},
                }
            ],
        },
    }


def cluster_role():
    """ClusterRole ash-operator-crd-reader: the ONLY cluster-scoped grant.

    Everything else the operator does is namespaced. The rules come from
    CLUSTER_RULES, which the test set-compares against the operator's rbac.yaml.
    """
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": CLUSTER_ROLE, "labels": LABELS},
        "rules": CLUSTER_RULES,
    }


def namespaced_role(namespace):
    """Role ash-operator, from NAMESPACED_RULES.

    Do not edit the rules here -- they are interpolated from the TypeScript
    constant so that one table is both installed and tested.
    """
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": ROLE, "namespace": namespace, "labels": LABELS},
        "rules": NAMESPACED_RULES,
    }


def cluster_role_binding(namespace):
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": CLUSTER_ROLE, "labels": LABELS},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": CLUSTER_ROLE,
        },
        "subjects": [subject(OPERATOR_SA, namespace)],
    }


def role_binding(namespace):
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": ROLE, "namespace": namespace, "labels": LABELS},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": ROLE,
        },
        "subjects": [subject(OPERATOR_SA, namespace)],
    }


def deployment(namespace, image):
    """The operator Deployment.

    replicas is an int, not a string, which is the reason these manifests are
    built here instead of being routed through the custom resource's properties:
    CloudFormation renders every property value as a string and the API server
    rejects "1".

    'args' IS LOAD-BEARING. DO NOT REMOVE IT. Without '--namespace' kopf does not
    fail -- it switches to cluster scope, every watcher 403s against the namespaced
    Role, and a scan reaches 'Complete 3/3' and then hangs with no verdict. Leave
    'command' unset: setting it replaces the ENTRYPOINT and drops 'kopf run'.

    Full reasoning, the measured symptom and the cluster-wide recipe are in the
    stack header of ash-eks-operator-stack.ts under THE CONTAINER ARGV.
    """
    container = {
        "name": "operator",
        "image": image,
        # Appended to the image ENTRYPOINT; removing it makes every scan hang after the
        # Job completes rather than failing. $(WATCH_NAMESPACE) rather than the
        # namespace literal: the kubelet expands it from the env var below, a fieldRef
        # on the pod's OWN namespace, so the watched namespace cannot disagree with
        # where the Deployment landed. A literal would be a second copy, and two copies
        # of this value desyncing produces the silent hang rather than an error.
        "args": ["--namespace", "$(WATCH_NAMESPACE)"],
        "env": [
            {
                "name": "WATCH_NAMESPACE",
                "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}},
            }
        ],
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "resources": {
            "requests": {"cpu": "100m", "memory": "256Mi"},
            "limits": {"memory": "512Mi"},
        },
        "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
    }
    pod = {
        "serviceAccountName": OPERATOR_SA,
        "securityContext": {
            "runAsNonRoot": True,
            # 1000, NOT AN INVENTED HIGH UID. The image creates one user at uid 1000 and
            # ends with USER 1000; its own manifest sets runAsUser: 1000 and the
            # Dockerfile says the uid must match. An earlier 10001 here ran the process
            # as a uid with no passwd entry and no home, so pwd.getpwuid raises
            # KeyError.
            "runAsUser": 1000,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [container],
        "volumes": [{"name": "tmp", "emptyDir": {}}],
    }
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": ROLE, "namespace": namespace, "labels": LABELS},
        "spec": {
            # ONE REPLICA, AND SCALING OUT IS A THREE-PART CHANGE, NOT A NUMBER.
            # The ENTRYPOINT carries --standalone, which disables kopf peering, so a
            # second replica would process every event twice. Going above one needs
            # all three together: drop --standalone (which means overriding the
            # ENTRYPOINT, so read the args note above first), re-add the
            # coordination.k8s.io/leases rule peering needs, and only then raise this.
            # Any one or two of the three alone is broken.
            "replicas": 1,
            "selector": {
                "matchLabels": {"app.kubernetes.io/name": "ash-operator"},
            },
            "template": {"metadata": {"labels": LABELS}, "spec": pod},
        },
    }


CLUSTER = "cluster"
NAMESPACED = "namespaced"


def documents(namespace, image):
    """(path, manifest, scope) for every object, in creation order.

    Paths are explicit rather than derived from apiVersion and kind: deriving needs a
    kind-to-plural table, which is one more thing to get wrong for no benefit here.

    THE SCOPE TAG IS THE WHOLE SAFETY RULE -- nothing CLUSTER-scoped is ever deleted.
    See the delete loop in handler(). Tagging each document means one added later is
    covered the moment it declares its scope.

    TWO ServiceAccounts. SCAN_SA exists for the scan Jobs but they do NOT run as it by
    default: the operator reads spec.get("scanServiceAccountName", "default"), so an
    adopter must also set that field. Creating it is necessary, not sufficient.
    SCAN_SA gets no RBAC -- the authoritative table grants it none.
    """
    ns_path = "/api/v1/namespaces/" + namespace
    crd_base = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/"
    out = [
        (
            ns_path,
            {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": namespace, "labels": LABELS},
            },
            CLUSTER,
        )
    ]
    for entry in CRDS:
        out.append((crd_base + entry["plural"] + "." + GROUP, crd(entry), CLUSTER))
    for name in (OPERATOR_SA, SCAN_SA):
        out.append(
            (
                ns_path + "/serviceaccounts/" + name,
                service_account(name, namespace),
                NAMESPACED,
            )
        )
    out.append((RBAC + "/clusterroles/" + CLUSTER_ROLE, cluster_role(), CLUSTER))
    out.append(
        (
            RBAC + "/clusterrolebindings/" + CLUSTER_ROLE,
            cluster_role_binding(namespace),
            CLUSTER,
        )
    )
    out.append(
        (
            RBAC + "/namespaces/" + namespace + "/roles/" + ROLE,
            namespaced_role(namespace),
            NAMESPACED,
        )
    )
    out.append(
        (
            RBAC + "/namespaces/" + namespace + "/rolebindings/" + ROLE,
            role_binding(namespace),
            NAMESPACED,
        )
    )
    out.append(
        (
            "/apis/apps/v1/namespaces/" + namespace + "/deployments/" + ROLE,
            deployment(namespace, image),
            NAMESPACED,
        )
    )
    return out

def request(endpoint, ca_file, token_for, path, method, body, force=True):
    """One HTTPS request to the API server, with a FRESHLY MINTED token.

    force=False KEEPS A CRD FROM BEING SILENTLY DOWNGRADED: server-side apply with
    force takes ownership from another field manager without a word, and the schema
    installed here is a deliberate subset of the operator's own.

    THE TOKEN IS MINTED PER REQUEST, NOT PER INVOCATION, and that placement is
    load-bearing. TOKEN_TTL_SECONDS is 60 while one retry chain can run 181s, so a
    token minted before the loop expires mid-install and call() treats the resulting
    401 as non-retryable. Minting here costs a local signing operation and no network
    call, so it removes the failure mode rather than widening a window.
    """
    url = endpoint + path
    if method == "PATCH":
        url += "?fieldManager=ash-cfn-installer"
        url += "&force=true" if force else "&force=false"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token_for())
    req.add_header("Accept", "application/json")
    if method == "PATCH":
        req.add_header("Content-Type", "application/apply-patch+yaml")
    context = ssl.create_default_context(cafile=ca_file)
    with urllib.request.urlopen(req, timeout=30, context=context) as response:
        return response.status, response.read()


def call(
    endpoint,
    ca_file,
    token_for,
    path,
    method,
    body,
    tolerate_404=False,
    force=True,
    tolerate_409=False,
):
    """One request, retried on transient failures only.

    A 4xx other than 404-when-tolerated is not retried: it is a permission or a
    schema problem, and retrying it just delays the real error by five attempts.

    That classification is only safe because request() mints a fresh token on every
    attempt. An expired-credential 401 is a 4xx that WOULD be worth retrying, and
    while the token was minted once per invocation it was reachable here -- so the
    two decisions are coupled and must not be changed independently.

    tolerate_409 is for the CRDs applied with force=False. A 409 there means another
    field manager already owns the object, which for a CRD is the GOOD case: whoever
    owns it applied the operator's authoritative schema, which is strictly richer than
    the subset this stack carries. Leaving theirs alone is correct, so the conflict is
    reported and stepped over rather than failing the install.
    """
    last = None
    for attempt in range(ATTEMPTS):
        try:
            return request(
                endpoint, ca_file, token_for, path, method, body, force=force
            )
        except urllib.error.HTTPError as err:
            detail = err.read().decode("utf-8", "replace")
            if err.code == 404 and tolerate_404:
                return err.code, detail.encode("utf-8")
            if err.code == 409 and tolerate_409:
                print(
                    "KEEPING THE EXISTING OBJECT AT " + path + ": another field "
                    "manager owns it, so this stack is not overwriting it. If that "
                    "is the operator's own CustomResourceDefinition it validates "
                    "more than the subset installed here, so keeping it is better."
                )
                return err.code, detail.encode("utf-8")
            if err.code < 500:
                raise RuntimeError(
                    method + " " + path + " failed " + str(err.code) + ": " + detail
                ) from err
            last = err
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            # Includes the connect failure a private-only API endpoint produces
            # when the function is not attached to the cluster's VPC.
            last = err
        time.sleep(2 ** attempt)
    raise RuntimeError(
        method
        + " "
        + path
        + " failed after "
        + str(ATTEMPTS)
        + " attempts: "
        + repr(last)
    )


def pod_identity_agent_state(session, cluster_name):
    """Whether the EKS Pod Identity agent add-on is installed on the cluster.

    Reported as custom resource Data so the stack can surface it as an OUTPUT,
    because an absent agent is otherwise completely silent: the association is
    created, the operator receives no AWS credentials, and that is
    indistinguishable from the zero-permission role this stack ships on purpose.
    One symptom, two very different causes, and no signal anywhere telling them
    apart.

    ANY failure here yields UNKNOWN rather than failing the install. This probe is
    diagnostic, and an IAM denial on eks:DescribeAddon must never be the reason an
    operator does not get installed.
    """
    try:
        addon = session.client("eks").describe_addon(
            clusterName=cluster_name, addonName="eks-pod-identity-agent"
        )
        return addon["addon"].get("status") or "UNKNOWN"
    except Exception as err:  # noqa: BLE001 - diagnostic only, never fatal
        if "ResourceNotFound" in type(err).__name__ or "ResourceNotFound" in repr(err):
            return "ABSENT"
        print("pod identity agent probe did not resolve: " + repr(err))
        return "UNKNOWN"


def respond(event, status, reason, physical_id, data=None):
    """PUT the CloudFormation response.

    A FAILURE HERE IS THE ONE ERROR THIS FUNCTION CANNOT REPORT, because this is the
    reporting channel. The response URL is a presigned S3 URL, which makes S3 a third
    required egress alongside EKS and STS -- the one that gets missed. The log line
    below is the only evidence that state produces, so it names the cause.

    The body is bounded to RESPONSE_MAX_BYTES here rather than trusted to be small.
    See the stack header under PRECONDITIONS for the S3 egress requirement.
    """
    # BOUNDED IN SERIALIZED BYTES, NOT CHARACTERS. reason[:1000] was a character slice
    # while json.dumps defaults to ensure_ascii=True, so 1,000 non-ASCII characters
    # became 6,000 bytes of escapes against a 4,096-byte cap -- on an ERROR message,
    # i.e. when the response matters most. Reachable: call() decodes failures with
    # errors="replace" and every U+FFFD escapes to six bytes.
    #
    # ensure_ascii=False makes a byte budget mean something. A byte slice can split a
    # character, so the tail is re-decoded with errors="ignore".
    #
    # WHAT ENFORCES THE CAP: the [:1000] PRE-SLICE, not the loop. An earlier comment
    # here claimed the loop, wrongly. The unshrinkable fields total ~700 bytes, so the
    # body lands near 1.7 KB and the loop NEVER ITERATES today -- it is belt-and-braces
    # for when one of them grows. The loop exits on an empty reason, which is not the
    # same as the body fitting, so the residual is handled below.
    def serialize(reason_bytes):
        return json.dumps(
            {
                "Status": status,
                "Reason": reason_bytes.decode("utf-8", "ignore"),
                "PhysicalResourceId": physical_id,
                "StackId": event["StackId"],
                "RequestId": event["RequestId"],
                "LogicalResourceId": event["LogicalResourceId"],
                "Data": data or {},
            },
            ensure_ascii=False,
        ).encode("utf-8")

    raw_reason = reason.encode("utf-8")[:1000]
    body = serialize(raw_reason)
    while len(body) > RESPONSE_MAX_BYTES and raw_reason:
        # Halving rather than stepping: the fields this cannot shrink -- StackId,
        # LogicalResourceId, PhysicalResourceId, Data -- are bounded by CloudFormation
        # and by this stack's own parameter limits, so a few iterations always suffice
        # and an unbounded loop is impossible.
        raw_reason = raw_reason[: len(raw_reason) // 2]
        body = serialize(raw_reason)
    if len(raw_reason) < min(len(reason.encode("utf-8")), 1000):
        print("reason truncated to fit " + str(RESPONSE_MAX_BYTES) + " bytes")
    if len(body) > RESPONSE_MAX_BYTES:
        # Reason empty and still over. What remains is CloudFormation's own identifiers
        # plus Data, and dropping either breaks the response's identity or an Output
        # that reads Data -- so it is sent as-is and said out loud. Sent rather than
        # withheld because an oversized response MAY be rejected, while sending nothing
        # hangs the stack with no log line at all.
        print(
            "RESPONSE IS " + str(len(body)) + " BYTES, OVER "
            + str(RESPONSE_MAX_BYTES) + ", reason already empty. Sending anyway; if "
            "CloudFormation rejects it the stack waits. Shrink Data."
        )
    req = urllib.request.Request(event["ResponseURL"], data=body, method="PUT")
    req.add_header("Content-Type", "")
    req.add_header("Content-Length", str(len(body)))
    try:
        with urllib.request.urlopen(req, timeout=30):
            pass
    except Exception as err:  # noqa: BLE001 - logged because it cannot be reported
        print(
            "CANNOT REACH THE CLOUDFORMATION RESPONSE URL: "
            + repr(err)
            + " -- that URL is a presigned S3 URL. A VPC-attached function needs a "
            "NAT gateway or a com.amazonaws.<region>.s3 endpoint to reach it; "
            "interface endpoints for EKS and STS alone are NOT enough. The stack "
            "will now sit in CREATE_IN_PROGRESS or DELETE_IN_PROGRESS until it "
            "times out -- cancel the stack operation."
        )
        raise


def handler(event, context):
    # Set before anything that can raise, so the failure path always has an id to
    # report. Keeping the same id across a failed CREATE and its rollback matters:
    # a changed id makes CloudFormation delete a resource it never created.
    physical_id = event.get("PhysicalResourceId") or "ash-operator-install"
    status = "FAILED"
    reason = "the handler did not reach a verdict"
    data = {}

    # THE BACKSTOP FOR THIS DESIGN'S OWN WORST FAILURE MODE, and the arithmetic makes it
    # reachable: one document can burn 30*5 + 31 = 181s of timeouts and backoff, so four
    # of ten exhaust a 600s Lambda. A killed function answers nothing, which is the
    # CREATE_IN_PROGRESS-until-timeout state this design is most exposed to. 'context'
    # was accepted and never read; it carries the remaining budget. Reserve is 45s: one
    # request plus margin for the response PUT, which also crosses the network.
    deadline_ms = 45_000

    def out_of_time():
        try:
            return context.get_remaining_time_in_millis() < deadline_ms
        except Exception:  # noqa: BLE001 - a missing context must not break the install
            return False

    try:
        # Read the properties INSIDE the try. They used to be read above it, so a
        # missing property raised before any responder existed -- and the symptom
        # was the same indefinite CREATE_IN_PROGRESS hang as an unreachable
        # response URL, with nothing anywhere naming the missing property.
        props = event.get("ResourceProperties") or {}
        cluster_name = props["ClusterName"]
        namespace = props["Namespace"]
        image = props["OperatorImage"]

        # DERIVED FROM THE TARGET, ALWAYS -- never carried over from the event. Keeping
        # the event's id silently orphaned an install whenever OperatorNamespace changed
        # on an UPDATE: no Delete was issued for the old namespace, which kept a running
        # Deployment while the shared ClusterRoleBinding was repointed away from it.
        # Deriving it makes a namespace change a replacement, so CloudFormation sends a
        # Delete carrying the OLD properties. Stable for a given (cluster, namespace),
        # so changing the image or the VPC config is still an in-place update.
        physical_id = cluster_name + "/" + namespace

        deleting = event["RequestType"] == "Delete"

        session = boto3.session.Session()
        cluster = None
        try:
            described = session.client("eks").describe_cluster(name=cluster_name)
            cluster = described["cluster"]
        except Exception as err:  # noqa: BLE001 - classified, not swallowed
            # A DELETE AGAINST A CLUSTER THAT NO LONGER EXISTS MUST SUCCEED. Deleting
            # the cluster first is ordinary teardown; everything this stack created went
            # with it. This call used to run ahead of the Delete branch, so
            # ResourceNotFoundException answered FAILED and left the stack PERMANENTLY
            # in DELETE_FAILED -- every retry re-ran the same lookup against the same
            # absent cluster. Narrowed by exception name: an AccessDenied or a throttle
            # during a Delete is a real failure a retry can clear, and is still
            # reported.
            missing = "ResourceNotFound" in type(err).__name__ or (
                "ResourceNotFound" in repr(err)
            )
            if not (deleting and missing):
                raise
            print("cluster " + cluster_name + " is gone; nothing left to delete")

        def token_for():
            return cluster_token(session, cluster_name)

        # Guarded, not unconditional: with no cluster there is no endpoint and no CA,
        # and this used to sit above the Delete branch where it raised on cluster[...].
        endpoint = None
        ca_file = None
        if cluster is not None:
            endpoint = cluster["endpoint"]
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".crt", delete=False, dir="/tmp"
            ) as handle:
                handle.write(
                    base64.b64decode(cluster["certificateAuthority"]["data"]).decode("utf-8")
                )
                ca_file = handle.name

        if cluster is None:
            # Only reachable on a Delete whose cluster is already gone; anything else
            # was re-raised above. Nothing to connect to and nothing to remove.
            status = "SUCCESS"
            reason = "cluster " + cluster_name + " no longer exists; nothing to delete"
        elif deleting:
            # NOTHING CLUSTER-SCOPED IS EVER DELETED. NARROWING THIS IS THE MOST
            # DESTRUCTIVE CHANGE ANYONE COULD MAKE TO THIS FILE.
            #
            # Deleting the namespace cascade-deletes everything in it; deleting a CRD
            # cascade-deletes every AshScan in EVERY namespace of the cluster; deleting
            # the ClusterRole or its binding strips any second installation's operator
            # of its CRD read. In each case CloudFormation reports DELETE_COMPLETE and
            # nothing signals what went with it. An ownership check was rejected at
            # every scope: "unused now" races with anything that starts using it.
            #
            # The cost is leftover cluster-scoped objects, which are cheap and
            # recoverable. The uninstall still removes the Deployment, so the operator
            # stops. Full reasoning is in the stack header of ash-eks-operator-stack.ts.
            removed = 0
            kept = 0
            for path, _, scope in reversed(documents(namespace, image)):
                if out_of_time():
                    raise RuntimeError(
                        "ran out of Lambda time after deleting "
                        + str(removed)
                        + " object(s); re-run the stack delete to finish"
                    )
                if scope == CLUSTER:
                    kept += 1
                    continue
                call(
                    endpoint,
                    ca_file,
                    token_for,
                    path,
                    "DELETE",
                    None,
                    tolerate_404=True,
                )
                removed += 1
            status = "SUCCESS"
            reason = (
                "deleted "
                + str(removed)
                + " namespaced object(s); kept "
                + str(kept)
                + " cluster-scoped object(s) on purpose"
            )
        else:
            applied = 0
            kept_existing = 0
            for path, manifest, _ in documents(namespace, image):
                if out_of_time():
                    raise RuntimeError(
                        "ran out of Lambda time after applying "
                        + str(applied)
                        + " of "
                        + str(len(documents(namespace, image)))
                        + " object(s); the install is incomplete"
                    )
                # CRDs go in WITHOUT force, so an existing one owned by another field
                # manager is left alone rather than silently downgraded to the subset
                # schema this stack carries. Everything else this stack owns outright
                # and force=True is correct: those are objects it created and must be
                # able to converge on a stack UPDATE.
                is_crd = manifest["kind"] == "CustomResourceDefinition"
                code, _body = call(
                    endpoint,
                    ca_file,
                    token_for,
                    path,
                    "PATCH",
                    manifest,
                    force=not is_crd,
                    tolerate_409=is_crd,
                )
                if code == 409:
                    kept_existing += 1
                else:
                    applied += 1
            status = "SUCCESS"
            reason = "applied " + str(applied) + " object(s)"
            if kept_existing:
                reason += "; kept " + str(kept_existing) + " CRD(s) owned elsewhere"
            data = {"PodIdentityAgent": pod_identity_agent_state(session, cluster_name)}
    except Exception as err:  # noqa: BLE001 - the response is the error channel
        print("FAILED: " + repr(err))
        status = "FAILED"
        reason = repr(err)

    # ONE respond call, on every path including the early-failure one. The previous
    # shape had three call sites and an early return, which is how the
    # property-read above came to sit outside the try without it being obvious.
    respond(event, status, reason, physical_id, data)
`;

// The ServiceAccount names are OPERATOR_SERVICE_ACCOUNT and SCAN_SERVICE_ACCOUNT,
// declared at the top of this file and interpolated into the applier. There is
// deliberately no second copy here: a local constant duplicating one of them is how
// the association and the manifests would come to name different accounts, which
// produces an association pointing at a ServiceAccount that does not exist — silent,
// because nothing fails until a pod asks for credentials.

/**
 * Installs the ASH operator into an existing EKS cluster.
 */
export class AshEksOperatorStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps = {}) {
    super(scope, id, { synthesizer: ashSynthesizer(), ...props });

    /**
     * REQUIRED, NO DEFAULT. A default cluster name would either name a cluster
     * the adopter does not have -- failing at deploy with a confusing
     * ResourceNotFound -- or, worse, name one they do have and install into it by
     * accident. `MinLength: 1` makes the console refuse an empty value.
     */
    const clusterName = new CfnParameter(this, 'EksClusterName', {
      type: 'String',
      minLength: 1,
      // EKS's own cluster name constraint.
      allowedPattern: '^[0-9A-Za-z][A-Za-z0-9\\-_]{0,99}$',
      description:
        'Name of the EXISTING EKS cluster to install the ASH operator into. Required. Its ' +
        'authentication mode must include the EKS API (API or API_AND_CONFIG_MAP), or the ' +
        'access entry this stack creates cannot be created.',
    });

    /**
     * REQUIRED, NO DEFAULT, AND DELIBERATELY UNSATISFIABLE BY GUESSWORK.
     *
     * ASH publishes no operator image anywhere, so there is no value this
     * template could default to that would work. The pattern demands a registry
     * host and an explicit tag or digest, which is what rejects the two plausible
     * wrong answers: a bare `ash-operator` (no registry, so the kubelet would
     * silently try Docker Hub) and an untagged repository URI (which resolves to
     * `:latest`, a tag ASH does not publish either).
     *
     * This mirrors the posture `automated_security_helper/utils/tool_downloads.py`
     * takes for a missing installer digest -- refuse rather than install
     * something plausible -- adapted to the one enforcement a CloudFormation
     * parameter actually has. A regex cannot prove the image exists; what it can
     * do is make the failure happen in the console, before anything is created,
     * instead of as an ImagePullBackOff twenty minutes later.
     */
    const operatorImage = new CfnParameter(this, 'OperatorImageUri', {
      type: 'String',
      minLength: 1,
      allowedPattern:
        '^[A-Za-z0-9][A-Za-z0-9.\\-]*(:[0-9]+)?/[A-Za-z0-9._\\-/]+(:[A-Za-z0-9._\\-]+|@sha256:[a-f0-9]{64})$',
      description:
        'Full URI of the ASH operator image in YOUR OWN registry, including an explicit tag ' +
        'or digest -- of the form <account>.dkr.ecr.<region>.amazonaws.com/ash-operator:v1 ' +
        '(the account and region placeholders are deliberately not spelled as digits here; ' +
        'a 12-digit literal anywhere in a committed template is what an account-id leak ' +
        'looks like, and this repository is public). Required, with no default: ASH ' +
        'publishes no operator image to any public registry, so there is nothing this ' +
        'template could point at on your behalf. Build it yourself first; see ' +
        'docs/content/docs/building-your-own-image.md. IF THAT REGISTRY IS PRIVATE -- ' +
        'private ECR is the likely case -- the cluster needs a pull path that neither ' +
        'this stack nor the operator creates: either the node role carries ECR pull ' +
        'permission, or an imagePullSecret is attached to the ServiceAccounts. The ' +
        'kubelet pulls the image before any pod identity exists, so the Pod Identity ' +
        'association in this stack does NOT help with image pull.',
    });

    const namespace = new CfnParameter(this, 'OperatorNamespace', {
      type: 'String',
      default: DEFAULT_OPERATOR_NAMESPACE,
      minLength: 1,
      // 63 is the DNS-1123 label limit, which is what a namespace name is. The pattern
      // below constrains the alphabet and not the length, so without this a 300-character
      // namespace passes the console and fails at the API server with a 422 -- after the
      // stack has already created the access entry and the roles. It also bounds
      // `physical_id`, which the applier builds as cluster + "/" + namespace and
      // `respond()` puts in a response CloudFormation caps at 4,096 bytes.
      maxLength: 63,
      allowedPattern: '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$',
      description:
        'Namespace to create and install the operator into. It is created if absent, and it ' +
        'is ALWAYS left in place when the stack is deleted -- deleting a namespace ' +
        'cascade-deletes everything in it, so this stack never deletes one. The operator, ' +
        'its RBAC and its CRD are removed on delete; an empty namespace may remain.',
    });

    /**
     * The customer-managed key parameter every stack in this app carries. It
     * encrypts this stack's one log group.
     */
    const customerKey = new AshCustomerKey(this);

    /**
     * VPC configuration for the applier, needed only by a cluster whose API
     * endpoint is private-only.
     *
     * `VpcSubnetIds` was RESERVED in `ash-config.ts` -- the name was fixed before
     * anything consumed it, precisely so the eventual consumer and the checkov
     * suppression could not disagree about what it would be called. This stack is
     * that consumer, so the name goes live here. It is declared locally rather
     * than through the `vpcSubnetIds` factory because that factory's description
     * talks about the CodeCommit gate's scan function and would be wrong on this
     * template.
     */
    const subnetIds = new CfnParameter(this, 'VpcSubnetIds', {
      type: 'CommaDelimitedList',
      default: '',
      description:
        'Private subnet ids, comma separated, to attach the installer function to. Required ' +
        'ONLY if the cluster API endpoint is private-only; leave empty for a public or ' +
        'mixed endpoint. A VPC-attached function needs egress to THREE services, not two: ' +
        'EKS, STS and S3. Use a NAT gateway, or interface endpoints for EKS and STS plus a ' +
        'com.amazonaws.<region>.s3 endpoint. S3 is required because CloudFormation\'s ' +
        'response URL is a presigned S3 URL: without it the manifests apply successfully ' +
        'and the stack then hangs in CREATE_IN_PROGRESS until it times out, because nothing ' +
        'can report the result.',
    });

    const securityGroupIds = new CfnParameter(this, 'VpcSecurityGroupIds', {
      type: 'CommaDelimitedList',
      default: '',
      description:
        'Security group ids for the installer function, comma separated. Required whenever ' +
        'VpcSubnetIds is set. The group must be allowed to reach the cluster security ' +
        "group's 443 ingress.",
    });

    /**
     * A CommaDelimitedList with an empty default resolves to a one-element list
     * holding the empty string, so `Fn::Select(0, ...)` against `''` is how "the
     * adopter supplied nothing" is detected. Same shape `ash-config.ts` documents
     * for the reserved parameter.
     */
    const hasVpc = new CfnCondition(this, 'HasVpcConfig', {
      expression: Fn.conditionNot(
        Fn.conditionEquals(Fn.select(0, subnetIds.valueAsList), ''),
      ),
    });

    // -----------------------------------------------------------------------
    // The installer function and the identity it uses.
    // -----------------------------------------------------------------------

    const logGroup = new logs.LogGroup(this, 'InstallerLogs', {
      ...diagnosticLogGroupProps(customerKey),
    });

    const installerRole = new iam.Role(this, 'InstallerRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description:
        'Applies the ASH operator manifests to the named EKS cluster. Holds cluster-admin ' +
        'IN THAT CLUSTER through the access entry in this stack, and nothing else.',
    });

    /**
     * `eks:DescribeCluster` on the ONE named cluster, not on `*`. The applier
     * needs the endpoint and the CA certificate and nothing more from the AWS
     * side; the Kubernetes permissions come from the access entry.
     */
    installerRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['eks:DescribeCluster'],
        resources: [
          Stack.of(this).formatArn({
            service: 'eks',
            resource: 'cluster',
            resourceName: clusterName.valueAsString,
          }),
        ],
      }),
    );

    /**
     * `eks:DescribeAddon`, so the installer can report whether the Pod Identity
     * agent is present and the stack can surface that as an output.
     *
     * Scoped to add-ons of the named cluster. The trailing wildcards are the add-on
     * name and the id EKS assigns it, neither of which is knowable here — and the
     * probe asks about one specific add-on name regardless.
     *
     * The applier treats ANY failure of this call as "UNKNOWN" rather than an error,
     * so if this grant is ever wrong the consequence is a less useful output, not a
     * failed install.
     */
    installerRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['eks:DescribeAddon'],
        resources: [
          Stack.of(this).formatArn({
            service: 'eks',
            resource: 'addon',
            resourceName: `${clusterName.valueAsString}/*/*`,
          }),
        ],
      }),
    );

    installerRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [logGroup.logGroupArn, `${logGroup.logGroupArn}:log-stream:*`],
      }),
    );

    /**
     * Attaching a function to a VPC needs these three EC2 actions, and they only
     * accept `*` -- the network interface does not exist when the policy is
     * evaluated, so there is no ARN to name. Granted unconditionally rather than
     * behind `HasVpcConfig`, because a conditional IAM policy resource whose
     * condition is false leaves a role that cannot attach itself to the VPC an
     * adopter just configured, and the failure reads as an unrelated Lambda
     * error. The cost of the wider grant is bounded: this role can create and
     * delete ENIs, and it cannot read or write anything else.
     */
    installerRole.addToPolicy(
      new iam.PolicyStatement({
        actions: [
          'ec2:CreateNetworkInterface',
          'ec2:DescribeNetworkInterfaces',
          'ec2:DeleteNetworkInterface',
        ],
        resources: ['*'],
      }),
    );

    const installer = new lambda.Function(this, 'Installer', {
      // Matches ash-image-build.ts. cdk-nag's AwsSolutions-L1 fails any runtime it
      // does not consider current, so this tracks that file rather than pinning
      // independently and drifting into a finding.
      runtime: lambda.Runtime.PYTHON_3_14,
      handler: 'index.handler',
      code: lambda.Code.fromInline(ASH_OPERATOR_APPLIER),
      role: installerRole,
      // Ten documents, each one HTTPS round trip plus bounded retries. Well
      // inside Lambda's ceiling, unlike the image build in ash-image-build.ts --
      // which is why this one answers CloudFormation itself.
      timeout: Duration.minutes(10),
      memorySize: 512,
      logGroup,
      // NO environment variables, deliberately. The group, version, CRD names and
      // RBAC rules used to arrive here as env vars while the rules themselves lived
      // in the Python; that split meant two sources of truth for one contract, and
      // the CRD name is built from the group AND the plural, so a disagreement
      // between them produced a name mismatch the API server reports as a schema
      // error. Everything is now interpolated into the applier from the constants
      // at the top of this file, which is also what lets the test set-compare the
      // RBAC against the operator's own rbac.yaml.
    });

    /**
     * VPC configuration applied through an L1 override rather than the L2 `vpc`
     * prop, because the L2 needs an `IVpc` object and resolving one from a
     * parameter would mean a context lookup -- which `bin/ash.ts` forbids by
     * synthesizing with `--no-lookups`. The whole property is
     * `Fn::If(HasVpcConfig, {...}, AWS::NoValue)`, so an adopter who supplies
     * nothing gets a template with no `VpcConfig` at all.
     */
    const installerL1 = installer.node.defaultChild as lambda.CfnFunction;
    installerL1.addPropertyOverride('VpcConfig', {
      'Fn::If': [
        hasVpc.logicalId,
        {
          SubnetIds: subnetIds.valueAsList,
          SecurityGroupIds: securityGroupIds.valueAsList,
        },
        { Ref: 'AWS::NoValue' },
      ],
    });

    // -----------------------------------------------------------------------
    // Authorization: the access entry that lets the installer into the cluster.
    // -----------------------------------------------------------------------

    /**
     * `AmazonEKSClusterAdminPolicy`, and the header explains at length why a
     * narrower one cannot work: creating a CustomResourceDefinition and a
     * ClusterRole is cluster-admin-level work by definition.
     *
     * The partition comes from `Aws.PARTITION` rather than the literal `aws` the
     * API returns, so the template is not silently commercial-only.
     */
    const clusterAdminPolicyArn = `arn:${Aws.PARTITION}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy`;

    const entry = new eks.CfnAccessEntry(this, 'InstallerAccess', {
      clusterName: clusterName.valueAsString,
      principalArn: installerRole.roleArn,
      type: 'STANDARD',
      accessPolicies: [
        {
          policyArn: clusterAdminPolicyArn,
          accessScope: { type: 'cluster' },
        },
      ],
    });

    // -----------------------------------------------------------------------
    // The operator's own AWS identity: wired, and empty.
    // -----------------------------------------------------------------------

    const operatorRole = new iam.Role(this, 'OperatorRole', {
      assumedBy: new iam.ServicePrincipal('pods.eks.amazonaws.com'),
      description:
        'The ASH operator\'s AWS identity, assumed through EKS Pod Identity. Ships with NO ' +
        'policies attached: the operator does not exist in this repository yet, so any ' +
        'permission set here would be a guess. Attach what your scans actually need.',
    });

    /**
     * Pod Identity's trust policy needs `sts:TagSession` alongside
     * `sts:AssumeRole`, which the L2 `ServicePrincipal` does not add on its own.
     * Without it the association exists and every credential fetch fails.
     */
    operatorRole.assumeRolePolicy?.addStatements(
      new iam.PolicyStatement({
        actions: ['sts:TagSession'],
        principals: [new iam.ServicePrincipal('pods.eks.amazonaws.com')],
      }),
    );

    const association = new eks.CfnPodIdentityAssociation(this, 'OperatorPodIdentity', {
      clusterName: clusterName.valueAsString,
      namespace: namespace.valueAsString,
      // The OPERATOR's account, not the scan account. The operator process runs
      // under this one; whether the scan Jobs also need an AWS identity is an open
      // question, so no second association is created on a guess.
      serviceAccount: OPERATOR_SERVICE_ACCOUNT,
      roleArn: operatorRole.roleArn,
    });

    // -----------------------------------------------------------------------
    // The custom resource that does the work.
    // -----------------------------------------------------------------------

    const install = new CustomResource(this, 'OperatorInstall', {
      serviceToken: installer.functionArn,
      /**
       * The outer bound, and the only one that covers a function killed before it can
       * answer. The applier's own in-Lambda deadline check handles the case where it is
       * still running; this handles the cases where it never got to run or died without
       * warning — a throttle at the concurrency limit, an OOM, an unhandled signal.
       *
       * Without it CloudFormation's own wait is the bound, which on this resource is an
       * hour of CREATE_IN_PROGRESS with nothing in the log. With it the stack fails with
       * a stated timeout, which is what makes the S3-egress precondition in the README
       * recoverable rather than a wedge: an adopter who forgot the S3 route gets a
       * failure in twelve minutes instead of a stack they have to cancel.
       *
       * Longer than the function's own 10-minute timeout so a Lambda that is merely slow
       * reports its own verdict first, and this only fires when nothing answers at all.
       */
      serviceTimeout: Duration.minutes(12),
      properties: {
        ClusterName: clusterName.valueAsString,
        Namespace: namespace.valueAsString,
        // No ServiceAccount property: the applier owns both account names, which are
        // interpolated into it. Passing one here too would be a second source of
        // truth for a value that must match the manifests exactly.
        OperatorImage: operatorImage.valueAsString,
      },
    });

    /**
     * Without this the access entry and the apply race, and the apply loses: the
     * function authenticates fine and every request comes back 403 because the
     * entry does not exist yet. CloudFormation has no reason to order them
     * otherwise -- nothing in the custom resource references the entry.
     */
    install.node.addDependency(entry);
    // The association only needs the namespace to exist eventually, but ordering
    // it after the install keeps a deleted stack from removing the namespace
    // while the association still points into it.
    association.node.addDependency(install);

    // -----------------------------------------------------------------------
    // cdk-nag.
    // -----------------------------------------------------------------------

    // One entry, covering both of this role's wildcards by name. Deliberately not
    // `suppressLambdaLogWildcard`: its reason claims the log-stream suffix is the
    // only wildcard, which is false here. See the helper's own header.
    //
    // No `suppressUnevaluableRules` call: measured against the synthesized report,
    // no rule throws on this stack, so an entry for `CdkNagValidationFailure` would
    // be a suppression that excuses nothing and still ships in the template.
    suppressEksInstallerRoleWildcards(installerRole);

    new CfnOutput(this, 'OperatorNamespaceOut', {
      value: namespace.valueAsString,
      description: 'Namespace the operator was installed into.',
    });

    new CfnOutput(this, 'OperatorRoleArn', {
      value: operatorRole.roleArn,
      description:
        'The operator\'s AWS role, assumed through Pod Identity. Attach policies to this ' +
        'role to give scans AWS access; it has none by default.',
    });

    /**
     * Whether the Pod Identity agent is actually installed, as an OUTPUT rather than
     * a remark in a source comment.
     *
     * The agent's absence and the deliberately-empty operator role produce the SAME
     * symptom -- the operator gets no AWS credentials -- so a reader who hits that
     * symptom cannot tell which cause they have. Nothing else in the stack would
     * tell them: the association is created either way and CloudFormation reports
     * success either way. This turns a silent precondition into a value visible on
     * the stack's Outputs tab.
     *
     * `ABSENT` means the add-on is not installed and Pod Identity will not work.
     * `UNKNOWN` means the probe could not answer — most likely the IAM grant above,
     * and deliberately not fatal. Anything else is the add-on's own status, `ACTIVE`
     * being the one that means this works.
     */
    new CfnOutput(this, 'PodIdentityAgentStatus', {
      value: install.getAttString('PodIdentityAgent'),
      description:
        'Status of the eks-pod-identity-agent add-on on the cluster, read at install time. ' +
        'ABSENT means the operator will receive no AWS credentials no matter what is ' +
        'attached to OperatorRoleArn -- install the add-on to fix that. UNKNOWN means the ' +
        'probe could not answer and says nothing either way.',
    });
  }
}
