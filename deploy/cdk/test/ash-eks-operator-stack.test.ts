/**
 * The EKS operator installer, asserted on the things that fail silently.
 *
 * WHAT THIS FILE IS FOR
 * ---------------------
 * Most of this stack cannot be tested without a cluster. What CAN be tested
 * offline is the set of properties whose absence produces a stack that deploys
 * "successfully" and does nothing, or a stack that asks an adopter a question with
 * no safe answer. Those are the ones here.
 *
 * Three of them are ordering or wiring properties that no synth error would ever
 * report:
 *
 *   1. The custom resource must depend on the access entry. Without it the two
 *      race, and the losing order is the common one: the function authenticates
 *      fine and every apply comes back 403. CloudFormation has no reason to order
 *      them on its own because nothing in the custom resource references the entry.
 *   2. The applier must reach the cluster with boto3 and the standard library only.
 *      A kubectl or `kubernetes` import would compile, synthesize and then fail at
 *      runtime with ImportError -- and would silently turn the template into an
 *      asset-backed one, which is the failure `ashSynthesizer` exists to prevent.
 *   3. The RBAC it installs must stay least-privilege. A `*` verb or a secrets rule
 *      is a security regression in a security tool, and nothing else in this repo
 *      reads the manifests.
 */

import { spawnSync } from 'child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { basename, join } from 'path';

import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import {
  AshCrd,
  ASH_OPERATOR_API_GROUP,
  ASH_OPERATOR_API_VERSION,
  ASH_OPERATOR_APPLIER,
  ASH_OPERATOR_CLUSTER_RULES,
  ASH_OPERATOR_CRDS,
  ASH_OPERATOR_NAMESPACED_RULES,
  AshEksOperatorStack,
  DEFAULT_OPERATOR_NAMESPACE,
  OPERATOR_SERVICE_ACCOUNT,
  pythonLiteral,
  RbacRule,
  SCAN_SERVICE_ACCOUNT,
} from '../lib/ash-eks-operator-stack';

function synth(): Template {
  return Template.fromStack(new AshEksOperatorStack(new App({ analyticsReporting: false }), 'S'));
}

const TEMPLATE = synth();
const JSON_TEMPLATE = TEMPLATE.toJSON();

describe('the parameters an adopter cannot be allowed to get wrong', () => {
  test.each(['EksClusterName', 'OperatorImageUri'])('%s is required with no default', (name) => {
    const parameter = JSON_TEMPLATE.Parameters?.[name];
    expect(parameter).toBeDefined();
    // A Default of any kind -- including an empty string -- makes CloudFormation
    // accept a blank value in the console, and the failure then surfaces as an
    // ImagePullBackOff or a ResourceNotFound long after the stack reports CREATE
    // COMPLETE. No Default plus MinLength 1 is what makes the console refuse.
    expect(parameter).not.toHaveProperty('Default');
    expect(parameter.MinLength).toBe(1);
  });

  test('the image pattern rejects the plausible wrong answers, not just empty', () => {
    const pattern = new RegExp(JSON_TEMPLATE.Parameters.OperatorImageUri.AllowedPattern);
    // Accepted: a registry host with an explicit tag, and with a digest.
    expect(pattern.test('example.dkr.ecr.us-east-1.amazonaws.com/ash-operator:v1')).toBe(true);
    expect(
      pattern.test(
        'registry.example.com/team/ash-operator@sha256:' + 'a'.repeat(64),
      ),
    ).toBe(true);
    expect(pattern.test('localhost:5000/ash-operator:dev')).toBe(true);
    // Rejected, and each of these is a real thing someone types. A bare name would
    // send the kubelet to Docker Hub; an untagged repository resolves to :latest,
    // which ASH does not publish either.
    expect(pattern.test('ash-operator')).toBe(false);
    expect(pattern.test('ash-operator:v1')).toBe(false);
    expect(pattern.test('example.dkr.ecr.us-east-1.amazonaws.com/ash-operator')).toBe(false);
    expect(pattern.test('')).toBe(false);
  });

  test('every declared parameter is read somewhere', () => {
    // A console launch shows every parameter. One nothing references is a question
    // with no consequence.
    const body = JSON.stringify({
      Resources: JSON_TEMPLATE.Resources,
      Conditions: JSON_TEMPLATE.Conditions,
      Outputs: JSON_TEMPLATE.Outputs,
    });
    for (const name of Object.keys(JSON_TEMPLATE.Parameters ?? {})) {
      expect(body).toContain(`"Ref":"${name}"`);
    }
  });
});

describe('authorization is wired, and wired in the right order', () => {
  test('exactly one access entry, for the installer role, at cluster scope', () => {
    const entries = TEMPLATE.findResources('AWS::EKS::AccessEntry');
    expect(Object.keys(entries)).toHaveLength(1);
    const properties = Object.values<any>(entries)[0].Properties;
    expect(properties.Type).toBe('STANDARD');
    expect(properties.AccessPolicies).toHaveLength(1);
    expect(properties.AccessPolicies[0].AccessScope).toEqual({ Type: 'cluster' });
    // Cluster-admin, deliberately, because installing a CRD and a ClusterRole is
    // cluster-admin-level work and the narrower built-in policies cannot. Asserted
    // so that narrowing it becomes a deliberate change with a failing test rather
    // than something that quietly stops working at deploy time.
    expect(JSON.stringify(properties.AccessPolicies[0].PolicyArn)).toContain(
      'cluster-access-policy/AmazonEKSClusterAdminPolicy',
    );
    // The principal is the installer's own role, not a parameter an adopter could
    // point at something else.
    expect(JSON.stringify(properties.PrincipalArn)).toContain('InstallerRole');
  });

  test('the install depends on the access entry', () => {
    // THE ORDERING TEST. Nothing in the custom resource references the entry, so
    // CloudFormation would happily create them in parallel and the apply would 403.
    const [logicalId, entry] = Object.entries<any>(
      TEMPLATE.findResources('AWS::EKS::AccessEntry'),
    )[0];
    const install = Object.entries<any>(JSON_TEMPLATE.Resources).find(
      ([, r]) => r.Type === 'AWS::CloudFormation::CustomResource',
    );
    expect(install).toBeDefined();
    expect(install![1].DependsOn).toContain(logicalId);
    // Non-vacuity: a DependsOn naming something that is not the entry would pass a
    // bare toContain against a stale id.
    expect(entry.Type).toBe('AWS::EKS::AccessEntry');
  });

  test('the operator role is assumable by pod identity and carries no policies', () => {
    const roles = Object.entries<any>(TEMPLATE.findResources('AWS::IAM::Role')).filter(([id]) =>
      id.startsWith('OperatorRole'),
    );
    expect(roles).toHaveLength(1);
    const role = roles[0][1].Properties;
    const document = JSON.stringify(role.AssumeRolePolicyDocument);
    expect(document).toContain('pods.eks.amazonaws.com');
    // Pod Identity needs BOTH actions. With only sts:AssumeRole the association
    // exists and every credential fetch fails, which looks like a cluster problem.
    expect(document).toContain('sts:AssumeRole');
    expect(document).toContain('sts:TagSession');
    // Ships empty on purpose: the default plugin set makes no AWS calls and an opted-in
    // plugin's needs depend on each AshScan, so any permission set here would be
    // invented. See the stack header.
    expect(role.ManagedPolicyArns ?? []).toEqual([]);
    expect(role.Policies ?? []).toEqual([]);
  });

  test('EVERY wildcard in the policy is accounted for in the suppression reason', () => {
    /*
     * The gap this closes, and it is the same shape as the vacuity hole in the RBAC
     * comparison: the existing assertions check named-claim-to-evidence (does the reason
     * mention ec2, is ec2 granted) and named-action-to-grant. None of them checked the
     * other direction — that no wildcard exists which the reason fails to mention.
     *
     * That direction is the one that rots. The reason said "Two wildcards" for a revision
     * while the policy had three, because the change that added `eks:DescribeAddon`
     * widened the grant and left the prose behind. cdk-nag raises one IAM5 finding per
     * wildcard resource, so the entry was suppressing three findings and explaining two.
     *
     * Keyed on the ACTIONS attached to each wildcard resource rather than on a count,
     * because a count in a test is the same brittle artifact as a count in prose.
     */
    const policies = Object.entries<any>(TEMPLATE.findResources('AWS::IAM::Policy')).filter(
      ([id]) => id.startsWith('InstallerRoleDefaultPolicy'),
    );
    expect(policies).toHaveLength(1);
    const [logicalId, policy] = policies[0];
    const statements = policy.Properties.PolicyDocument.Statement;

    // A resource is wildcarded if any of its ARN forms is '*' or ends in one.
    const wildcarded = statements.filter((s: any) =>
      [s.Resource].flat().some((r: any) => JSON.stringify(r).includes('*')),
    );
    expect(wildcarded.length).toBeGreaterThan(0);

    const reason = policy.Metadata.cdk_nag.rules_to_suppress.find(
      (e: any) => e.id === 'AwsSolutions-IAM5',
    )?.reason;
    expect(reason).toBeDefined();

    /*
     * Every action on a wildcard resource must appear in the reason -- matched as a WHOLE
     * TOKEN, not as a substring.
     *
     * `reason.includes(action)` was the first version and the hole ran in the unsafe
     * direction: IAM action names nest by prefix, and the PREFIX is the broader grant. A
     * policy that later granted `eks:Describe` -- every Describe call, not one -- would be
     * satisfied by a reason mentioning `eks:DescribeAddon`, so the check would pass on
     * precisely the widening it exists to catch.
     *
     * Tokenizing both sides and comparing membership removes the subtlety rather than
     * encoding it in a regex: the reason's action-shaped tokens are extracted and each
     * granted action must be one of them exactly.
     */
    const mentioned = new Set(reason.match(/\b[a-z0-9]+:[A-Za-z0-9*]+/g) ?? []);
    expect(mentioned.size).toBeGreaterThan(0);
    const unexplained = wildcarded
      .flatMap((s: any) => [s.Action].flat())
      .filter((action: string) => !mentioned.has(action));
    expect({ policy: logicalId, unexplained }).toEqual({ policy: logicalId, unexplained: [] });

    // The tokenizer is the load-bearing part now, so it carries its own control: a reason
    // naming only the narrower action must NOT satisfy a broader one.
    const narrowerOnly = new Set('eks:DescribeAddon'.match(/\b[a-z0-9]+:[A-Za-z0-9*]+/g) ?? []);
    expect(narrowerOnly.has('eks:DescribeAddon')).toBe(true);
    expect(narrowerOnly.has('eks:Describe')).toBe(false);

    // And the converse control: the reason must not claim a wildcard action the policy
    // does not actually grant on a wildcard, which is how a reason drifts into describing
    // a policy that was narrowed.
    const wildcardActions = new Set(wildcarded.flatMap((s: any) => [s.Action].flat()));
    for (const claimed of ['ec2:CreateNetworkInterface', 'eks:DescribeAddon']) {
      expect(wildcardActions.has(claimed)).toBe(true);
    }
    // eks:DescribeCluster is scoped and must NOT be among them.
    expect(wildcardActions.has('eks:DescribeCluster')).toBe(false);
  });

  test('the installer role reads one cluster and holds no other AWS reach', () => {
    const policies = Object.entries<any>(TEMPLATE.findResources('AWS::IAM::Policy')).filter(
      ([id]) => id.startsWith('InstallerRoleDefaultPolicy'),
    );
    expect(policies).toHaveLength(1);
    const statements = policies[0][1].Properties.PolicyDocument.Statement;
    const actions = statements.flatMap((s: any) => [s.Action].flat());
    expect(actions).toContain('eks:DescribeCluster');
    // The wildcards this role is allowed, and nothing else. Anything new here has to
    // be added deliberately and explained in suppressEksInstallerRoleWildcards,
    // whose reason is serialized into the committed template.
    const wildcardActions = statements
      .filter((s: any) => [s.Resource].flat().some((r: any) => r === '*'))
      .flatMap((s: any) => [s.Action].flat())
      .sort();
    // Exactly the list the Lambda developer guide requires for a VPC-attached function.
    // Written out rather than read from LAMBDA_VPC_ENI_ACTIONS, so a change to that
    // constant shows up here as a failing test.
    expect(wildcardActions).toEqual([
      'ec2:AssignPrivateIpAddresses',
      'ec2:CreateNetworkInterface',
      'ec2:DeleteNetworkInterface',
      'ec2:DescribeNetworkInterfaces',
      'ec2:DescribeSubnets',
      'ec2:UnassignPrivateIpAddresses',
    ]);
    // eks:DescribeCluster must NOT be one of them: it is scoped to the named cluster.
    expect(wildcardActions).not.toContain('eks:DescribeCluster');
  });
});

describe('the EC2 grant is usable by the Lambda service only', () => {
  /*
   * The ENI actions are granted on "*" because the Lambda service needs them to attach
   * the function to a VPC. Without a Deny, the function's own code could call them too.
   * The Lambda developer guide's fix is a Deny keyed on lambda:SourceFunctionArn, which
   * only calls from function code carry.
   */
  const denies = Object.entries<any>(TEMPLATE.findResources('AWS::IAM::Policy')).filter(([id]) =>
    id.startsWith('InstallerEc2CodeDeny'),
  );

  test('one deny policy, attached to the installer role', () => {
    expect(denies).toHaveLength(1);
    expect(JSON.stringify(denies[0][1].Properties.Roles)).toContain('InstallerRole');
  });

  test('it denies every EC2 action the role allows on a wildcard, keyed on this function', () => {
    const allowed = Object.entries<any>(TEMPLATE.findResources('AWS::IAM::Policy'))
      .filter(([id]) => id.startsWith('InstallerRoleDefaultPolicy'))
      .flatMap(([, p]) => p.Properties.PolicyDocument.Statement)
      .filter((s: any) => s.Effect === 'Allow' && s.Resource === '*')
      .flatMap((s: any) => [s.Action].flat())
      .filter((a: string) => a.startsWith('ec2:'));
    // Non-vacuity: an empty allow list would make the subset check below pass trivially.
    expect(allowed.length).toBeGreaterThan(0);

    const [statement] = denies[0][1].Properties.PolicyDocument.Statement;
    expect(statement.Effect).toBe('Deny');
    expect(statement.Resource).toBe('*');
    const denied = new Set([statement.Action].flat());
    expect(allowed.filter((a: string) => !denied.has(a))).toEqual([]);

    // The condition must name THIS function. A Deny with no condition would also block
    // the Lambda service and break the VPC attachment; one naming another function
    // would block nothing.
    const fn = Object.keys(TEMPLATE.findResources('AWS::Lambda::Function'))[0];
    expect(statement.Condition).toEqual({
      ArnEquals: { 'lambda:SourceFunctionArn': { 'Fn::GetAtt': [fn, 'Arn'] } },
    });
  });

  test('the function does not depend on the deny, so there is no cycle', () => {
    const fn = Object.values<any>(TEMPLATE.findResources('AWS::Lambda::Function'))[0];
    expect([fn.DependsOn ?? []].flat().join(',')).not.toContain('InstallerEc2CodeDeny');
  });

  test('the install waits for the deny, so the first apply already runs under it', () => {
    // The deny is created after the function. Without this ordering CloudFormation may
    // invoke the installer before the deny is attached.
    const install = Object.values<any>(JSON_TEMPLATE.Resources).find(
      (r) => r.Type === 'AWS::CloudFormation::CustomResource',
    );
    expect(denies).toHaveLength(1);
    expect([install.DependsOn ?? []].flat()).toContain(denies[0][0]);
  });
});

describe('the installer function as a custom-resource responder', () => {
  test('it reserves exactly one concurrent execution', () => {
    // One responder for one resource; a second slot would only let two applies
    // race against the same cluster.
    const fn = Object.values<any>(TEMPLATE.findResources('AWS::Lambda::Function'))[0];
    expect(fn.Properties.ReservedConcurrentExecutions).toBe(1);
  });

  test('ServiceTimeout is an integer, longer than the function timeout', () => {
    // CDK renders it as a string, which CloudFormation coerces and its validator flags.
    const install = Object.values<any>(JSON_TEMPLATE.Resources).find(
      (r) => r.Type === 'AWS::CloudFormation::CustomResource',
    );
    const fn = Object.values<any>(TEMPLATE.findResources('AWS::Lambda::Function'))[0];
    expect(typeof install.Properties.ServiceTimeout).toBe('number');
    expect(install.Properties.ServiceTimeout).toBeGreaterThan(fn.Properties.Timeout);
  });
});

describe('the applier stays self-contained', () => {
  test('it imports nothing outside boto3 and the standard library', () => {
    // A kubectl layer or the `kubernetes` package would make this template
    // asset-backed, which reintroduces the cdk bootstrap dependency
    // ashSynthesizer exists to remove.
    expect(ASH_OPERATOR_APPLIER).toContain('import boto3');
    expect(ASH_OPERATOR_APPLIER).toContain('from botocore.signers import RequestSigner');
    /*
     * Keyed on IMPORT AND INVOCATION SYNTAX, not on the bare words. A plain
     * `not.toContain('kubectl')` failed the moment a docstring explained that
     * `kubectl get ashscans` loses the Phase column — the prose describing why this
     * design is correct tripped the test defending it. Third time a substring check over
     * this string has been broken by documenting the thing it checks, so the assertion is
     * now about the only forms that could actually create a dependency: an import, or a
     * subprocess call.
     */
    for (const forbidden of [
      'import kubernetes',
      'import yaml',
      'import subprocess',
      'subprocess.',
      'os.system',
    ]) {
      expect(ASH_OPERATOR_APPLIER).not.toContain(forbidden);
    }
  });

  test('the template carries no asset reference and needs no bootstrap', () => {
    const rendered = JSON.stringify(JSON_TEMPLATE);
    expect(rendered).not.toContain('cdk-hnb659fds');
    expect(Object.keys(JSON_TEMPLATE.Parameters ?? {})).not.toContain('BootstrapVersion');
    // The code is inline, which is what keeps it asset-free.
    const functions = Object.values<any>(TEMPLATE.findResources('AWS::Lambda::Function'));
    expect(functions).toHaveLength(1);
    expect(functions[0].Properties.Code).toHaveProperty('ZipFile');
    expect(functions[0].Properties.Code).not.toHaveProperty('S3Bucket');
  });

  test('it invokes no aws CLI', () => {
    // The same rule ash-no-aws-cli.test.ts enforces for buildspecs. This function
    // runs on a Lambda runtime, which ships boto3 and no CLI.
    const offenders = ASH_OPERATOR_APPLIER.split('\n').filter((line) =>
      /(?<![\w.-])aws\s+[a-z][a-z0-9-]*/.test(line),
    );
    expect(offenders).toEqual([]);
  });

  test('the bearer token is built from the client endpoint, not an f-string host', () => {
    // A hardcoded sts.<region>.amazonaws.com would be wrong outside the commercial
    // partition, and the symptom is an auth failure rather than anything naming the
    // endpoint.
    expect(ASH_OPERATOR_APPLIER).toContain('client.meta.endpoint_url');
    expect(ASH_OPERATOR_APPLIER).toContain('k8s-aws-v1.');
    expect(ASH_OPERATOR_APPLIER).toContain('x-k8s-aws-id');
  });

  test('a failure is reported to CloudFormation rather than left to time out', () => {
    // Without this a raised exception leaves the stack in CREATE_IN_PROGRESS until
    // its internal timeout, with nothing saying why. The handler sets status/reason
    // and falls through to a single respond call, so the assertion is on the
    // FAILED verdict being reachable rather than on a literal respond(..., "FAILED")
    // call site -- there deliberately is not one any more.
    expect(ASH_OPERATOR_APPLIER).toContain('status = "FAILED"');
    expect(ASH_OPERATOR_APPLIER).toContain('reason = repr(err)');
    expect(ASH_OPERATOR_APPLIER).toContain('except Exception as err');
  });

  test('a delete tolerates a 404 so a half-installed stack is still deletable', () => {
    expect(ASH_OPERATOR_APPLIER).toContain('tolerate_404=True');
  });
});

/*
 * The three regressions below were real defects found in review, and each one
 * produced a failure that reported success or reported nothing. They are pinned
 * here because none of them is visible in a synthesized template — all three live
 * in a Python string that nothing else in this repository executes or inspects.
 */
describe('REGRESSION: stack deletion must not delete anything cluster-scoped', () => {
  /*
   * This started as a namespace-only guard. It was widened after review pointed out
   * that the same argument applies one scope up and the original fix stopped short:
   * the loop still deleted both CustomResourceDefinitions and the
   * ClusterRole/ClusterRoleBinding.
   *
   * Deleting `ashscans.ash.awslabs.github.io` cascade-deletes every AshScan in EVERY
   * namespace of the cluster. And because the install uses server-side apply with
   * force=true, a second installation silently adopts the same cluster-scoped
   * objects, so deleting either stack strips the other. In both cases
   * CloudFormation reports DELETE_COMPLETE.
   *
   * The rule is now scope-based rather than a list of excepted paths, which is what
   * makes it hold for a document added later: a new object is covered the moment it
   * declares its scope, instead of being deleted because nobody added another
   * exception.
   */
  test('the delete loop skips on scope, not on a path allowlist', () => {
    expect(ASH_OPERATOR_APPLIER).toContain('for path, _, scope in reversed(documents(');
    expect(ASH_OPERATOR_APPLIER).toContain('if scope == CLUSTER:');
    // The guard must be a skip, not a log-and-proceed.
    const guard = ASH_OPERATOR_APPLIER.slice(
      ASH_OPERATOR_APPLIER.indexOf('if scope == CLUSTER:'),
    );
    expect(guard.slice(0, guard.indexOf('call('))).toContain('continue');
    // The superseded path-matching form must be gone, or both could coexist with
    // only the weaker one reached.
    expect(ASH_OPERATOR_APPLIER).not.toContain('if path == namespace_path:');
  });

  test('the only DELETE call in the applier is the guarded one', () => {
    // A second, unguarded delete site would reintroduce the defect while leaving
    // the guard above in place and passing.
    const deletes = ASH_OPERATOR_APPLIER.match(/"DELETE"/g) ?? [];
    expect(deletes).toHaveLength(1);
  });

  test('both scope constants exist and documents() tags with them', () => {
    /*
     * Deliberately NOT a count of CLUSTER occurrences in the Python text. I wrote
     * that first and it was wrong -- the tag appears in two different syntactic
     * positions depending on how the tuple wraps, so the regex found 4 of 5 and the
     * test failed on formatting rather than on behaviour. A text count of a Python
     * literal is the wrong instrument for a question about what the function
     * RETURNS.
     *
     * The set membership -- exactly which five documents are cluster-scoped, and that a
     * delete issues six DELETEs touching none of them -- is asserted by
     * `tests/unit/deploy/test_eks_operator_applier.py`, which reassembles the applier out
     * of the committed template, EXECUTES it, and simulates the delete loop against what
     * `documents()` actually returns. That check cannot be satisfied by reformatting.
     *
     * It is a committed pytest rather than a scratch script deliberately. The same checks
     * previously lived in an ephemeral job directory, which made this comment cite a
     * verification artifact no future reader could find or re-run -- an alibi for the most
     * destructive-if-wrong path in the stack, even though the check was real when written.
     */
    expect(ASH_OPERATOR_APPLIER).toContain('CLUSTER = "cluster"');
    expect(ASH_OPERATOR_APPLIER).toContain('NAMESPACED = "namespaced"');
    expect(ASH_OPERATOR_APPLIER).toContain('(path, manifest, scope)');
  });

  test('the uninstall behaviour is documented where an adopter reads it', () => {
    // A stack that deliberately leaves things behind has to say so, or the leftovers
    // read as a bug and someone deletes them by hand without knowing what shares them.
    const readme = readFileSync(join(__dirname, '..', '..', 'README.md'), 'utf8');
    expect(readme).toMatch(/Deleting the stack does not remove everything it created/);
    expect(readme).toMatch(/AshScan` in every namespace/i);
  });

  test('the README warns that VPC network interfaces can outlive a stack delete', () => {
    // CloudFormation deletes the execution role right after the function. The Lambda
    // guide says Lambda needs that role to delete the Hyperplane ENI, so an adopter who
    // set VpcSubnetIds can be left with an ENI to remove by hand.
    const readme = readFileSync(join(__dirname, '..', '..', 'README.md'), 'utf8');
    expect(readme).toMatch(/Hyperplane network interface/);
    expect(readme).toContain('https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html');
  });

  test('the parameter description no longer promises an occupancy check', () => {
    // The original description claimed the namespace was "left in place ... only if
    // something else still occupies it". No such check existed, and none can exist:
    // "empty now" races with anything scheduling into it. A description promising a
    // guard that is not implemented is worse than no description.
    const description = JSON_TEMPLATE.Parameters.OperatorNamespace.Description;
    expect(description).not.toMatch(/only if/i);
    expect(description).not.toMatch(/occupies/i);
    expect(description).toMatch(/ALWAYS left in place/);
  });

  test('the parameter description says what the delete loop keeps, not the opposite', () => {
    // The launch form is what an adopter reads before deleting. It once said the CRD
    // and RBAC "are removed on delete", while the loop above skips every cluster-scoped
    // document. Pinned to the same split deploy/README.md states.
    const description: string = JSON_TEMPLATE.Parameters.OperatorNamespace.Description;
    expect(description).not.toMatch(/(CRD|RBAC|ClusterRole)[^.;]*\bremoved\b/i);
    expect(description).toMatch(/removes the Deployment, NetworkPolicy, ServiceAccounts, Role and RoleBinding/);
    expect(description).toMatch(/the CRDs, ClusterRole and ClusterRoleBinding are kept/);
  });
});

describe('REGRESSION: the bearer token must not expire mid-install', () => {
  test('the token is minted per request, not once per invocation', () => {
    // TOKEN_TTL_SECONDS is 60. One 5xx retry chain is ~31s of backoff plus up to
    // 30s per request, so a token minted before the eight-document loop can expire
    // partway through. The API server then answers 401, which call() classifies as
    // non-retryable, and the install dies having already applied some documents.
    expect(ASH_OPERATOR_APPLIER).toContain('def request(endpoint, ca_file, token_for,');
    expect(ASH_OPERATOR_APPLIER).toContain('"Bearer " + token_for()');
    // The old shape passed a already-minted string down. If `token` comes back as a
    // parameter name, the mint has moved back out of the request.
    expect(ASH_OPERATOR_APPLIER).not.toContain('def request(endpoint, ca_file, token,');
    expect(ASH_OPERATOR_APPLIER).not.toContain('def call(endpoint, ca_file, token,');
  });

  test('the handler passes a callable rather than resolving it once', () => {
    expect(ASH_OPERATOR_APPLIER).toContain('def token_for():');
    expect(ASH_OPERATOR_APPLIER).toContain('return cluster_token(session, cluster_name)');
    // Every call site must hand on the callable.
    const resolvedAtCallSite = ASH_OPERATOR_APPLIER.match(/call\(\s*endpoint,\s*ca_file,\s*token[,)]/g);
    expect(resolvedAtCallSite).toBeNull();
  });
});

describe('REGRESSION: an unanswerable CloudFormation response must not be silent', () => {
  test('respond handles its own failure and names S3 as the cause', () => {
    // The response URL is a presigned S3 URL. A VPC-attached function with
    // interface endpoints for EKS and STS but no route to S3 applies every manifest
    // and then cannot report it, leaving the stack in CREATE_IN_PROGRESS until it
    // times out with no error anywhere. This log line is the only evidence.
    const respond = ASH_OPERATOR_APPLIER.slice(
      ASH_OPERATOR_APPLIER.indexOf('def respond('),
      ASH_OPERATOR_APPLIER.indexOf('def handler('),
    );
    expect(respond).toContain('CANNOT REACH THE CLOUDFORMATION RESPONSE URL');
    expect(respond).toContain('presigned S3 URL');
    expect(respond).toContain('except Exception as err');
  });

  test("respond's ensure_ascii comment matches the call it explains", () => {
    // The comment ships inside the ZipFile. A shortened version read "with
    // ensure_ascii=True each U+FFFD ... escapes to six bytes" above a call passing
    // False, which states the opposite of the code.
    const respond = ASH_OPERATOR_APPLIER.slice(
      ASH_OPERATOR_APPLIER.indexOf('def respond('),
      ASH_OPERATOR_APPLIER.indexOf('def handler('),
    );
    expect(respond).toContain('ensure_ascii=False,');
    expect(respond).not.toMatch(/with ensure_ascii=True each/);
    expect(respond).toMatch(/default ensure_ascii=True\s+#\s+escapes each U\+FFFD to six bytes, so this uses False/);
  });

  test('the properties are read inside the try, so a missing one still responds', () => {
    // These used to be read above the try. A missing property then raised before any
    // responder existed, producing the same indefinite hang as an unreachable
    // response URL and naming nothing.
    const handler = ASH_OPERATOR_APPLIER.slice(ASH_OPERATOR_APPLIER.indexOf('def handler('));
    const tryAt = handler.indexOf('try:');
    const clusterAt = handler.indexOf('cluster_name = props["ClusterName"]');
    expect(tryAt).toBeGreaterThan(-1);
    expect(clusterAt).toBeGreaterThan(tryAt);
  });

  test('there is exactly one respond call, reached on every path', () => {
    // Three call sites and an early return is what let the property read drift
    // outside the try unnoticed.
    const handler = ASH_OPERATOR_APPLIER.slice(ASH_OPERATOR_APPLIER.indexOf('def handler('));
    expect(handler.match(/^\s*respond\(event, status, reason, physical_id, data\)$/m)).not.toBeNull();
    // Matched on `respond(event`, the call form, rather than `respond(`. A comment in the
    // handler now refers to "respond()'s own docstring", and the looser pattern counted
    // that prose as a second call site — the same collision as the kubectl check above.
    expect(handler.match(/respond\(event/g) ?? []).toHaveLength(1);
  });

  test('the physical id is set before anything that can raise', () => {
    // A physical id that differs between a failed CREATE and its rollback makes
    // CloudFormation delete a resource it never created.
    const handler = ASH_OPERATOR_APPLIER.slice(ASH_OPERATOR_APPLIER.indexOf('def handler('));
    expect(handler.indexOf('physical_id = event.get("PhysicalResourceId")')).toBeLessThan(
      handler.indexOf('try:'),
    );
  });

  test('the S3 egress requirement reaches the SHIPPED PARAMETER, not just a comment', () => {
    /*
     * This test used to read the TypeScript header -- a file no adopter ever opens --
     * while its own comment said the precondition list "is what made an adopter
     * following it exactly hit the hang". So it passed while the surface that caused
     * the hang was unchanged. That is the same shape as the defect it was meant to
     * guard: the code was right and the instruction was not.
     *
     * The console shows this description. It is the surface that matters.
     */
    const description = JSON_TEMPLATE.Parameters.VpcSubnetIds.Description;
    expect(description).toMatch(/THREE services, not two/i);
    expect(description).toContain('S3');
    expect(description).toMatch(/com\.amazonaws\.<region>\.s3/);
    // The old wording named two services and stopped there.
    expect(description).not.toMatch(/interface endpoints for both/);
  });
});

/*
 * THE ADOPTER-FACING DOCUMENTATION IS PART OF THE CONTRACT, AND NOTHING WAS
 * CHECKING IT.
 *
 * The round that corrected the CRD kind in the manifests and the RBAC introduced
 * `A \`Scan\` custom resource` into deploy/README.md in the SAME change -- the
 * identifier fix 8 existed to remove, reintroduced in the one surface an adopter
 * actually reads. 533 tests were green because none of them read a README.
 *
 * An adopter following that table writes `kind: Scan`, applies it, and gets
 * `no matches for kind "Scan" in version "ash.awslabs.github.io/v1alpha1"` against a
 * correctly installed operator. The install is right; the instruction is not, and the
 * instruction is what they have.
 *
 * So the kinds are asserted against the READMEs, in both directions: the real ones
 * must appear, and the wrong one must not.
 */
describe('the READMEs name the resource an adopter actually creates', () => {
  const readmes: Record<string, string> = {
    'deploy/README.md': readFileSync(join(__dirname, '..', '..', 'README.md'), 'utf8'),
    'deploy/cdk/README.md': readFileSync(join(__dirname, '..', 'README.md'), 'utf8'),
  };

  test('at least one README names the real kinds', () => {
    const combined = Object.values(readmes).join('\n');
    for (const crd of ASH_OPERATOR_CRDS) {
      expect(combined).toContain(crd.kind);
    }
  });

  test.each(Object.keys(readmes))('%s does not name a kind the operator does not serve', (name) => {
    /*
     * Matched as a whole word inside backticks, which is how a README names a kind.
     * A bare /Scan/ would fire on "AshScan" and on the word "scan" in prose; the
     * point is to catch `Scan` presented as the resource to create.
     */
    const wrongKinds = [/`Scan`/, /`scans`/, /kind:\s*Scan\b/];
    for (const pattern of wrongKinds) {
      expect(readmes[name]).not.toMatch(pattern);
    }
  });

  test('the launch-targets row names the real kinds and no other', () => {
    /*
     * Scoped to the one table row that tells an adopter what to create. A sweep over
     * the whole README for /`Ash[A-Z]\w*`/ was my first attempt and it was useless:
     * it matched AshFargate, AshVersion, AshImageTag and six more, because every
     * stack and half the parameters share that prefix. The defect being guarded is
     * specifically "the entry point column names the wrong kind", so the assertion
     * belongs on that row.
     */
    const row = readmes['deploy/README.md']
      .split('\n')
      .find((line) => line.startsWith('| EKS operator |'));
    expect(row).toBeDefined();
    const named = [...row!.matchAll(/`(Ash[A-Z][A-Za-z]*)`/g)].map((m) => m[1]).sort();
    expect(named).toEqual(ASH_OPERATOR_CRDS.map((c) => c.kind).sort());
  });
});

describe('the Pod Identity agent precondition is observable', () => {
  test('its status is a stack output, not only a source comment', () => {
    // An absent agent and the deliberately-empty operator role produce the same
    // symptom, so a reader cannot tell them apart without this.
    const outputs = JSON_TEMPLATE.Outputs ?? {};
    expect(Object.keys(outputs)).toContain('PodIdentityAgentStatus');
    expect(JSON.stringify(outputs.PodIdentityAgentStatus.Value)).toContain('Fn::GetAtt');
  });

  test('the probe never fails the install', () => {
    // A diagnostic that can break the thing it is diagnosing is worse than none.
    const probe = ASH_OPERATOR_APPLIER.slice(
      ASH_OPERATOR_APPLIER.indexOf('def pod_identity_agent_state('),
      ASH_OPERATOR_APPLIER.indexOf('def respond('),
    );
    expect(probe).toContain('return "ABSENT"');
    expect(probe).toContain('return "UNKNOWN"');
    expect(probe).toContain('except Exception as err');
    // No re-raise anywhere in the probe.
    expect(probe).not.toContain('raise');
  });

  test('the installer may read add-ons of the named cluster only', () => {
    const policies = Object.values<any>(TEMPLATE.findResources('AWS::IAM::Policy'));
    const statements = policies[0].Properties.PolicyDocument.Statement;
    const addon = statements.find((s: any) =>
      [s.Action].flat().includes('eks:DescribeAddon'),
    );
    expect(addon).toBeDefined();
    // Scoped to an addon ARN, not '*'.
    expect([addon.Resource].flat()).not.toContain('*');
    expect(JSON.stringify(addon.Resource)).toContain(':addon/');
  });
});

/*
 * THE OPERATOR'S RBAC AND CRD CONTRACT, PARSED FROM THE OPERATOR'S OWN FILES.
 *
 * The other side of every comparison below is read from
 * `deploy/kubernetes-operator/manifests/rbac.yaml` and
 * `deploy/kubernetes-operator/generated/crd-*.yaml` on this commit. Until this was
 * changed it was a second hand-transcribed copy of the table, and the comparison could
 * only prove that the stack agreed with that copy: when the operator's AshScan CRD
 * gained a `Coverage` printer column, the stack never installed it and every test
 * stayed green. Parsing the operator's files is what makes a change on either side
 * fail here.
 *
 * Compared as SETS, failing on any difference in EITHER direction. A "contains
 * everything required" assertion would pass while silently keeping an over-grant --
 * `jobs: patch` is the specific one that was here before and that the operator's
 * author deliberately removed when they moved from `kopf.on.field` to stateless
 * `on.event`. Over-grant on RBAC installed by a cluster-admin bootstrap matters as
 * much as under-grant.
 *
 * js-yaml is a direct devDependency for this. It was already in the lockfile through
 * jest's coverage stack, and depending on a transitive copy would let an unrelated jest
 * upgrade remove the parser this suite needs.
 */
const { loadAll: yamlLoadAll } = require('js-yaml') as { loadAll: (text: string) => unknown[] };

const OPERATOR_DIR = join(__dirname, '..', '..', 'kubernetes-operator');
const OPERATOR_RBAC_YAML = join(OPERATOR_DIR, 'manifests', 'rbac.yaml');
/**
 * Every manifest the operator ships, in every format `kubectl apply -f manifests/` reads:
 * `.json`, `.yaml` and `.yml`. RBAC and ServiceAccounts are read from all of them, not
 * from rbac.yaml alone, so a Role added to operator.yaml, to a new file, or to a JSON file
 * is compared too rather than sitting outside the files this suite happens to open.
 */
function manifestFiles(dir: string): string[] {
  return readdirSync(dir)
    .filter((name) => ['.json', '.yaml', '.yml'].some((ext) => name.endsWith(ext)))
    .sort()
    .map((name) => join(dir, name));
}
const OPERATOR_MANIFESTS_DIR = join(OPERATOR_DIR, 'manifests');
const OPERATOR_MANIFEST_YAMLS = manifestFiles(OPERATOR_MANIFESTS_DIR);
const OPERATOR_CRD_YAMLS = ['crd-ashscans.yaml', 'crd-ashmcpservers.yaml'].map((name) =>
  join(OPERATOR_DIR, 'generated', name),
);

/** One Kubernetes document, as far as these tests read it. */
interface K8sDoc {
  readonly kind: string;
  readonly metadata: {
    readonly name: string;
    readonly namespace?: string;
    readonly labels?: Record<string, string>;
    readonly annotations?: Record<string, string>;
  };
  readonly rules?: RbacRule[];
  readonly roleRef?: { readonly apiGroup?: string; readonly kind: string; readonly name: string };
  readonly subjects?: Array<{ readonly kind: string; readonly name: string; readonly namespace?: string }>;
  readonly spec?: any;
}

/**
 * Every kind that grants or binds a permission.
 *
 * The comparison below is over ALL documents of these kinds, not over the two roles this
 * stack happens to install. Selecting by name was the gap: a Role, ClusterRole or binding
 * added to rbac.yaml under any other name was never read, so the stack could under-install
 * the operator's RBAC with every test green.
 */
const RBAC_KINDS = ['ClusterRole', 'ClusterRoleBinding', 'Role', 'RoleBinding'];

function loadYamlDocs(path: string): K8sDoc[] {
  // loadAll, and nulls dropped: a leading or trailing `---` yields an empty document.
  return yamlLoadAll(readFileSync(path, 'utf8')).filter((d) => d != null) as K8sDoc[];
}

/**
 * Every top-level kind the operator's manifests may carry. A document of any other kind
 * is reported as drift, so a new kind, or a wrapper this suite does not unwrap, cannot be
 * applied by `kubectl apply -f manifests/` while every comparison here skips it.
 */
const MANIFEST_KINDS = [
  'ClusterRole',
  'ClusterRoleBinding',
  'Deployment',
  'Namespace',
  'NetworkPolicy',
  'Role',
  'RoleBinding',
  'ServiceAccount',
];

/**
 * A manifest file's documents with every `kind: *List` flattened into its `items`, the
 * way kubectl's resource builder does. YAML is a superset of JSON, so one parser reads
 * all three file types.
 */
function loadManifestDocs(path: string): K8sDoc[] {
  const expand = (doc: any): K8sDoc[] =>
    typeof doc?.kind === 'string' && doc.kind.endsWith('List') ? (doc.items ?? []).flatMap(expand) : [doc];
  return loadYamlDocs(path).flatMap(expand);
}

/** The one document of `kind` named `name`; anything else is a parse problem, not drift. */
function only(docs: K8sDoc[], kind: string, name: string): K8sDoc {
  const found = docs.filter((d) => d.kind === kind && d.metadata?.name === name);
  if (found.length !== 1) {
    throw new Error(`expected one ${kind}/${name} in the operator manifests, found ${found.length}`);
  }
  return found[0];
}

/** What the operator's own files declare, in the stack's vocabulary. */
interface OperatorContract {
  /** Every Role, ClusterRole, RoleBinding and ClusterRoleBinding in the operator's manifests. */
  readonly rbac: K8sDoc[];
  /** `Kind namespace/name` of every manifest document whose kind is not in MANIFEST_KINDS. */
  readonly unexpectedKinds: string[];
  readonly serviceAccounts: string[];
  readonly crds: Array<{
    readonly group: string;
    readonly versions: string[];
    readonly entry: AshCrd;
  }>;
}

function loadOperatorContract(manifestPaths: string[], crdPaths: string[]): OperatorContract {
  const rbac = manifestPaths.flatMap(loadManifestDocs);
  const crds = crdPaths.flatMap(loadYamlDocs).filter((d) => d.kind === 'CustomResourceDefinition');
  return {
    rbac: rbac.filter((d) => RBAC_KINDS.includes(d.kind)),
    unexpectedKinds: rbac.filter((d) => !MANIFEST_KINDS.includes(d?.kind)).map((d) => rbacKey(d)),
    serviceAccounts: rbac
      .filter((d) => d.kind === 'ServiceAccount')
      .map((d) => d.metadata.name)
      .sort(),
    crds: crds.map((d) => {
      const versions = d.spec.versions as any[];
      // The stack installs exactly one version; a second one in the operator's CRD is
      // drift, and is reported through `versions` rather than silently read from [0].
      const v0 = versions[0];
      return {
        group: d.spec.group,
        versions: versions.map((v) => v.name),
        entry: {
          kind: d.spec.names.kind,
          listKind: d.spec.names.listKind,
          plural: d.spec.names.plural,
          singular: d.spec.names.singular,
          shortNames: d.spec.names.shortNames ?? [],
          required: v0.schema.openAPIV3Schema.properties.spec.required ?? [],
          printerColumns: (v0.additionalPrinterColumns ?? []).map((c: any) => ({
            name: c.name,
            type: c.type,
            jsonPath: c.jsonPath,
          })),
        },
      };
    }),
  };
}

const OPERATOR = loadOperatorContract(OPERATOR_MANIFEST_YAMLS, OPERATOR_CRD_YAMLS);
const OPERATOR_RBAC_DOCS = loadManifestDocs(OPERATOR_RBAC_YAML);
const AUTHORITATIVE_CLUSTER_RULES: RbacRule[] =
  only(OPERATOR_RBAC_DOCS, 'ClusterRole', 'ash-operator-crd-reader').rules ?? [];
const AUTHORITATIVE_NAMESPACED_RULES: RbacRule[] =
  only(OPERATOR_RBAC_DOCS, 'Role', 'ash-operator').rules ?? [];

/**
 * The documents the applier actually builds, got by RUNNING its `documents()`.
 *
 * The stack's side of the RBAC comparison has to be what it installs, and that is built
 * in Python: the binding names, roleRefs and subjects exist nowhere in the TypeScript. A
 * TypeScript description of them would be one more hand copy that agrees with itself.
 * So the rendered applier is executed with python3, with boto3 and botocore stubbed (the
 * document builders use neither), and `documents()` is called the way `handler()` calls
 * it. The pytest suite does the same against the committed template.
 *
 * Fails, rather than skips, when python3 is missing: a skipped comparison is the
 * green-with-nothing-checked outcome this exists to prevent.
 */
function installedDocuments(namespace: string): { docs: K8sDoc[]; labels: Record<string, string> } {
  const driver = [
    'import json, sys, types',
    'boto3 = types.ModuleType("boto3")',
    'signers = types.ModuleType("botocore.signers")',
    'signers.RequestSigner = object',
    'sys.modules.update({"boto3": boto3, "botocore": types.ModuleType("botocore"),',
    '                    "botocore.signers": signers})',
    'scope = {"__name__": "ash_eks_applier"}',
    'exec(compile(sys.stdin.read(), "applier", "exec"), scope)',
    'docs = scope["documents"](sys.argv[1], "registry.example/op:v1")',
    'print(json.dumps({"docs": [m for _, m, _ in docs], "labels": scope["LABELS"]}))',
  ].join('\n');
  const run = spawnSync(process.env.ASH_TEST_PYTHON ?? 'python3', ['-c', driver, namespace], {
    input: ASH_OPERATOR_APPLIER,
    encoding: 'utf8',
  });
  if (run.error || run.status !== 0) {
    throw new Error(`running the applier's documents() failed: ${run.error ?? run.stderr}`);
  }
  return JSON.parse(run.stdout);
}

// The operator's rbac.yaml installs into ash-system, which is this stack's default.
const { docs: INSTALLED, labels: STACK_LABELS } = installedDocuments(DEFAULT_OPERATOR_NAMESPACE);
const INSTALLED_RBAC = INSTALLED.filter((d) => RBAC_KINDS.includes(d.kind));

/**
 * How many rules the namespaced Role must carry.
 *
 * Spelled out so the set comparison below cannot pass vacuously. Two empty arrays are
 * set-equal, so an accident that emptied either side -- a bad edit, or a parser change
 * if this ever reads the rules instead of declaring them -- would report a clean
 * comparison having measured nothing. The operator's own RBAC differ hit exactly that:
 * it anchored on the first `[` after the constant name, which is the one in
 * `RbacRule[]`, parsed `[]`, and reported "0 over-grants, 45 missing" against an empty
 * set. A count is the cheapest guard against a comparison that proves nothing.
 */
const EXPECTED_NAMESPACED_RULE_COUNT = 10;
const EXPECTED_CLUSTER_RULE_COUNT = 1;

/**
 * A value as canonical JSON: object keys sorted and every array sorted, recursively.
 *
 * Structural, not delimiter-joined. Joining members with a comma made `["a", "b"]` and
 * `["a,b"]` render alike, and RBAC matches those strings literally, so a rule granting
 * nothing compared equal to one granting two resources. Every array in an RBAC object is
 * a set to the API server, so sorting them makes a reordering compare equal and nothing
 * else.
 */
function setJson(value: unknown): string {
  const norm = (v: unknown): unknown => {
    if (Array.isArray(v)) {
      return v
        .map(norm)
        .map((x) => [JSON.stringify(x), x] as const)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([, x]) => x);
    }
    if (v !== null && typeof v === 'object') {
      return Object.fromEntries(
        Object.keys(v as object)
          .sort()
          .map((k) => [k, norm((v as Record<string, unknown>)[k])]),
      );
    }
    return v;
  };
  return JSON.stringify(norm(value) ?? null);
}

/** One rule as canonical JSON, with EVERY key in it, so rules compare as a set. */
function canonical(rule: RbacRule): string {
  return setJson(rule);
}

function canonicalSet(rules: RbacRule[]): string[] {
  return rules.map(canonical).sort();
}

describe('the RBAC it installs equals the operator contract exactly', () => {
  test('NON-VACUITY: both sides carry the expected number of rules', () => {
    /*
     * This test exists so the two set comparisons below cannot pass by comparing
     * nothing. `canonicalSet([])` equals `canonicalSet([])`, so an edit that emptied
     * either array -- or, if this ever parses the rules rather than importing them, a
     * parser that anchored on the wrong bracket -- would report agreement having
     * measured zero rules.
     *
     * That is not hypothetical: the operator's own RBAC differ anchored on the first
     * `[` after the constant name, which is the one in the type annotation
     * `RbacRule[]`, and so diffed against `[]` and reported "0 over-grants, 45
     * missing".
     *
     * Asserted on BOTH sides, because guarding only the stack's constants would leave
     * an emptied authoritative table reporting a clean comparison.
     */
    expect(ASH_OPERATOR_NAMESPACED_RULES).toHaveLength(EXPECTED_NAMESPACED_RULE_COUNT);
    expect(AUTHORITATIVE_NAMESPACED_RULES).toHaveLength(EXPECTED_NAMESPACED_RULE_COUNT);
    expect(ASH_OPERATOR_CLUSTER_RULES).toHaveLength(EXPECTED_CLUSTER_RULE_COUNT);
    expect(AUTHORITATIVE_CLUSTER_RULES).toHaveLength(EXPECTED_CLUSTER_RULE_COUNT);
    // And every rule is non-empty in all three fields, so a rule reduced to
    // `{apiGroups: [], resources: [], verbs: []}` cannot pad the count.
    for (const rule of [...ASH_OPERATOR_CLUSTER_RULES, ...ASH_OPERATOR_NAMESPACED_RULES]) {
      expect(rule.apiGroups.length).toBeGreaterThan(0);
      expect(rule.resources.length).toBeGreaterThan(0);
      expect(rule.verbs.length).toBeGreaterThan(0);
    }
  });

  test('the cluster-scoped rules are set-equal to the authoritative table', () => {
    expect(canonicalSet(ASH_OPERATOR_CLUSTER_RULES)).toEqual(
      canonicalSet(AUTHORITATIVE_CLUSTER_RULES),
    );
  });

  test('the namespaced rules are set-equal to the authoritative table', () => {
    // toEqual on two sorted arrays fails in BOTH directions and prints the
    // difference, which is what makes an over-grant as loud as a missing grant.
    expect(canonicalSet(ASH_OPERATOR_NAMESPACED_RULES)).toEqual(
      canonicalSet(AUTHORITATIVE_NAMESPACED_RULES),
    );
  });

  test('no duplicate rule inflates either side of that comparison', () => {
    // Two identical rules collapse in a set comparison, so a table with a
    // duplicated row could match a table missing a different row. Checked rather
    // than assumed, because it would make the equality above meaningless.
    for (const rules of [ASH_OPERATOR_CLUSTER_RULES, ASH_OPERATOR_NAMESPACED_RULES]) {
      const seen = canonicalSet(rules);
      expect(new Set(seen).size).toBe(seen.length);
    }
  });

  test('the four load-bearing properties of the table hold', () => {
    const by = (resource: string) =>
      ASH_OPERATOR_NAMESPACED_RULES.find((r) => r.resources.includes(resource));
    // 1. pods is read-only: the operator reads pod state, the Jobs create pods.
    expect(by('pods')!.verbs.sort()).toEqual(['get', 'list', 'watch']);
    // 2. jobs has NO patch. The author moved to stateless on.event precisely so
    //    kopf would stop patching the watched Job; granting patch undoes that.
    expect(by('jobs')!.verbs).not.toContain('patch');
    // 3. There is NO leases rule. This assertion was the exact inverse one revision
    //    ago, on the invented reason "kopf peering needs it". Measurement against the
    //    running operator settled it: no leases are taken, a full scan completes
    //    without the grant, and the e2e suite passes against the reduced set. Those
    //    five triples were this stack's only over-grant. Re-adding the rule is correct
    //    only together with dropping --standalone.
    expect(by('leases')).toBeUndefined();
    // 4. status subresources are separate, and they are the operator's whole
    //    reporting path. A grant on ashscans alone does not cover them.
    const status = by('ashscans/status')!;
    expect(status.resources).toContain('ashmcpservers/status');
    expect(status.verbs.sort()).toEqual(['get', 'patch']);
  });

  test('no rule grants a wildcard api group, resource or verb', () => {
    for (const rule of [...ASH_OPERATOR_CLUSTER_RULES, ...ASH_OPERATOR_NAMESPACED_RULES]) {
      for (const value of [...rule.apiGroups, ...rule.resources, ...rule.verbs]) {
        expect(value).not.toBe('*');
      }
    }
  });

  test('it never asks for secrets', () => {
    // A security scanner able to read every Secret in the cluster is a far larger
    // target than one that cannot.
    const resources = [...ASH_OPERATOR_CLUSTER_RULES, ...ASH_OPERATOR_NAMESPACED_RULES]
      .flatMap((r) => r.resources);
    expect(resources).not.toContain('secrets');
    expect(ASH_OPERATOR_APPLIER).not.toContain('"secrets"');
  });

  test('pythonLiteral refuses JSON spellings Python would not understand', () => {
    /*
     * The guard's whole purpose is that nothing in this repository parses the embedded
     * source, so `true` reaching the applier as a bare word would surface as a NameError
     * inside a Lambda at deploy time — after synth, after the drift gate, after review.
     * It was untested, which meant the one mechanism protecting against that had no
     * evidence it fired.
     */
    expect(() => pythonLiteral([{ served: true }])).toThrow(/pythonLiteral cannot render/);
    expect(() => pythonLiteral({ enabled: false })).toThrow(/false/);
    expect(() => pythonLiteral({ value: null })).toThrow(/null/);
    // And the positive control: the shapes actually interpolated must pass, or the guard
    // would be throwing on everything and the test above would prove nothing.
    expect(() => pythonLiteral(ASH_OPERATOR_NAMESPACED_RULES)).not.toThrow();
    expect(() => pythonLiteral(ASH_OPERATOR_CRDS)).not.toThrow();
    expect(pythonLiteral(['get', 'list'])).toContain('"get"');
  });

  test('the rules reach the applier rather than only living in TypeScript', () => {
    // The constants are the source of truth only if they are actually interpolated.
    // Without this the set comparison above could pass against a Python body that
    // installs something else entirely.
    // Through the same renderer the applier uses, so a change to its formatting
    // cannot make this assertion quietly stop matching.
    expect(ASH_OPERATOR_APPLIER).toContain(pythonLiteral(ASH_OPERATOR_CLUSTER_RULES));
    expect(ASH_OPERATOR_APPLIER).toContain(pythonLiteral(ASH_OPERATOR_NAMESPACED_RULES));
    expect(ASH_OPERATOR_APPLIER).toContain('"rules": CLUSTER_RULES');
    expect(ASH_OPERATOR_APPLIER).toContain('"rules": NAMESPACED_RULES');
  });
});

/** One CRD entry as a canonical string, so the two sides compare field by field. */
function canonicalCrd(entry: AshCrd): string {
  return JSON.stringify({
    kind: entry.kind,
    listKind: entry.listKind,
    plural: entry.plural,
    singular: entry.singular,
    shortNames: [...entry.shortNames].sort(),
    required: [...entry.required].sort(),
    // Order kept: it is the column order `kubectl get` prints.
    printerColumns: entry.printerColumns.map((c) => [c.name, c.type, c.jsonPath]),
  });
}

/** Where an RBAC object lives, as `Kind namespace/name`; cluster-scoped ones have no namespace. */
function rbacKey(doc: K8sDoc): string {
  return `${doc?.kind} ${doc?.metadata?.namespace ?? '(cluster)'}/${doc?.metadata?.name}`;
}

/** A binding's subjects, each as canonical JSON, every key kept. */
function canonicalSubjects(doc: K8sDoc): string[] {
  return (doc.subjects ?? []).map(setJson).sort();
}

/** The top-level keys an RBAC document may carry here; any other one is reported. */
const RBAC_DOC_FIELDS = ['apiVersion', 'kind', 'metadata', 'rules', 'aggregationRule', 'roleRef', 'subjects'];
/** The metadata keys compared; any other one is reported. */
const METADATA_FIELDS = ['name', 'namespace', 'labels', 'annotations'];

/**
 * Inputs the API server would reject, reported here so they fail in CI rather than at
 * `kubectl apply` time. Nothing is defaulted on the way in: a roleRef without apiGroup is
 * invalid, not rbac's group, and `apiGroups: []` is not `[""]`.
 */
function invalidities(doc: K8sDoc): string[] {
  const out: string[] = [];
  for (const rule of (doc.rules ?? []) as unknown as Array<Record<string, unknown>>) {
    const nonEmpty = (k: string) => Array.isArray(rule[k]) && (rule[k] as unknown[]).length > 0;
    if (!nonEmpty('verbs')) out.push(`rule without verbs: ${setJson(rule)}`);
    if (!nonEmpty('resources') && !nonEmpty('nonResourceURLs')) out.push(`rule without resources: ${setJson(rule)}`);
    if (nonEmpty('resources') && !nonEmpty('apiGroups')) out.push(`rule with empty apiGroups: ${setJson(rule)}`);
  }
  if (doc.kind?.endsWith('Binding')) {
    const ref = (doc.roleRef ?? {}) as Record<string, unknown>;
    for (const k of ['apiGroup', 'kind', 'name']) if (!ref[k]) out.push(`roleRef without ${k}`);
  }
  return out;
}

/**
 * Every way the stack disagrees with an operator contract, as readable lines.
 *
 * One function, used both on the real files and on the planted copies below, so the
 * negative controls exercise the same comparison the real assertion makes.
 *
 * The RBAC half compares what the applier BUILDS (`INSTALLED_RBAC`) against every RBAC
 * document in the operator's manifests: the set of (kind, namespace, name) in both
 * directions, then for each object on both sides its apiVersion, labels, annotations and
 * rules or aggregationRule, or its roleRef and subjects. Every value is compared as
 * structure (`setJson`), nothing is projected or defaulted, and a field this function
 * does not know is reported rather than skipped.
 */
function contractDrift(op: OperatorContract): string[] {
  const drift: string[] = [];
  const diffSets = (what: string, ours: string[], theirs: string[]) => {
    for (const x of ours.filter((v) => !theirs.includes(v))) drift.push(`${what}: only in the stack: ${x}`);
    for (const x of theirs.filter((v) => !ours.includes(v))) drift.push(`${what}: only in the operator: ${x}`);
    // Membership alone would let a duplicated entry on one side pass as equal.
    for (const [side, list] of [['stack', ours], ['operator', theirs]] as const) {
      for (const x of new Set(list.filter((v, i) => list.indexOf(v) !== i))) {
        drift.push(`${what}: repeated in the ${side}: ${x}`);
      }
    }
  };
  for (const key of op.unexpectedKinds) drift.push(`manifests: kind not in the allowlist: ${key}`);
  const ours = new Map(INSTALLED_RBAC.map((d) => [rbacKey(d), d]));
  const theirs = new Map(op.rbac.map((d) => [rbacKey(d), d]));
  // Two documents with one key would collapse in the maps and hide each other.
  if (theirs.size !== op.rbac.length) drift.push('RBAC objects: the operator repeats a kind/namespace/name');
  diffSets('RBAC objects', [...ours.keys()].sort(), [...theirs.keys()].sort());
  for (const [side, docs] of [['stack', INSTALLED_RBAC], ['operator', op.rbac]] as const) {
    for (const doc of docs) {
      for (const field of Object.keys(doc).filter((k) => !RBAC_DOC_FIELDS.includes(k)).sort()) {
        drift.push(`${rbacKey(doc)}: unknown field in the ${side}: ${field}`);
      }
      for (const field of Object.keys(doc.metadata ?? {}).filter((k) => !METADATA_FIELDS.includes(k)).sort()) {
        drift.push(`${rbacKey(doc)}: unknown metadata field in the ${side}: ${field}`);
      }
      for (const problem of invalidities(doc)) drift.push(`${rbacKey(doc)}: invalid in the ${side}: ${problem}`);
    }
  }
  for (const [key, mine] of ours) {
    const other = theirs.get(key);
    if (other === undefined) continue;
    diffSets(`${key} apiVersion`, [setJson((mine as any).apiVersion)], [setJson((other as any).apiVersion)]);
    // Labels: every operator label must be on the stack's object with the same value, and
    // every stack label other than its own bookkeeping LABELS must be on the operator's.
    // An aggregate-to-admin label merges the role into a built-in one, so it is not cosmetic.
    const labelSet = (d: K8sDoc) => Object.entries(d.metadata?.labels ?? {}).map(([k, v]) => setJson([k, v]));
    const stackOwn = new Set(Object.entries(STACK_LABELS).map(([k, v]) => setJson([k, v])));
    const theirLabels = labelSet(other);
    diffSets(
      `${key} labels`,
      labelSet(mine).filter((l) => !stackOwn.has(l) || theirLabels.includes(l)),
      theirLabels,
    );
    diffSets(`${key} annotations`, [setJson(mine.metadata?.annotations ?? {})], [setJson(other.metadata?.annotations ?? {})]);
    if (mine.kind.endsWith('Binding')) {
      diffSets(`${key} roleRef`, [setJson(mine.roleRef ?? null)], [setJson(other.roleRef ?? null)]);
      diffSets(`${key} subjects`, canonicalSubjects(mine), canonicalSubjects(other));
    } else {
      diffSets(`${key} rules`, canonicalSet(mine.rules ?? []), canonicalSet(other.rules ?? []));
      const agg = (d: K8sDoc) => setJson((d as any).aggregationRule ?? null);
      diffSets(`${key} aggregationRule`, [agg(mine)], [agg(other)]);
    }
  }
  diffSets(
    'service accounts',
    INSTALLED.filter((d) => d.kind === 'ServiceAccount').map((d) => d.metadata.name).sort(),
    op.serviceAccounts,
  );
  for (const crd of op.crds) {
    if (crd.group !== ASH_OPERATOR_API_GROUP) drift.push(`${crd.entry.plural}: group ${crd.group}`);
    if (JSON.stringify(crd.versions) !== JSON.stringify([ASH_OPERATOR_API_VERSION])) {
      drift.push(`${crd.entry.plural}: versions ${crd.versions.join(',')}`);
    }
  }
  diffSets('CRDs', ASH_OPERATOR_CRDS.map(canonicalCrd).sort(), op.crds.map((c) => canonicalCrd(c.entry)).sort());
  return drift;
}

/** The operator contract re-read after `edit` is applied to a temp copy of one file. */
function plantedContractBy(file: string, edit: (text: string) => string): OperatorContract {
  const original = readFileSync(file, 'utf8');
  const planted = edit(original);
  // The plant must land. An edit that changed nothing would leave the copy equal to
  // the original, and the "drift is reported" assertion would then be testing the real
  // files under another name.
  expect(planted).not.toBe(original);
  const dir = mkdtempSync(join(tmpdir(), 'ash-eks-contract-'));
  try {
    const copy = join(dir, basename(file));
    writeFileSync(copy, planted);
    const swap = (p: string) => (p === file ? copy : p);
    return loadOperatorContract(OPERATOR_MANIFEST_YAMLS.map(swap), OPERATOR_CRD_YAMLS.map(swap));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The operator contract re-read after one textual replacement, which must match. */
function plantedContract(file: string, from: string, to: string): OperatorContract {
  return plantedContractBy(file, (text) => {
    expect(text).toContain(from);
    return text.replace(from, to);
  });
}

/**
 * The operator contract re-read from a temp copy of the whole manifests directory after
 * `edit` adds or changes files in it. File discovery runs again on the copy, so a control
 * planted here exercises which files are read, not only how they are compared.
 */
function plantedManifestsDir(edit: (dir: string) => void): OperatorContract {
  const dir = mkdtempSync(join(tmpdir(), 'ash-eks-manifests-'));
  try {
    for (const file of readdirSync(OPERATOR_MANIFESTS_DIR)) {
      writeFileSync(join(dir, file), readFileSync(join(OPERATOR_MANIFESTS_DIR, file)));
    }
    edit(dir);
    return loadOperatorContract(manifestFiles(dir), OPERATOR_CRD_YAMLS);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * The operator contract with its parsed RBAC documents edited in place, on a deep copy.
 *
 * Structural rather than textual, so a control does not depend on one line of rbac.yaml
 * staying as it is: a text anchor that stops matching fails as "plant did not land",
 * which reads as drift being caught when nothing was compared.
 */
function plantedDocs(edit: (find: (kind: string, name: string) => any) => void): OperatorContract {
  const rbac = JSON.parse(JSON.stringify(OPERATOR.rbac)) as K8sDoc[];
  const before = JSON.stringify(rbac);
  edit((kind, name) => {
    const found = rbac.find((d) => d.kind === kind && d.metadata.name === name);
    expect(found).toBeDefined();
    return found;
  });
  expect(JSON.stringify(rbac)).not.toBe(before);
  return { ...OPERATOR, rbac };
}

const K_CR = 'ClusterRole (cluster)/ash-operator-crd-reader';
const K_CRB = 'ClusterRoleBinding (cluster)/ash-operator-crd-reader';
const K_ROLE = 'Role ash-system/ash-operator';
const K_RB = 'RoleBinding ash-system/ash-operator';
const OPERATOR_SUBJECT = { kind: 'ServiceAccount', name: 'ash-operator', namespace: 'ash-system' };
const ruleFor = (doc: any, resource: string) => doc.rules.find((r: any) => r.resources?.includes(resource));
const SECRETS_ROLE = {
  apiVersion: 'rbac.authorization.k8s.io/v1',
  kind: 'Role',
  metadata: { name: 'ash-secrets', namespace: 'ash-system' },
  rules: [{ apiGroups: [''], resources: ['secrets'], verbs: ['get', 'list'] }],
};
const SECRETS_BINDING = {
  apiVersion: 'rbac.authorization.k8s.io/v1',
  kind: 'RoleBinding',
  metadata: { name: 'ash-secrets', namespace: 'ash-system' },
  roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: 'ash-secrets' },
  subjects: [OPERATOR_SUBJECT],
};

describe("the stack's operator contract equals the operator's own files", () => {
  test('NON-VACUITY: the parsed side is populated', () => {
    // Both CRD files parsed, each with its names and its columns, and both accounts.
    expect(OPERATOR.crds.map((c) => c.entry.plural).sort()).toEqual(['ashmcpservers', 'ashscans']);
    for (const crd of OPERATOR.crds) {
      expect(crd.entry.printerColumns.length).toBeGreaterThan(0);
      expect(crd.entry.required).toContain('image');
    }
    expect(OPERATOR.serviceAccounts).toEqual(['ash-operator', 'ash-scan']);
  });

  test('NON-VACUITY: both sides of the RBAC comparison carry all four objects', () => {
    // Two empty lists are set-equal. The executed applier and rbac.yaml must each yield
    // the two roles and the two bindings, every binding with a roleRef and a subject.
    const keys = [
      'ClusterRole (cluster)/ash-operator-crd-reader',
      'ClusterRoleBinding (cluster)/ash-operator-crd-reader',
      'Role ash-system/ash-operator',
      'RoleBinding ash-system/ash-operator',
    ];
    expect(INSTALLED_RBAC.map(rbacKey).sort()).toEqual(keys);
    expect(OPERATOR.rbac.map(rbacKey).sort()).toEqual(keys);
    for (const doc of [...INSTALLED_RBAC, ...OPERATOR.rbac]) {
      if (doc.kind.endsWith('Binding')) {
        expect(doc.roleRef?.name).toBeTruthy();
        expect(canonicalSubjects(doc).length).toBeGreaterThan(0);
      } else {
        expect((doc.rules ?? []).length).toBeGreaterThan(0);
      }
    }
  });

  test('there is no drift in either direction', () => {
    // toEqual([]) prints every drifted line, so a failure names what to change.
    expect(contractDrift(OPERATOR)).toEqual([]);
  });

  test('NEGATIVE CONTROL: an extra verb on an operator rule is reported', () => {
    const planted = plantedDocs((find) => ruleFor(find('Role', 'ash-operator'), 'jobs').verbs.push('patch'));
    const jobs = { apiGroups: ['batch'], resources: ['jobs'], verbs: ['get', 'list', 'watch', 'create', 'delete'] };
    expect(contractDrift(planted)).toEqual([
      `${K_ROLE} rules: only in the stack: ${setJson(jobs)}`,
      `${K_ROLE} rules: only in the operator: ${setJson({ ...jobs, verbs: [...jobs.verbs, 'patch'] })}`,
    ]);
  });

  test('NEGATIVE CONTROL: comma-joined members are not the same members', () => {
    // RBAC matches strings literally: ["a,b"] grants nothing on a or b.
    const resources = plantedDocs((find) => {
      ruleFor(find('Role', 'ash-operator'), 'ashscans').resources = ['ashscans,ashmcpservers'];
    });
    expect(contractDrift(resources)).toHaveLength(2);
    expect(contractDrift(resources)[1]).toContain('"resources":["ashscans,ashmcpservers"]');
    const verbs = plantedDocs((find) => {
      ruleFor(find('Role', 'ash-operator'), 'configmaps').verbs = ['create,delete,get,list,watch'];
    });
    expect(contractDrift(verbs)).toHaveLength(2);
    expect(contractDrift(verbs)[1]).toContain('"verbs":["create,delete,get,list,watch"]');
  });

  test('NEGATIVE CONTROL: an extra Role appended to rbac.yaml is reported', () => {
    const planted = plantedContractBy(
      OPERATOR_RBAC_YAML,
      (text) =>
        `${text}\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n` +
        'metadata: {name: ash-scan, namespace: ash-system}\n' +
        'rules: [{apiGroups: [""], resources: [secrets], verbs: [get]}]\n',
    );
    expect(contractDrift(planted)).toEqual(['RBAC objects: only in the operator: Role ash-system/ash-scan']);
  });

  test('NEGATIVE CONTROL: a Role in a new .json manifest is reported', () => {
    // `kubectl apply -f manifests/` reads .json files too.
    const planted = plantedManifestsDir((dir) =>
      writeFileSync(join(dir, 'extra-rbac.json'), JSON.stringify(SECRETS_ROLE, null, 2)),
    );
    expect(contractDrift(planted)).toEqual(['RBAC objects: only in the operator: Role ash-system/ash-secrets']);
  });

  test('NEGATIVE CONTROL: a Role and RoleBinding inside a kind: List are reported', () => {
    // kubectl flattens a List into its items, so they are applied like top-level documents.
    const planted = plantedManifestsDir((dir) =>
      writeFileSync(
        join(dir, 'zz-list.yaml'),
        JSON.stringify({ apiVersion: 'v1', kind: 'List', items: [SECRETS_ROLE, SECRETS_BINDING] }),
      ),
    );
    expect(contractDrift(planted)).toEqual([
      'RBAC objects: only in the operator: Role ash-system/ash-secrets',
      'RBAC objects: only in the operator: RoleBinding ash-system/ash-secrets',
    ]);
  });

  test('NEGATIVE CONTROL: a manifest kind outside the allowlist is reported', () => {
    const planted = plantedManifestsDir((dir) =>
      writeFileSync(
        join(dir, 'zz-other.yml'),
        'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: surprise, namespace: ash-system}\n',
      ),
    );
    expect(contractDrift(planted)).toEqual([
      'manifests: kind not in the allowlist: ConfigMap ash-system/surprise',
    ]);
  });

  test('NEGATIVE CONTROL: an extra ClusterRole and its binding are reported', () => {
    const planted = plantedManifestsDir((dir) =>
      writeFileSync(
        join(dir, 'zz-extra.yaml'),
        [
          'apiVersion: rbac.authorization.k8s.io/v1',
          'kind: ClusterRole',
          'metadata: {name: ash-operator-extra}',
          'rules: [{apiGroups: [""], resources: [nodes], verbs: [get]}]',
          '---',
          'apiVersion: rbac.authorization.k8s.io/v1',
          'kind: ClusterRoleBinding',
          'metadata: {name: ash-operator-extra}',
          'roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: ash-operator-extra}',
          'subjects: [{kind: ServiceAccount, name: ash-operator, namespace: ash-system}]',
        ].join('\n'),
      ),
    );
    expect(contractDrift(planted)).toEqual([
      'RBAC objects: only in the operator: ClusterRole (cluster)/ash-operator-extra',
      'RBAC objects: only in the operator: ClusterRoleBinding (cluster)/ash-operator-extra',
    ]);
  });

  test("NEGATIVE CONTROL: a RoleBinding's subject changed is reported", () => {
    const planted = plantedDocs((find) => {
      find('RoleBinding', 'ash-operator').subjects[0].name = 'ash-scan';
    });
    expect(contractDrift(planted)).toEqual([
      `${K_RB} subjects: only in the stack: ${setJson(OPERATOR_SUBJECT)}`,
      `${K_RB} subjects: only in the operator: ${setJson({ ...OPERATOR_SUBJECT, name: 'ash-scan' })}`,
    ]);
  });

  test("NEGATIVE CONTROL: a ClusterRoleBinding's roleRef changed is reported", () => {
    const planted = plantedDocs((find) => {
      find('ClusterRoleBinding', 'ash-operator-crd-reader').roleRef.name = 'view';
    });
    const ref = { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: 'ash-operator-crd-reader' };
    expect(contractDrift(planted)).toEqual([
      `${K_CRB} roleRef: only in the stack: ${setJson(ref)}`,
      `${K_CRB} roleRef: only in the operator: ${setJson({ ...ref, name: 'view' })}`,
    ]);
  });

  test('NEGATIVE CONTROL: a roleRef without apiGroup is invalid, not defaulted', () => {
    const planted = plantedDocs((find) => {
      delete find('RoleBinding', 'ash-operator').roleRef.apiGroup;
    });
    const drift = contractDrift(planted);
    expect(drift[0]).toBe(`${K_RB}: invalid in the operator: roleRef without apiGroup`);
    expect(drift).toHaveLength(3);
  });

  test('NEGATIVE CONTROL: apiGroups: [] is invalid, not the core group', () => {
    const planted = plantedDocs((find) => {
      ruleFor(find('Role', 'ash-operator'), 'pods').apiGroups = [];
    });
    const drift = contractDrift(planted);
    expect(drift[0]).toMatch(new RegExp(`^${K_ROLE}: invalid in the operator: rule with empty apiGroups: `));
    expect(drift).toHaveLength(3);
  });

  test('NEGATIVE CONTROL: resourceNames added to an operator rule is reported', () => {
    // The operator granting ONE ConfigMap while the stack grants all of them.
    const planted = plantedDocs((find) => {
      ruleFor(find('Role', 'ash-operator'), 'configmaps').resourceNames = ['ash-only'];
    });
    const drift = contractDrift(planted);
    expect(drift).toHaveLength(2);
    expect(drift[1]).toMatch(new RegExp(`^${K_ROLE} rules: only in the operator: .*"resourceNames":\\["ash-only"\\]`));
  });

  test('NEGATIVE CONTROL: a nonResourceURLs rule added to the ClusterRole is reported', () => {
    const planted = plantedDocs((find) => {
      find('ClusterRole', 'ash-operator-crd-reader').rules.push({ nonResourceURLs: ['/metrics'], verbs: ['get'] });
    });
    expect(contractDrift(planted)).toEqual([
      `${K_CR} rules: only in the operator: ${setJson({ nonResourceURLs: ['/metrics'], verbs: ['get'] })}`,
    ]);
  });

  test('NEGATIVE CONTROL: an aggregationRule added to the ClusterRole is reported', () => {
    // Aggregation makes the controller manager fill the rules from other ClusterRoles,
    // so the operator's effective grant is no longer the rules list in this file.
    const rule = { clusterRoleSelectors: [{ matchLabels: { 'ash-aggregate': 'true' } }] };
    const planted = plantedDocs((find) => {
      find('ClusterRole', 'ash-operator-crd-reader').aggregationRule = rule;
    });
    expect(contractDrift(planted)).toEqual([
      `${K_CR} aggregationRule: only in the stack: null`,
      `${K_CR} aggregationRule: only in the operator: ${setJson(rule)}`,
    ]);
  });

  test('NEGATIVE CONTROL: an aggregate-to-admin label on the ClusterRole is reported', () => {
    // The label merges this role's rules into the built-in admin role.
    const planted = plantedDocs((find) => {
      find('ClusterRole', 'ash-operator-crd-reader').metadata.labels = {
        'rbac.authorization.k8s.io/aggregate-to-admin': 'true',
      };
    });
    expect(contractDrift(planted)).toEqual([
      `${K_CR} labels: only in the operator: ${setJson(['rbac.authorization.k8s.io/aggregate-to-admin', 'true'])}`,
    ]);
  });

  test('NEGATIVE CONTROL: an annotation, unknown rule key or unknown field is reported', () => {
    const annotated = plantedDocs((find) => {
      find('Role', 'ash-operator').metadata.annotations = { note: 'x' };
    });
    expect(contractDrift(annotated)).toEqual([
      `${K_ROLE} annotations: only in the stack: {}`,
      `${K_ROLE} annotations: only in the operator: {"note":"x"}`,
    ]);
    const ruleKey = plantedDocs((find) => {
      ruleFor(find('Role', 'ash-operator'), 'pods').futureField = ['x'];
    });
    expect(contractDrift(ruleKey)).toHaveLength(2);
    expect(contractDrift(ruleKey)[1]).toContain('"futureField":["x"]');
    const field = plantedDocs((find) => {
      find('Role', 'ash-operator').futureField = 1;
    });
    expect(contractDrift(field)).toEqual([`${K_ROLE}: unknown field in the operator: futureField`]);
    const meta = plantedDocs((find) => {
      find('Role', 'ash-operator').metadata.finalizers = ['x'];
    });
    expect(contractDrift(meta)).toEqual([`${K_ROLE}: unknown metadata field in the operator: finalizers`]);
  });

  test("NEGATIVE CONTROL: a subject's apiGroup and a duplicated subject are reported", () => {
    const grouped = plantedDocs((find) => {
      find('RoleBinding', 'ash-operator').subjects[0].apiGroup = 'example.io';
    });
    expect(contractDrift(grouped)).toEqual([
      `${K_RB} subjects: only in the stack: ${setJson(OPERATOR_SUBJECT)}`,
      `${K_RB} subjects: only in the operator: ${setJson({ ...OPERATOR_SUBJECT, apiGroup: 'example.io' })}`,
    ]);
    const doubled = plantedDocs((find) => {
      find('RoleBinding', 'ash-operator').subjects.push({ ...OPERATOR_SUBJECT });
    });
    expect(contractDrift(doubled)).toEqual([
      `${K_RB} subjects: repeated in the operator: ${setJson(OPERATOR_SUBJECT)}`,
    ]);
  });

  test('NEGATIVE CONTROL: a printer column removed from the operator CRD is reported', () => {
    const planted = plantedContract(
      OPERATOR_CRD_YAMLS[0],
      "    - name: Coverage\n      type: boolean\n      jsonPath: .status.coverageComplete\n",
      '',
    );
    const drift = contractDrift(planted);
    expect(drift.filter((line) => line.startsWith('CRDs: only in the stack:'))).toHaveLength(1);
    expect(drift.filter((line) => line.startsWith('CRDs: only in the operator:'))).toHaveLength(1);
  });

  test('NEGATIVE CONTROL: a renamed ServiceAccount in rbac.yaml is reported', () => {
    const planted = plantedContract(
      OPERATOR_RBAC_YAML,
      'kind: ServiceAccount\nmetadata:\n  name: ash-scan\n',
      'kind: ServiceAccount\nmetadata:\n  name: ash-scanner\n',
    );
    expect(contractDrift(planted)).toEqual([
      'service accounts: only in the stack: ash-scan',
      'service accounts: only in the operator: ash-scanner',
    ]);
  });

  test('CONTROL: ORDER anywhere in rbac.yaml is not drift', () => {
    // A reordering is a no-op to the API server, so it must not go red here. Every array
    // in every document is reversed, recursively, and the documents themselves too.
    const reversed = (v: any): any =>
      Array.isArray(v)
        ? [...v].reverse().map(reversed)
        : v && typeof v === 'object'
          ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, reversed(x)]))
          : v;
    const shuffled = { ...OPERATOR, rbac: reversed(OPERATOR.rbac) };
    expect(JSON.stringify(shuffled.rbac)).not.toBe(JSON.stringify(OPERATOR.rbac));
    expect(contractDrift(shuffled)).toEqual([]);
  });
});

describe('the CRD and ServiceAccount contract', () => {
  test('there are two CRDs with the operator names, not one', () => {
    // Identity fields only. A whole-object toEqual broke as soon as listKind, shortNames,
    // required and printerColumns were added, which is a test coupled to the shape of a
    // structure rather than to the property it exists to check — that there are exactly
    // two CRDs and they carry the operator's names. The added fields have their own test.
    expect(
      ASH_OPERATOR_CRDS.map((c) => ({ kind: c.kind, plural: c.plural, singular: c.singular })),
    ).toEqual([
      { kind: 'AshScan', plural: 'ashscans', singular: 'ashscan' },
      { kind: 'AshMcpServer', plural: 'ashmcpservers', singular: 'ashmcpserver' },
    ]);
    expect(ASH_OPERATOR_API_GROUP).toBe('ash.awslabs.github.io');
    expect(ASH_OPERATOR_API_VERSION).toBe('v1alpha1');
  });

  test('the earlier wrong names are gone', () => {
    // kind Scan / plural scans installed a CRD the operator never watches, which
    // fails in the worst available way: everything reports success and nothing runs.
    expect(ASH_OPERATOR_CRDS.map((c) => c.plural)).not.toContain('scans');
    expect(ASH_OPERATOR_CRDS.map((c) => c.kind)).not.toContain('Scan');
  });

  test('shortNames, listKind and printer columns match the operator CRDs', () => {
    /*
     * This assertion was `expect(ASH_OPERATOR_APPLIER).not.toContain('"shortNames"')` one
     * revision ago — a test actively PINNING a divergence. I had dropped shortNames as an
     * invention and then wrote a test forbidding it, so the suite defended the gap.
     * The operator's generated CRDs declare `shortNames: [ashscan]` and
     * `shortNames: [ashmcp]`, so they are transcription, not invention.
     *
     * Printer columns are not cosmetic: `Phase` is the field the missing-`--namespace`
     * symptom is read from, so a CRD without it hides the operator's own most recent
     * regression from `kubectl get`.
     */
    const byPlural = Object.fromEntries(ASH_OPERATOR_CRDS.map((c) => [c.plural, c]));
    expect(byPlural.ashscans.shortNames).toEqual(['ashscan']);
    expect(byPlural.ashmcpservers.shortNames).toEqual(['ashmcp']);
    expect(byPlural.ashscans.listKind).toBe('AshScanList');
    expect(byPlural.ashmcpservers.listKind).toBe('AshMcpServerList');
    expect(byPlural.ashscans.printerColumns.map((c) => c.name)).toEqual([
      'Phase',
      'Shards',
      'Actionable',
      'Coverage',
      'Incomplete',
      'Age',
    ]);
    expect(byPlural.ashmcpservers.printerColumns.map((c) => c.name)).toEqual([
      'Phase',
      'Endpoint',
      'Age',
    ]);
    for (const crd of ASH_OPERATOR_CRDS) {
      expect(crd.printerColumns.map((c) => c.name)).toContain('Phase');
      expect(crd.required).toContain('image');
    }
    expect(byPlural.ashscans.required).toEqual(['image', 'shardCount', 'source']);
  });

  test('a CRD is applied WITHOUT force, so an existing richer one is not downgraded', () => {
    /*
     * The schema this stack installs is a deliberate subset — the operator's own CRDs are
     * 98 KB and 91 KB of YAML against a 50,688-byte template budget, so embedding them is
     * impossible rather than merely costly. That makes force=true actively harmful for
     * CRDs: server-side apply would take ownership from whoever installed the
     * authoritative schema and replace it with the subset, permanently, since CRDs are
     * never deleted by design. No error and no event.
     */
    expect(ASH_OPERATOR_APPLIER).toContain('force=not is_crd');
    expect(ASH_OPERATOR_APPLIER).toContain('tolerate_409=is_crd');
    expect(ASH_OPERATOR_APPLIER).toContain('"&force=true" if force else "&force=false"');
    // A 409 on a CRD is the good case and must not fail the install.
    expect(ASH_OPERATOR_APPLIER).toContain('KEEPING THE EXISTING OBJECT AT ');
  });

  test('the CRD name is built as plural.group', () => {
    // Anything else is rejected with a name mismatch that reads as a schema error.
    expect(ASH_OPERATOR_APPLIER).toContain('crd_name = entry["plural"] + "." + GROUP');
  });

  test('two ServiceAccounts are created, and the scan one is distinct', () => {
    // The operator launches Jobs that run as the SECOND account. A stack creating
    // only the operator's leaves every Job it launches with no identity.
    expect(OPERATOR_SERVICE_ACCOUNT).toBe('ash-operator');
    expect(SCAN_SERVICE_ACCOUNT).toBe('ash-scan');
    expect(SCAN_SERVICE_ACCOUNT).not.toBe(OPERATOR_SERVICE_ACCOUNT);
    expect(ASH_OPERATOR_APPLIER).toContain('for name in (OPERATOR_SA, SCAN_SA):');
  });

  test('the deployment runs unprivileged with a read-only root filesystem', () => {
    for (const expected of [
      '"runAsNonRoot": True',
      '"readOnlyRootFilesystem": True',
      '"allowPrivilegeEscalation": False',
      '"drop": ["ALL"]',
    ]) {
      expect(ASH_OPERATOR_APPLIER).toContain(expected);
    }
  });

  test('replicas is an int, and the namespace arg is present', () => {
    // A string "1" is rejected by the API server, which is why the manifests are
    // built in Python rather than passed through ResourceProperties.
    expect(ASH_OPERATOR_APPLIER).toContain('"replicas": 1');

    /*
     * THE ARG IS LOAD-BEARING. One revision ago this test asserted the OPPOSITE --
     * that no args were set -- on the reasoning that the image's ENTRYPOINT already
     * carried everything and an invented argv would override it. The ENTRYPOINT does
     * carry `kopf run --standalone -m ash_operator.main`, and Kubernetes APPENDS args
     * to it rather than replacing it, so `--namespace` was the one part that had to
     * come from here.
     *
     * Without it kopf 1.37.2 warns and silently switches to cluster scope, where every
     * watcher 403s against the namespaced Role. Measured symptom: an AshScan reaches
     * `phase: Scanning`, the shard Job runs to `Complete 3/3`, and then it hangs with
     * no collector and no verdict. A scan that looks like it is working and never
     * concludes, which is why neither reading the Dockerfile nor reading this file
     * caught it.
     */
    expect(ASH_OPERATOR_APPLIER).toMatch(/"args": \[\s*"--namespace",\s*"\$\(WATCH_NAMESPACE\)",/);

    /*
     * The namespace arrives via a fieldRef on the pod's own metadata.namespace, not as
     * a literal interpolated from the CloudFormation parameter. An intermediate
     * revision did use the literal, and it worked -- the reason for the fieldRef is
     * that it cannot disagree with where the Deployment landed, and the failure when
     * two copies of this value desync is the silent hang above rather than an error.
     *
     * Asserted negatively too: if the literal form comes back, both would be present
     * and only one can take effect.
     */
    expect(ASH_OPERATOR_APPLIER).toContain('"name": "WATCH_NAMESPACE"');
    expect(ASH_OPERATOR_APPLIER).toContain('"fieldRef": {"fieldPath": "metadata.namespace"}');
    expect(ASH_OPERATOR_APPLIER).not.toContain('"args": ["--namespace", namespace]');

    // `command` must stay unset: setting it REPLACES the ENTRYPOINT and discards
    // `kopf run` entirely, which is a different and worse failure than the one above.
    expect(ASH_OPERATOR_APPLIER).not.toContain('"command"');

    // --standalone is already in the image ENTRYPOINT, so passing it again would be
    // redundant. Matched on the quoted form because the docstring names it in prose.
    expect(ASH_OPERATOR_APPLIER).not.toContain('"--standalone"');
  });
});

describe('the VPC opt-in', () => {
  test('VpcConfig is conditional, so the default template has none', () => {
    const functions = Object.values<any>(TEMPLATE.findResources('AWS::Lambda::Function'));
    const vpcConfig = functions[0].Properties.VpcConfig;
    expect(vpcConfig).toHaveProperty('Fn::If');
    expect(vpcConfig['Fn::If'][0]).toBe('HasVpcConfig');
    // The false branch removes the property outright rather than sending an empty
    // list, which Lambda rejects.
    expect(vpcConfig['Fn::If'][2]).toEqual({ Ref: 'AWS::NoValue' });
  });

  test('the Rule uses only functions CloudFormation allows in Rules', () => {
    /*
     * The CloudFormation "Rules syntax" page lists the only functions a rule may use.
     * Anything else fails template validation at launch, and nothing offline reports
     * it: cfn-lint, cdk-nag and synth all passed a Rule built on Fn::Select. A test
     * that evaluates the Rule with its own interpreter would accept Fn::Select too,
     * so the allowlist is checked separately.
     */
    const RULE_FUNCTIONS = new Set([
      'Fn::And',
      'Fn::Contains',
      'Fn::EachMemberEquals',
      'Fn::EachMemberIn',
      'Fn::Equals',
      'Fn::If',
      'Fn::Not',
      'Fn::Or',
      'Fn::RefAll',
      'Fn::ValueOf',
      'Fn::ValueOfAll',
      'Ref',
    ]);
    const used = new Set<string>();
    const walk = (node: any): void => {
      if (Array.isArray(node)) node.forEach(walk);
      else if (node && typeof node === 'object') {
        for (const [key, value] of Object.entries(node)) {
          if (key.startsWith('Fn::') || key === 'Ref') used.add(key);
          walk(value);
        }
      }
    };
    walk(JSON_TEMPLATE.Rules);
    expect(used.size).toBeGreaterThan(0);
    expect([...used].filter((fn) => !RULE_FUNCTIONS.has(fn))).toEqual([]);
  });

  test('a Rule refuses subnets without security groups, and the reverse', () => {
    /*
     * Evaluated here the way CloudFormation evaluates it, with the parameter values
     * substituted as lists, so the test exercises the assertion's logic and not only
     * its presence. An empty CommaDelimitedList parameter resolves to [""].
     */
    const rule = JSON_TEMPLATE.Rules?.VpcSubnetsAndSecurityGroupsTogether;
    expect(rule).toBeDefined();
    const [assertion] = rule.Assertions;
    const evaluate = (node: any, params: Record<string, string[]>): any => {
      if (typeof node !== 'object' || node === null) return node;
      const [fn] = Object.keys(node);
      const args = node[fn];
      switch (fn) {
        case 'Fn::Or':
          return args.some((a: any) => evaluate(a, params));
        case 'Fn::And':
          return args.every((a: any) => evaluate(a, params));
        case 'Fn::Not':
          return !evaluate(args[0], params);
        case 'Fn::EachMemberEquals': {
          const list: string[] = evaluate(args[0], params);
          return list.every((member) => member === args[1]);
        }
        case 'Ref':
          expect(params).toHaveProperty(args);
          return params[args];
        default:
          throw new Error('unexpected function in rule: ' + fn);
      }
    };
    const cases: [string[], string[], boolean][] = [
      [[''], [''], true],
      [['subnet-a', 'subnet-b'], ['sg-a'], true],
      [['subnet-a'], [''], false],
      [[''], ['sg-a'], false],
    ];
    for (const [subnets, groups, ok] of cases) {
      expect({
        subnets,
        groups,
        ok: evaluate(assertion.Assert, { VpcSubnetIds: subnets, VpcSecurityGroupIds: groups }),
      }).toEqual({ subnets, groups, ok });
    }
  });

  test('the condition keys on the first subnet being empty', () => {
    // A CommaDelimitedList defaulting to '' resolves to a one-element list holding
    // the empty string, so Fn::Select(0) against '' is the only shape that detects
    // "the adopter supplied nothing". Testing against Fn::Equals of the whole list
    // would always be false and the VPC would never attach.
    const condition = JSON.stringify(JSON_TEMPLATE.Conditions.HasVpcConfig);
    expect(condition).toContain('Fn::Select');
    expect(condition).toContain('VpcSubnetIds');
  });
});
