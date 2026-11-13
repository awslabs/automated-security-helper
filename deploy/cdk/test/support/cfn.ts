/**
 * Resolve a synthesized template's values the way CloudFormation would at a launch.
 *
 * WHY THIS EXISTS
 * ---------------
 * Several tests run a script the template hands to a container (the MCP entrypoint,
 * the CodeCommit gate handler, the bootstrap starter) and need the environment a
 * launch would really give it. Writing that environment out by hand keeps agreeing
 * with itself after the stack stops agreeing with it, so the environment is read
 * off the synthesized template instead: every `Ref` to a parameter becomes that
 * parameter's `Default` (or an explicit override, standing in for a value the
 * adopter typed at launch), and every `Fn::If` is decided by evaluating its
 * condition against the same parameter values.
 *
 * WHAT IT DOES NOT DO
 * -------------------
 * It is not a CloudFormation engine. Attributes that only exist after a resource is
 * created (`Fn::GetAtt`, a `Ref` to a resource) resolve to a placeholder the caller
 * can override, and only the intrinsic functions these templates use are handled.
 * An intrinsic it does not know throws rather than resolving to something
 * plausible, so a new shape fails loudly here instead of producing an environment
 * nobody would get.
 */

import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

/** A synthesized template as plain JSON. */
export interface CfnTemplate {
  readonly Parameters?: Record<string, { Default?: unknown; Description?: string; Type?: string }>;
  readonly Conditions?: Record<string, unknown>;
  readonly Resources: Record<string, CfnResource>;
}

export interface CfnResource {
  readonly Type: string;
  readonly Properties?: Record<string, any>;
  readonly Condition?: string;
  readonly DependsOn?: string | string[];
}

/** Synthesize one stack, the same way bin/ash.ts does for the committed templates. */
export function synth(factory: (app: App) => Stack): CfnTemplate {
  const app = new App({ analyticsReporting: false });
  return Template.fromStack(factory(app)).toJSON() as CfnTemplate;
}

/** Marker for `AWS::NoValue`: the property or list element is dropped. */
export const NO_VALUE = Symbol('AWS::NoValue');

export interface ResolveOptions {
  /** Parameter values an adopter typed at launch. Anything absent takes its Default. */
  readonly parameters?: Record<string, string>;
  /** Values for `Fn::GetAtt`, keyed `LogicalId.Attribute`. */
  readonly attributes?: Record<string, string>;
  /** Values for a `Ref` to a resource, keyed by logical id. */
  readonly resourceRefs?: Record<string, string>;
}

const PSEUDO_PARAMETERS: Record<string, string> = {
  'AWS::Region': 'us-east-1',
  'AWS::AccountId': '000000000000',
  'AWS::Partition': 'aws',
  'AWS::URLSuffix': 'amazonaws.com',
  'AWS::StackName': 'AshTestStack',
  'AWS::StackId': 'arn:aws:cloudformation:us-east-1:000000000000:stack/AshTestStack/test',
};

export class CfnResolver {
  constructor(
    private readonly template: CfnTemplate,
    private readonly options: ResolveOptions = {},
  ) {}

  /** The value a parameter would have at this launch. */
  parameter(name: string): string {
    const override = this.options.parameters?.[name];
    if (override !== undefined) {
      return override;
    }
    const declared = this.template.Parameters?.[name];
    if (!declared) {
      throw new Error(`template declares no parameter ${name}`);
    }
    return declared.Default === undefined ? '' : String(declared.Default);
  }

  /** Whether a named condition holds at this launch. */
  condition(name: string): boolean {
    const expression = this.template.Conditions?.[name];
    if (expression === undefined) {
      throw new Error(`template declares no condition ${name}`);
    }
    return this.evaluateCondition(expression);
  }

  private evaluateCondition(expression: unknown): boolean {
    if (expression && typeof expression === 'object' && !Array.isArray(expression)) {
      const node = expression as Record<string, any>;
      if ('Condition' in node) return this.condition(node.Condition as string);
      if ('Fn::Equals' in node) {
        const [left, right] = node['Fn::Equals'] as unknown[];
        return JSON.stringify(this.resolve(left)) === JSON.stringify(this.resolve(right));
      }
      if ('Fn::Not' in node) return !this.evaluateCondition((node['Fn::Not'] as unknown[])[0]);
      if ('Fn::And' in node) return (node['Fn::And'] as unknown[]).every((c) => this.evaluateCondition(c));
      if ('Fn::Or' in node) return (node['Fn::Or'] as unknown[]).some((c) => this.evaluateCondition(c));
    }
    throw new Error(`unsupported condition expression ${JSON.stringify(expression)}`);
  }

  /** Resolve any template value to plain JSON, or NO_VALUE. */
  resolve(value: unknown): any {
    if (value === null || typeof value !== 'object') {
      return value;
    }
    if (Array.isArray(value)) {
      return value.map((item) => this.resolve(item)).filter((item) => item !== NO_VALUE);
    }
    const node = value as Record<string, any>;
    const keys = Object.keys(node);
    if (keys.length === 1) {
      const [key] = keys;
      const arg = node[key];
      switch (key) {
        case 'Ref':
          return this.ref(arg as string);
        case 'Fn::GetAtt': {
          const [id, attribute] = arg as [string, string];
          return this.options.attributes?.[`${id}.${attribute}`] ?? `getatt:${id}.${attribute}`;
        }
        case 'Fn::If': {
          const [conditionName, whenTrue, whenFalse] = arg as [string, unknown, unknown];
          return this.resolve(this.condition(conditionName) ? whenTrue : whenFalse);
        }
        case 'Fn::Join': {
          const [separator, parts] = arg as [string, unknown[]];
          return (this.resolve(parts) as unknown[]).map((part) => String(part)).join(separator);
        }
        case 'Fn::Select': {
          const [index, list] = arg as [unknown, unknown];
          const resolved = this.resolve(list) as unknown[];
          return resolved[Number(this.resolve(index))];
        }
        case 'Fn::Split': {
          const [separator, source] = arg as [string, unknown];
          return String(this.resolve(source)).split(separator);
        }
        default:
          if (key.startsWith('Fn::')) {
            throw new Error(`unsupported intrinsic ${key}`);
          }
      }
    }
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(node)) {
      const resolved = this.resolve(item);
      if (resolved !== NO_VALUE) {
        out[key] = resolved;
      }
    }
    return out;
  }

  private ref(name: string): unknown {
    if (name === 'AWS::NoValue') return NO_VALUE;
    if (name in PSEUDO_PARAMETERS) return PSEUDO_PARAMETERS[name];
    if (this.template.Parameters && name in this.template.Parameters) return this.parameter(name);
    if (name in this.template.Resources) return this.options.resourceRefs?.[name] ?? `ref:${name}`;
    throw new Error(`Ref to ${name}, which is neither a parameter nor a resource`);
  }
}

/** The single resource of a type, failing if there is not exactly one. */
export function onlyResource(template: CfnTemplate, type: string): [string, CfnResource] {
  const found = Object.entries(template.Resources).filter(([, resource]) => resource.Type === type);
  if (found.length !== 1) {
    throw new Error(`expected exactly one ${type}, found ${found.length}`);
  }
  return found[0];
}

/** Flatten an environment map to strings, as the container would see it. */
export function stringEnvironment(resolved: Record<string, unknown>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [name, value] of Object.entries(resolved)) {
    env[name] = value === undefined || value === null ? '' : String(value);
  }
  return env;
}

/** One IAM statement, normalized so Action and Resource are always lists. */
export interface IamStatement {
  readonly effect: string;
  readonly actions: string[];
  readonly resources: string[];
  readonly source: string;
}

/**
 * Every Allow/Deny statement that applies to a role, from every policy shape these
 * stacks emit: `AWS::IAM::Policy` resources attached to it, and inline `Policies`
 * on the role itself. Values are resolved with the given resolver.
 */
export function statementsForRole(
  template: CfnTemplate,
  roleLogicalId: string,
  resolver: CfnResolver,
): IamStatement[] {
  const out: IamStatement[] = [];
  const collect = (document: any, source: string) => {
    const statements = (document?.Statement ?? []) as any[];
    for (const statement of statements) {
      const resolved = resolver.resolve(statement) as Record<string, any>;
      const actions = ([] as string[]).concat(resolved.Action ?? []);
      const resources = ([] as unknown[]).concat(resolved.Resource ?? []).map((r) => String(r));
      out.push({ effect: String(resolved.Effect), actions, resources, source });
    }
  };

  for (const [id, resource] of Object.entries(template.Resources)) {
    if (resource.Type === 'AWS::IAM::Policy') {
      const roles = (resource.Properties?.Roles ?? []) as unknown[];
      if (roles.some((role) => JSON.stringify(role) === JSON.stringify({ Ref: roleLogicalId }))) {
        collect(resource.Properties?.PolicyDocument, id);
      }
    }
  }
  const role = template.Resources[roleLogicalId];
  if (!role || role.Type !== 'AWS::IAM::Role') {
    throw new Error(`${roleLogicalId} is not an AWS::IAM::Role`);
  }
  for (const inline of (role.Properties?.Policies ?? []) as any[]) {
    collect(inline.PolicyDocument, `${roleLogicalId}/${inline.PolicyName}`);
  }
  return out;
}

/** The logical id of the role a resource names through `Fn::GetAtt [role, Arn]`. */
export function roleOf(roleArn: unknown): string {
  const getAtt = (roleArn as Record<string, unknown> | undefined)?.['Fn::GetAtt'] as unknown[] | undefined;
  if (!getAtt || getAtt[1] !== 'Arn') {
    throw new Error(`expected Fn::GetAtt [<role>, Arn], got ${JSON.stringify(roleArn)}`);
  }
  return String(getAtt[0]);
}

/** IAM action matching with `*` wildcards, case-insensitive as IAM is. */
export function actionMatches(pattern: string, action: string): boolean {
  const regex = new RegExp(
    '^' + pattern.split('*').map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$',
    'i',
  );
  return regex.test(action);
}
