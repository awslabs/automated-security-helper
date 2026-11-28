// The configuration editor's validator.
//
// It checks a value tree, as ASH's loader reads a configuration file, against the raw
// assertion keywords of ASH's configuration schema, and reports each failure as the JSON
// pointer of the instance that failed and the keyword that failed. The verdicts are those of
// Python's jsonschema Draft 2020-12 validator over the same schema, and the tests compare
// them as sets of (instance pointer, keyword).
//
// The keyword set is closed. A schema that uses a keyword outside it, a pattern that is not
// in the pattern table, or a reference it cannot follow makes validation throw
// UnsupportedKeyword, so a page never says "valid" for a rule it does not understand.
//
// Lengths count code points. An integer is a number with no fraction, a boolean is never a
// number, and `format` is an annotation. The module reads no DOM and imports nothing.

/** The assertion keywords this validator implements, in sorted order. */
export const ASSERTION_KEYWORDS = Object.freeze([
  '$ref',
  'additionalProperties',
  'anyOf',
  'const',
  'enum',
  'exclusiveMinimum',
  'items',
  'maxItems',
  'maxLength',
  'maximum',
  'minItems',
  'minLength',
  'minimum',
  'pattern',
  'properties',
  'propertyNames',
  'required',
  'type',
]);

const ASSERTIONS = new Set(ASSERTION_KEYWORDS);

// Keywords that assert nothing: annotations, and `$defs`, where definitions live.
const NON_ASSERTIONS = new Set([
  '$comment',
  '$defs',
  '$id',
  '$schema',
  'default',
  'deprecated',
  'description',
  'examples',
  'format',
  'readOnly',
  'title',
  'writeOnly',
]);

// A reference that is still being followed after this many hops never reaches a keyword.
const MAX_REFERENCE_DEPTH = 200;

/** Thrown when the schema holds something this validator cannot judge. */
export class UnsupportedKeyword extends Error {
  constructor(keyword, detail = '') {
    super(`the validator does not implement '${keyword}'${detail ? ` (${detail})` : ''}`);
    this.name = 'UnsupportedKeyword';
    this.keyword = keyword;
  }
}

const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

const escapeToken = (part) => String(part).replace(/~/g, '~0').replace(/\//g, '~1');

function codePointLength(text) {
  let length = 0;
  // Iterating a string yields code points, so a pair of surrogates counts once.
  for (const _point of text) {
    length += 1;
  }
  return length;
}

function isType(instance, type) {
  switch (type) {
    case 'object':
      return isObject(instance);
    case 'array':
      return Array.isArray(instance);
    case 'string':
      return typeof instance === 'string';
    case 'number':
      return typeof instance === 'number';
    case 'integer':
      return Number.isInteger(instance);
    case 'boolean':
      return typeof instance === 'boolean';
    case 'null':
      return instance === null;
    default:
      throw new UnsupportedKeyword('type', String(type));
  }
}

// JSON equality. A boolean never equals a number, which strict equality already gives.
function equal(left, right) {
  if (left === right) {
    return true;
  }
  if (Array.isArray(left)) {
    return (
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((item, index) => equal(item, right[index]))
    );
  }
  if (isObject(left) && isObject(right)) {
    const keys = Object.keys(left);
    return (
      keys.length === Object.keys(right).length &&
      keys.every((key) => hasOwn(right, key) && equal(left[key], right[key]))
    );
  }
  return false;
}

/** The node a local reference such as "#/$defs/Name" points at in `root`. */
export function resolveRef(root, ref) {
  if (ref === '#') {
    return root;
  }
  if (typeof ref !== 'string' || !ref.startsWith('#/')) {
    throw new UnsupportedKeyword('$ref', String(ref));
  }
  let node = root;
  for (const raw of ref.slice(2).split('/')) {
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (!isObject(node) && !Array.isArray(node)) {
      throw new UnsupportedKeyword('$ref', `${ref} does not exist`);
    }
    if (!hasOwn(node, key)) {
      throw new UnsupportedKeyword('$ref', `${ref} does not exist`);
    }
    node = node[key];
  }
  return node;
}

/**
 * The patterns the schema may use, as compiled expressions. `table` is the data block's
 * pattern map: the Python source of each pattern mapped to its JavaScript translation.
 */
export function compilePatterns(table) {
  const compiled = new Map();
  for (const [source, translation] of Object.entries(table)) {
    compiled.set(source, new RegExp(translation.js, translation.flags));
  }
  return compiled;
}

function check(context, schema, instance, pointer, out) {
  if (schema === true) {
    return;
  }
  if (schema === false) {
    out.push({ pointer, keyword: 'false', detail: {} });
    return;
  }
  if (!isObject(schema)) {
    throw new UnsupportedKeyword('schema', pointer);
  }
  for (const [keyword, value] of Object.entries(schema)) {
    if (NON_ASSERTIONS.has(keyword)) {
      continue;
    }
    if (!ASSERTIONS.has(keyword)) {
      throw new UnsupportedKeyword(keyword);
    }
    const fail = (detail = {}) => out.push({ pointer, keyword, detail });
    switch (keyword) {
      case '$ref':
        if (context.depth >= MAX_REFERENCE_DEPTH) {
          throw new UnsupportedKeyword('$ref', 'a reference that never reaches a keyword');
        }
        context.depth += 1;
        try {
          check(context, resolveRef(context.root, value), instance, pointer, out);
        } finally {
          context.depth -= 1;
        }
        break;
      case 'type': {
        const types = Array.isArray(value) ? value : [value];
        if (!types.some((type) => isType(instance, type))) {
          fail({ expected: types });
        }
        break;
      }
      case 'enum':
        if (!value.some((allowed) => equal(allowed, instance))) {
          fail({ allowed: value });
        }
        break;
      case 'const':
        if (!equal(value, instance)) {
          fail({ expected: value });
        }
        break;
      case 'maximum':
        if (typeof instance === 'number' && instance > value) {
          fail({ limit: value });
        }
        break;
      case 'minimum':
        if (typeof instance === 'number' && instance < value) {
          fail({ limit: value });
        }
        break;
      case 'exclusiveMinimum':
        if (typeof instance === 'number' && instance <= value) {
          fail({ limit: value });
        }
        break;
      case 'minItems':
        if (Array.isArray(instance) && instance.length < value) {
          fail({ limit: value });
        }
        break;
      case 'maxItems':
        if (Array.isArray(instance) && instance.length > value) {
          fail({ limit: value });
        }
        break;
      case 'minLength':
        if (typeof instance === 'string' && codePointLength(instance) < value) {
          fail({ limit: value });
        }
        break;
      case 'maxLength':
        if (typeof instance === 'string' && codePointLength(instance) > value) {
          fail({ limit: value });
        }
        break;
      case 'pattern': {
        const expression = context.patterns.get(value);
        if (expression === undefined) {
          throw new UnsupportedKeyword('pattern', value);
        }
        if (typeof instance === 'string' && !expression.test(instance)) {
          fail({ pattern: value });
        }
        break;
      }
      case 'required': {
        if (isObject(instance)) {
          const missing = value.filter((name) => !hasOwn(instance, name));
          if (missing.length > 0) {
            fail({ missing });
          }
        }
        break;
      }
      case 'properties':
        if (isObject(instance)) {
          for (const [name, sub] of Object.entries(value)) {
            if (hasOwn(instance, name)) {
              check(context, sub, instance[name], `${pointer}/${escapeToken(name)}`, out);
            }
          }
        }
        break;
      case 'additionalProperties': {
        if (!isObject(instance)) {
          break;
        }
        const known = isObject(schema.properties) ? schema.properties : {};
        const extras = Object.keys(instance).filter((name) => !hasOwn(known, name));
        if (isObject(value)) {
          for (const name of extras) {
            check(context, value, instance[name], `${pointer}/${escapeToken(name)}`, out);
          }
        } else if (value === false && extras.length > 0) {
          fail({ extras });
        }
        break;
      }
      case 'items':
        if (Array.isArray(instance)) {
          if (value === false) {
            if (instance.length > 0) {
              fail();
            }
          } else {
            instance.forEach((item, index) => {
              check(context, value, item, `${pointer}/${index}`, out);
            });
          }
        }
        break;
      case 'anyOf': {
        const admitted = value.some((sub) => {
          const found = [];
          check(context, sub, instance, pointer, found);
          return found.length === 0;
        });
        if (!admitted) {
          fail();
        }
        break;
      }
      case 'propertyNames':
        if (isObject(instance)) {
          // The failure belongs to the object, not to the name, as in jsonschema.
          for (const name of Object.keys(instance)) {
            check(context, value, name, pointer, out);
          }
        }
        break;
      default:
        throw new UnsupportedKeyword(keyword);
    }
  }
}

/**
 * The failures of `instance` against `schema`, which is `root` or a schema inside it.
 * Each failure is { pointer, keyword, detail }: the JSON pointer of the instance that
 * failed, the keyword, and the facts a sentence needs (the missing keys, the extra keys,
 * the allowed values, the limit). An empty list is a pass.
 */
export function validate(root, schema, instance, patterns = new Map()) {
  const out = [];
  check({ root, patterns, depth: 0 }, schema, instance, '', out);
  return out;
}

/**
 * The failures of `instance` against the schema of the field at `path` in the data block
 * (the dotted path the block's `fields` map uses), or against the whole schema when `path`
 * is empty.
 */
export function validateField(block, path, instance, patterns = compilePatterns(block.patterns)) {
  const root = block.validationSchema;
  let schema = root;
  if (path !== '') {
    const field = block.fields[path];
    if (field === undefined) {
      throw new RangeError(`the data has no field '${path}'`);
    }
    schema = resolveRef(root, field.schemaPointer);
  }
  return validate(root, schema, instance, patterns);
}

/**
 * Every keyword in `root` that this validator does not implement, sorted. The schema of
 * the page's data must give an empty list, and a build that finds a keyword here fails
 * before the page can ship.
 */
export function unsupportedKeywords(root) {
  const found = new Set();
  const seen = new Set();
  const walk = (schema) => {
    if (!isObject(schema) || seen.has(schema)) {
      return;
    }
    seen.add(schema);
    for (const [keyword, value] of Object.entries(schema)) {
      if (keyword === '$defs') {
        Object.values(value).forEach(walk);
      } else if (NON_ASSERTIONS.has(keyword)) {
        // An annotation: nothing to check.
      } else if (!ASSERTIONS.has(keyword)) {
        found.add(keyword);
      } else if (keyword === 'properties') {
        Object.values(value).forEach(walk);
      } else if (keyword === 'anyOf') {
        value.forEach(walk);
      } else if (['items', 'additionalProperties', 'propertyNames'].includes(keyword)) {
        walk(value);
      }
    }
  };
  walk(root);
  return [...found].sort();
}
