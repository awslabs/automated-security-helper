// The editor's validator gives the verdicts of Python's jsonschema.
//
// fixtures/validator-corpus.json holds instances with the verdict and the one failing
// keyword and instance pointer that jsonschema's Draft 2020-12 validator reports for each
// (a Python test checks the file against jsonschema). Here the same cases run through
// validate.js, and the failures are compared as sets of (instance pointer, keyword). The
// tests after the corpus plant inputs that each rule has to flag, and inputs it has to let
// through, so a validator that stopped checking a keyword would fail by name.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  ASSERTION_KEYWORDS,
  UnsupportedKeyword,
  compilePatterns,
  resolveRef,
  unsupportedKeywords,
  validate,
  validateField,
} from '../content/assets/javascripts/config-editor/validate.js';

const fixture = (name) =>
  JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));

const block = fixture('editor-data.json');
const corpus = fixture('validator-corpus.json');
const patterns = compilePatterns(block.patterns);

// Code points that are easy to get wrong in source text, written by number.
const EMOJI = String.fromCodePoint(0x1f600);
const PRECOMPOSED_E = String.fromCodePoint(0xe9);
const DECOMPOSED_E = String.fromCodePoint(0x65, 0x301);

// The failures of a run as a sorted list of "pointer keyword" pairs, each once.
const pairs = (failures) =>
  [...new Set(failures.map((failure) => `${failure.pointer} ${failure.keyword}`))].sort();

const run = (schema, instance) => pairs(validate(schema, schema, instance, patterns));

for (const item of corpus.cases) {
  test(`corpus: ${item.id}`, () => {
    const got = pairs(validateField(block, item.path, item.instance, patterns));
    assert.deepEqual(got, item.valid ? [] : [`${item.pointer} ${item.keyword}`]);
  });
}

for (const item of corpus.keywordCases) {
  test(`keyword corpus: ${item.id}`, () => {
    const want = item.valid ? [] : [`${item.pointer} ${item.keyword}`];
    assert.deepEqual(run(item.schema, item.instance), want);
  });
}

test('the corpus has no repeated id and names a field the block has', () => {
  const ids = [...corpus.cases, ...corpus.keywordCases].map((item) => item.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const item of corpus.cases) {
    assert.ok(item.path === '' || block.fields[item.path], `no field ${item.path}`);
  }
});

test('the editor implements exactly the eighteen assertion keywords', () => {
  assert.equal(ASSERTION_KEYWORDS.length, 18);
  assert.deepEqual([...ASSERTION_KEYWORDS].sort(), [...ASSERTION_KEYWORDS]);
  assert.ok(ASSERTION_KEYWORDS.includes('$ref'));
});

test('the schema of the block uses no keyword the editor lacks', () => {
  assert.deepEqual(unsupportedKeywords(block.validationSchema), []);
});

test('a keyword outside the closed set is found wherever it sits in a schema', () => {
  const nests = {
    'at the top': { oneOf: [] },
    'in properties': { properties: { a: { allOf: [] } } },
    'in anyOf': { anyOf: [{ type: 'string' }, { not: {} }] },
    'in items': { items: { patternProperties: {} } },
    'in additionalProperties': { additionalProperties: { if: {} } },
    'in propertyNames': { propertyNames: { contains: {} } },
    'in a definition': { $defs: { a: { dependentRequired: {} } }, $ref: '#/$defs/a' },
  };
  for (const [where, schema] of Object.entries(nests)) {
    assert.equal(unsupportedKeywords(schema).length, 1, where);
  }
  assert.deepEqual(unsupportedKeywords({ oneOf: [], not: {} }), ['not', 'oneOf']);
});

test('annotation keywords are not assertions and do not close the set', () => {
  const schema = {
    title: 't',
    description: 'd',
    default: 1,
    examples: [1],
    format: 'email',
    type: 'string',
  };
  assert.deepEqual(unsupportedKeywords(schema), []);
  assert.deepEqual(run(schema, 5), [' type']);
  assert.deepEqual(run(schema, 'text'), []);
});

test('validation refuses what it cannot judge instead of saying valid', () => {
  const refused = [
    [{ oneOf: [{}] }, 'oneOf'],
    [{ patternProperties: {} }, 'patternProperties'],
    [{ if: {} }, 'if'],
    [{ pattern: '^not-in-the-table$' }, 'pattern'],
    [{ $ref: 'https://example.com/schema.json' }, '$ref'],
    [{ $ref: '#/$defs/missing' }, '$ref'],
    [{ type: 'decimal' }, 'type'],
  ];
  for (const [schema, keyword] of refused) {
    assert.throws(
      () => validate(schema, schema, 'text', patterns),
      (error) => error instanceof UnsupportedKeyword && error.keyword === keyword,
      JSON.stringify(schema),
    );
  }
});

test('a field the block does not have is a mistake, not a pass', () => {
  assert.throws(() => validateField(block, 'no.such.field', 1, patterns), RangeError);
});

test('booleans are never numbers, and numbers are never booleans', () => {
  assert.deepEqual(run({ type: 'integer' }, true), [' type']);
  assert.deepEqual(run({ type: 'number' }, false), [' type']);
  assert.deepEqual(run({ type: 'boolean' }, 1), [' type']);
  assert.deepEqual(run({ enum: [1] }, true), [' enum']);
  assert.deepEqual(run({ enum: [true] }, 1), [' enum']);
  assert.deepEqual(run({ const: 0 }, false), [' const']);
  assert.deepEqual(run({ const: false }, 0), [' const']);
  assert.deepEqual(run({ minimum: 5 }, false), []);
  assert.deepEqual(run({ maximum: 0 }, true), []);
  assert.deepEqual(run({ enum: [[1, true]] }, [1, true]), []);
  assert.deepEqual(run({ enum: [[1, true]] }, [1, 1]), [' enum']);
});

test('an integer has no fraction, and an integral float is an integer', () => {
  assert.deepEqual(run({ type: 'integer' }, 2.5), [' type']);
  assert.deepEqual(run({ type: 'integer' }, 2), []);
  assert.deepEqual(run({ type: 'integer' }, 1e2), []);
  assert.deepEqual(run({ type: 'integer' }, Infinity), [' type']);
  assert.deepEqual(run({ type: ['integer', 'null'] }, null), []);
  assert.deepEqual(run({ type: ['integer', 'null'] }, 'x'), [' type']);
});

test('lengths count code points, not UTF-16 units', () => {
  assert.deepEqual(run({ maxLength: 1 }, EMOJI), []);
  assert.deepEqual(run({ minLength: 2 }, EMOJI), [' minLength']);
  // A letter with a combining accent is two code points; the precomposed letter is one.
  assert.deepEqual(run({ maxLength: 1 }, DECOMPOSED_E), [' maxLength']);
  assert.deepEqual(run({ maxLength: 1 }, PRECOMPOSED_E), []);
  assert.deepEqual(run({ minLength: 1 }, ''), [' minLength']);
});

test('numeric limits are inclusive except exclusiveMinimum', () => {
  assert.deepEqual(run({ minimum: 1 }, 1), []);
  assert.deepEqual(run({ minimum: 1 }, 0.5), [' minimum']);
  assert.deepEqual(run({ maximum: 1 }, 1), []);
  assert.deepEqual(run({ maximum: 1 }, 1.5), [' maximum']);
  assert.deepEqual(run({ exclusiveMinimum: 0 }, 0), [' exclusiveMinimum']);
  assert.deepEqual(run({ exclusiveMinimum: 0 }, 0.1), []);
  assert.deepEqual(run({ minItems: 1 }, []), [' minItems']);
  assert.deepEqual(run({ maxItems: 1 }, [1, 2]), [' maxItems']);
  assert.deepEqual(run({ maxItems: 1 }, [1]), []);
});

test('required names the missing keys, and additionalProperties the extra ones', () => {
  const needs = { required: ['a', 'b'] };
  assert.deepEqual(validate(needs, needs, { a: 1 }, patterns), [
    { pointer: '', keyword: 'required', detail: { missing: ['b'] } },
  ]);
  const closed = { properties: { a: {} }, additionalProperties: false };
  assert.deepEqual(validate(closed, closed, { a: 1, z: 2, y: 3 }, patterns), [
    { pointer: '', keyword: 'additionalProperties', detail: { extras: ['z', 'y'] } },
  ]);
  assert.deepEqual(run({ additionalProperties: {} }, { z: 1 }), []);
  assert.deepEqual(run({ additionalProperties: true }, { z: 1 }), []);
  assert.deepEqual(run({ additionalProperties: { type: 'string' } }, { z: 1 }), ['/z type']);
});

test('boolean subschemas: false refuses, true admits, and items false refuses any element', () => {
  assert.deepEqual(run({ properties: { a: false } }, { a: 1 }), ['/a false']);
  assert.deepEqual(run({ properties: { a: true } }, { a: 1 }), []);
  assert.deepEqual(run({ items: false }, []), []);
  assert.deepEqual(run({ items: false }, [1]), [' items']);
  assert.deepEqual(run({ items: true }, [1]), []);
  assert.deepEqual(run({ anyOf: [false, true] }, 1), []);
  assert.deepEqual(run({ anyOf: [false, false] }, 1), [' anyOf']);
});

test('anyOf reports one failure however many branches fail', () => {
  const schema = { anyOf: [{ type: 'string' }, { type: 'integer' }, { type: 'null' }] };
  assert.equal(validate(schema, schema, true, patterns).length, 1);
  assert.deepEqual(run(schema, 3), []);
});

test('propertyNames reports the inner keyword at the object', () => {
  const schema = { propertyNames: { pattern: '^[a-zA-Z][\\w-]+$' } };
  assert.deepEqual(run(schema, { good: 1, '1bad': 2 }), [' pattern']);
  assert.deepEqual(run(schema, { good: 1 }), []);
  assert.deepEqual(run({ propertyNames: { maxLength: 1 } }, { ab: 1, cd: 2 }), [' maxLength']);
});

test('a reference is followed, and its siblings are checked too', () => {
  const schema = { $defs: { n: { type: 'integer' } }, $ref: '#/$defs/n', maximum: 5, default: 3 };
  assert.deepEqual(run(schema, 7.5), [' maximum', ' type']);
  assert.deepEqual(run(schema, 4), []);
  const chain = { $defs: { a: { $ref: '#/$defs/b' }, b: { type: 'string' } }, $ref: '#/$defs/a' };
  assert.deepEqual(run(chain, 1), [' type']);
  assert.equal(resolveRef({ a: { 'b/c': { 'd~e': 7 } } }, '#/a/b~1c/d~0e'), 7);
});

test('a reference that never reaches a keyword stops instead of looping', () => {
  const loops = [
    { $defs: { a: { $ref: '#/$defs/b' }, b: { $ref: '#/$defs/a' } }, $ref: '#/$defs/a' },
    { $ref: '#' },
  ];
  for (const loop of loops) {
    assert.throws(() => validate(loop, loop, 1, patterns), UnsupportedKeyword);
  }
});

test('instance pointers escape slash and tilde, and number array indexes', () => {
  const schema = { additionalProperties: { items: { type: 'string' } } };
  assert.deepEqual(run(schema, { 'a/b~c': ['x', 1] }), ['/a~1b~0c/1 type']);
});

test('a pattern is a search, through the translation in the table', () => {
  const hex = { pattern: '^[0-9a-fA-F]{64}$' };
  assert.deepEqual(run(hex, 'x'.repeat(64)), [' pattern']);
  assert.deepEqual(run(hex, 'a'.repeat(64)), []);
  assert.deepEqual(run(hex, 5), []);
  assert.equal(patterns.size, Object.keys(block.patterns).length);
  for (const regex of patterns.values()) {
    assert.ok(regex instanceof RegExp);
  }
});
