// The editor's plugin-section spelling fold gives the answers ASH's fold gives.
//
// fixtures/spelling-vectors.json lists section keys and the declared section each one names,
// and whole mappings with the keys left after the fold or the two spellings that clash. A
// Python test runs ASH's own functions on the same file. Here the port runs on it, and the
// tests after the vectors pin the places a careless port goes wrong: lowering with
// toLowerCase, which reads more characters as equal than ASH does, and dropping the
// separators or the trailing type word in a way that changes which section a key names.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  asciiLower,
  declaredByFold,
  declaredTarget,
  foldSectionKeys,
  foldedSectionName,
} from '../content/assets/javascripts/config-editor/spelling.js';

const fixture = (name) =>
  JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));

const vectors = fixture('spelling-vectors.json');
const block = fixture('editor-data.json');

// Characters that toLowerCase folds onto an ASCII letter and ASH's lowering does not.
const KELVIN_SIGN = String.fromCodePoint(0x212a);
const LONG_S = String.fromCodePoint(0x17f);
const DOTTED_CAPITAL_I = String.fromCodePoint(0x130);

const declaredOf = (kind) => declaredByFold(vectors.canonical[kind]);

for (const [kind, text, expected] of vectors.targets) {
  test(`${kind}: ${JSON.stringify(text)} names ${expected ?? 'no section'}`, () => {
    assert.equal(declaredTarget(declaredOf(kind), text), expected);
  });
}

for (const item of vectors.sections) {
  test(`${item.kind}: the keys ${item.keys.join(', ')}`, () => {
    const result = foldSectionKeys(declaredOf(item.kind), item.keys);
    if (item.ambiguous === null) {
      assert.equal(result.ambiguous, null);
      assert.deepEqual([...result.keys].sort(), item.folded);
    } else {
      assert.deepEqual(result.ambiguous, item.ambiguous);
      assert.equal(result.keys, null);
    }
  });
}

test('the vectors in the data hold under the port', () => {
  const { canonical, vectors: own } = block.spelling;
  assert.ok(own.length > 0);
  for (const [kind, text, expected] of own) {
    assert.equal(declaredTarget(declaredByFold(canonical[kind]), text), expected, `${kind} ${text}`);
  }
});

test('lowering touches the ASCII capitals and nothing else', () => {
  assert.equal(asciiLower('ABC-xyz_09'), 'abc-xyz_09');
  for (const character of [KELVIN_SIGN, LONG_S, DOTTED_CAPITAL_I]) {
    assert.equal(asciiLower(character), character);
  }
  // The trap: toLowerCase and ASCII lowering disagree on these characters.
  assert.notEqual(KELVIN_SIGN.toLowerCase(), KELVIN_SIGN);
  assert.notEqual(DOTTED_CAPITAL_I.toLowerCase(), DOTTED_CAPITAL_I);
});

test('the fold drops case and the two separators, and keeps every other character', () => {
  assert.equal(foldedSectionName('Cdk_Nag--x'), 'cdknagx');
  assert.equal(foldedSectionName('a.b c'), 'a.b c');
  assert.equal(foldedSectionName('_-_'), '');
  assert.equal(foldedSectionName(`${LONG_S}emgrep`), `${LONG_S}emgrep`);
});

test('a type word must end the key as written and must leave something of the name', () => {
  const declared = declaredByFold(['bandit', 'csv']);
  assert.equal(declaredTarget(declared, 'banditScanner'), 'bandit');
  assert.equal(declaredTarget(declared, 'bandit-scanner'), 'bandit');
  assert.equal(declaredTarget(declared, 'csvReporter'), 'csv');
  assert.equal(declaredTarget(declared, 'bandit-scan_ner'), null);
  assert.equal(declaredTarget(declared, 'scanner'), null);
  assert.equal(declaredTarget(declared, 'banditscannerscanner'), null);
  assert.equal(declaredTarget(declared, 'scannerbandit'), null);
});

test('folding reports the variants it rewrote, and does not change its input', () => {
  const declared = declaredByFold(['bandit', 'cdk-nag']);
  const keys = ['Bandit', 'cdk-nag', 'mystery'];
  const result = foldSectionKeys(declared, keys);
  assert.deepEqual(result.variants, [{ key: 'Bandit', target: 'bandit' }]);
  assert.deepEqual([...result.keys].sort(), ['bandit', 'cdk-nag', 'mystery']);
  assert.deepEqual(keys, ['Bandit', 'cdk-nag', 'mystery']);
});

test('a declared spelling is never a variant of itself', () => {
  const declared = declaredByFold(['bandit']);
  const result = foldSectionKeys(declared, ['bandit']);
  assert.deepEqual(result.variants, []);
  assert.equal(result.ambiguous, null);
});
