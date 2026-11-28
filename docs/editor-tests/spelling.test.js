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
import * as spellingModule from '../content/assets/javascripts/config-editor/spelling.js';

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

// The fold of a whole section mapping, the merge of a variant into the declared section, and
// the pointer of each value in the file as written. The merges in the vectors are ASH's own.

for (const item of vectors.merges) {
  test(`${item.kind}: ${JSON.stringify(item.section)} is read as ${JSON.stringify(item.folded)}`, () => {
    const result = spellingModule.foldSection(declaredOf(item.kind), item.section);
    assert.equal(result.ambiguous, null);
    assert.deepEqual(result.section, item.folded);
  });
}

test('a variant and the declared spelling merge key by key, and the declared value wins', () => {
  const declared = declaredByFold(['bandit']);
  const section = {
    Bandit: { enabled: 'yes', options: { a: 1, b: 2 } },
    bandit: { enabled: true, options: { b: 3 } },
  };
  const result = spellingModule.foldSection(declared, section);
  assert.deepEqual(result.section, { bandit: { enabled: true, options: { a: 1, b: 3 } } });
  assert.deepEqual(result.variants, [{ key: 'Bandit', target: 'bandit' }]);
  // Neither side of the merge is changed.
  assert.deepEqual(section.Bandit, { enabled: 'yes', options: { a: 1, b: 2 } });
  assert.deepEqual(section.bandit, { enabled: true, options: { b: 3 } });
});

test('only mappings merge: anything else on either side is the declared value whole', () => {
  assert.deepEqual(spellingModule.mergedRaw({ a: 1 }, { b: 2 }), { a: 1, b: 2 });
  assert.equal(spellingModule.mergedRaw({ a: 1 }, 5), 5);
  assert.deepEqual(spellingModule.mergedRaw(5, { a: 1 }), { a: 1 });
  assert.deepEqual(spellingModule.mergedRaw([1, 2], [3]), [3]);
  assert.equal(spellingModule.mergedRaw({ a: 1 }, null), null);
});

test('a section that holds two spellings of one plugin is not folded', () => {
  const result = spellingModule.foldSection(declaredByFold(['bandit']), {
    BANDIT: { enabled: 'yes' },
    'ban-dit': {},
  });
  assert.equal(result.section, null);
  assert.deepEqual(result.ambiguous, { first: 'BANDIT', second: 'ban-dit', target: 'bandit' });
  assert.equal(result.written('/bandit/enabled'), '/bandit/enabled');
});

test('the pointer of a folded value is the pointer of the value where the file wrote it', () => {
  const declared = declaredByFold(['bandit', 'zizmor']);

  // A variant alone: everything under the declared name was written under the variant.
  const alone = spellingModule.foldSection(declared, { Bandit: { options: { x: 1 } }, zizmor: {} });
  assert.equal(alone.written('/bandit/options/x'), '/Bandit/options/x');
  assert.equal(alone.written('/bandit'), '/Bandit');
  assert.equal(alone.written('/zizmor/enabled'), '/zizmor/enabled');
  assert.equal(alone.written('/mystery'), '/mystery');
  assert.equal(alone.written(''), '');

  // A variant beside the declared spelling: each value is where it was written, and where
  // both wrote one the declared value is the one that counts.
  const merged = spellingModule.foldSection(declared, {
    Bandit: { only: 1, both: { v: 1, wins: 'v' }, scalar: 'v', 'a/b': 1 },
    bandit: { both: { d: 2, wins: 'd' }, scalar: 'd', extra: 3 },
  });
  assert.equal(merged.written('/bandit/only'), '/Bandit/only');
  assert.equal(merged.written('/bandit/both/v'), '/Bandit/both/v');
  assert.equal(merged.written('/bandit/both/d'), '/bandit/both/d');
  assert.equal(merged.written('/bandit/both/wins'), '/bandit/both/wins');
  assert.equal(merged.written('/bandit/scalar'), '/bandit/scalar');
  assert.equal(merged.written('/bandit/extra'), '/bandit/extra');
  assert.equal(merged.written('/bandit/a~1b'), '/Bandit/a~1b');
  assert.equal(merged.written('/bandit/both'), '/bandit/both');
  assert.equal(merged.written('/bandit'), '/bandit');

  // A value taken whole from the declared side is written where the declared side wrote it.
  const whole = spellingModule.foldSection(declared, {
    Bandit: { x: 5, y: { a: 1 } },
    bandit: { x: { a: 1 }, y: 5 },
  });
  assert.deepEqual(whole.section, { bandit: { x: { a: 1 }, y: 5 } });
  assert.equal(whole.written('/bandit/x/a'), '/bandit/x/a');
  assert.equal(whole.written('/bandit/y'), '/bandit/y');
});

test('a key named __proto__ is data to the fold: it is carried over, and nothing is polluted', () => {
  const section = JSON.parse('{"__proto__": {"polluted": true}, "Bandit": {"enabled": false}}');
  const result = spellingModule.foldSection(declaredByFold(['bandit']), section);
  assert.equal(Object.getPrototypeOf(result.section), Object.prototype);
  assert.deepEqual(Object.keys(result.section).sort(), ['__proto__', 'bandit']);
  assert.equal({}.polluted, undefined);
  assert.equal(result.written('/bandit/enabled'), '/Bandit/enabled');
});
