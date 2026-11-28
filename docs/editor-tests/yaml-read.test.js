// Tests for the configuration editor's YAML reader: the values it builds, the
// positions and styles it keeps for the patcher, and the inputs it refuses.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { MAX_BYTES, mappingPairs, readYaml } from '../content/assets/javascripts/config-editor/yaml-read.js';
import { Reference, Timestamp } from '../content/assets/javascripts/config-editor/yaml-scalars.js';

function read(text) {
  const doc = readYaml(text);
  assert.ok(doc.ok, `the reader refused: ${doc.refusal && doc.refusal.message}`);
  return doc;
}

function refusal(text) {
  const doc = readYaml(text);
  assert.equal(doc.ok, false, 'the reader read a text it should refuse');
  const { code, line, column } = doc.refusal;
  return { code, line, column };
}

test('a block document gives its offsets, lines, styles and indentation', () => {
  const text = "a: 1\nb:\n  - x\n  - y # why\nc: 'q'\n";
  const doc = read(text);
  assert.equal(doc.root.kind, 'map');
  assert.equal(doc.root.style, 'block');
  assert.equal(doc.root.indent, 0);
  const [a, b, c] = doc.root.entries;
  assert.equal(a.key.text, 'a');
  assert.equal(a.colon, 1);
  assert.equal(a.value.type, 'int');
  assert.equal(a.value.value, 1);
  assert.deepEqual([a.start, a.end], [0, 4]);
  assert.equal(b.value.kind, 'seq');
  assert.equal(b.value.indent, 2);
  assert.equal(b.value.items.length, 2);
  assert.deepEqual(
    b.value.items.map((item) => [item.text, item.dash, item.dashEnd, item.dashColumn]),
    [
      ['x', 10, 11, 2],
      ['y', 16, 17, 2],
    ],
  );
  assert.equal(b.end, 19);
  assert.equal(c.value.style, 'single');
  assert.equal(text.slice(c.value.start, c.value.end), "'q'");
  assert.equal(c.value.text, 'q');
  assert.deepEqual(doc.lineStarts, [0, 5, 8, 14, 26, 33]);
  assert.equal(doc.newline, '\n');
  assert.deepEqual(doc.style, { indent: 2, seq: 'indented' });
});

test('every comment is recorded with its range, the modeline and block scalar headers included', () => {
  const text = '# yaml-language-server: $schema=x\na: 1 # one\nb: |  # block\n  t\n';
  const doc = read(text);
  assert.deepEqual(
    doc.comments.map((comment) => text.slice(comment.start, comment.end)),
    ['# yaml-language-server: $schema=x', '# one', '# block'],
  );
  assert.deepEqual(
    doc.comments.map((comment) => comment.line),
    [0, 1, 2],
  );
});

test('plain scalars are typed as ASH reads them and references stay tokens', () => {
  const doc = read(
    'n: 3\nf: 1.5\nb: yes\nz: ~\ns: text\nd: 2026-12-31\nr: ${HOME:x}\nq: !ENV ${A}\n',
  );
  const { value } = doc;
  assert.equal(value.n, 3);
  assert.equal(value.f, 1.5);
  assert.equal(value.b, true);
  assert.equal(value.z, null);
  assert.equal(value.s, 'text');
  assert.ok(value.d instanceof Timestamp);
  assert.equal(value.d.iso, '2026-12-31');
  assert.ok(value.r instanceof Reference);
  assert.equal(value.r.text, '${HOME:x}');
  assert.equal(value.r.explicit, false);
  assert.ok(value.q instanceof Reference);
  assert.equal(value.q.text, '${A}');
  assert.equal(value.q.explicit, true);
});

test('flow collections are read, and keep their style', () => {
  const doc = read('a: [1, two, {k: v}]\nb: {x: 1, y: [2, 3]}\n');
  assert.deepStrictEqual(doc.value, { a: [1, 'two', { k: 'v' }], b: { x: 1, y: [2, 3] } });
  const [a, b] = doc.root.entries;
  assert.equal(a.value.style, 'flow');
  assert.equal(a.value.items.length, 3);
  assert.equal(b.value.style, 'flow');
  assert.equal(doc.text.slice(b.value.start, b.value.end), '{x: 1, y: [2, 3]}');
});

test('block scalars end at their last content line', () => {
  const text = 'a: |\n  one\n  two\nb: >-\n  x\n  y\nc: |+\n  z\n\nd: 1\n';
  const doc = read(text);
  assert.deepStrictEqual(doc.value, { a: 'one\ntwo\n', b: 'x y', c: 'z\n\n', d: 1 });
  const [a, b, c] = doc.root.entries;
  assert.equal(text.slice(a.value.start, a.value.end), '|\n  one\n  two');
  assert.equal(text.slice(b.value.start, b.value.end), '>-\n  x\n  y');
  assert.equal(text.slice(c.value.start, c.value.end), '|+\n  z');
  assert.equal(a.value.style, 'literal');
  assert.equal(b.value.style, 'folded');
});

test('quoted and multi-line scalars are folded and unescaped as PyYAML does', () => {
  const doc = read('a: "t\\tab \\x41"\nb: \'it\'\'s\'\nc: one\n  two\n\n  three\n');
  assert.deepStrictEqual(doc.value, { a: 't\tab A', b: "it's", c: 'one two\nthree' });
});

test('an anchor nothing uses is kept on the node, and an empty tagged value is read', () => {
  const doc = read('a: &x 1\nb: 2\nc: !!str\nd: !ENV\n');
  assert.equal(doc.root.entries[0].value.anchor, 'x');
  assert.equal(doc.text.slice(doc.root.entries[0].value.start, doc.root.entries[0].value.end), '&x 1');
  assert.equal(doc.value.a, 1);
  assert.equal(doc.value.c, '');
  assert.ok(doc.value.d instanceof Reference);
  assert.equal(doc.value.d.text, '');
  assert.equal(doc.value.d.explicit, true);
});

test('the indentation unit, the list style and the line ending are detected', () => {
  assert.equal(read('a:\n    b: 1\n').style.indent, 4);
  const indentless = read('list:\n- a\n- b\n');
  assert.equal(indentless.style.seq, 'indentless');
  const list = indentless.root.entries[0].value;
  assert.equal(list.indent, 0);
  assert.equal(list.indentless, true);
  assert.equal(list.items[0].dashColumn, 0);
  const crlf = read('a: 1\r\nb: 2\r\n');
  assert.equal(crlf.newline, '\r\n');
  assert.deepStrictEqual(crlf.value, { a: 1, b: 2 });
  assert.deepEqual(crlf.lineStarts, [0, 6, 12]);
  assert.equal(crlf.root.entries[0].end, 4);
});

test('a repeated key keeps the last value, warns, and locks both entries', () => {
  const doc = read('a: 1\nb: 2\na: 3\n');
  assert.deepStrictEqual(doc.value, { a: 3, b: 2 });
  assert.equal(doc.warnings.length, 1);
  assert.equal(doc.warnings[0].code, 'duplicate-key');
  assert.equal(doc.warnings[0].line, 3);
  assert.equal(doc.warnings[0].firstLine, 1);
  const [first, second, third] = doc.root.entries;
  assert.equal(first.locked, 'duplicate-key');
  assert.equal(third.locked, 'duplicate-key');
  assert.equal(second.locked, undefined);
});

test('a merge key puts its pairs first, and locks the mapping that holds it', () => {
  const doc = read('d:\n  <<: {x: 9}\n  z: 3\n');
  assert.deepStrictEqual(doc.value, { d: { x: 9, z: 3 } });
  assert.equal(doc.root.entries[0].value.locked, 'merge-key');
  assert.equal(doc.warnings.length, 1);
  assert.equal(doc.warnings[0].code, 'merge-key');
  assert.match(doc.warnings[0].message, /the keys x come from a merge key/);
  assert.equal(doc.warnings[0].line, 2);
  const list = read('d:\n  <<: [{x: 1}, {x: 2, y: 3}]\n');
  assert.deepStrictEqual(list.value, { d: { x: 1, y: 3 } });
  const pairs = mappingPairs(doc.root.entries[0].value, () => {
    throw new Error('no failure expected');
  });
  assert.deepEqual(
    pairs.map(([key]) => key.text),
    ['x', 'z'],
  );
});

test('an equals sign is a key as text, and a refusal as a value', () => {
  assert.deepStrictEqual(read('=: 1\n').value, { '=': 1 });
  assert.deepEqual(refusal('a: =\n'), { code: 'constructor', line: 1, column: 4 });
});

test('a key called __proto__ is data and changes nothing else', () => {
  const doc = read('__proto__: 1\nb: 2\n');
  assert.equal(Object.keys(doc.value).length, 2);
  assert.equal(Object.getPrototypeOf(doc.value), Object.prototype);
  assert.equal(doc.value.polluted, undefined);
});

test('the empty and comment-only documents have no root', () => {
  for (const text of ['', '# only a comment\n', '\n\n  \n', '---\n']) {
    const doc = read(text);
    assert.equal(doc.root, null, JSON.stringify(text));
    assert.equal(doc.value, null, JSON.stringify(text));
  }
});

test('an alias is refused where it is written, in ASH words', () => {
  const doc = readYaml('a: &x 1\nb: *x\n');
  assert.equal(doc.ok, false);
  assert.deepEqual(
    { code: doc.refusal.code, line: doc.refusal.line, column: doc.refusal.column },
    { code: 'alias', line: 2, column: 4 },
  );
  assert.match(doc.refusal.message, /ASH configuration does not accept YAML aliases/);
});

test('an anchor written twice is refused at its second writing, as PyYAML refuses it', () => {
  const cases = [
    ['two scalars', 'a: &x 1\nb: &x 2\n', { code: 'anchor', line: 2, column: 4 }],
    ['two collections', 'a: &x {k: 1}\nb: &x [1]\n', { code: 'anchor', line: 2, column: 4 }],
    ['a scalar and a list item', 'a: &x 1\nl:\n  - &x 2\n', { code: 'anchor', line: 3, column: 5 }],
    ['an anchor after a tag', 'a: &x 1\nb: !!str &x two\n', { code: 'anchor', line: 2, column: 4 }],
    ['a tag before an anchor', 'a: !!str &x one\nb: &x 2\n', { code: 'anchor', line: 2, column: 4 }],
  ];
  for (const [name, text, expected] of cases) {
    assert.deepEqual(refusal(text), expected, name);
  }
  assert.match(readYaml('a: &x 1\nb: &x 2\n').refusal.message, /found duplicate anchor 'x'/);
  // Different names, and the same name in a text that is not a second writing, read as before.
  assert.ok(readYaml('a: &x 1\nb: &y 2\n').ok);
  assert.ok(readYaml('a: "&x"\nb: &x 2\n').ok);
});

test('the inputs the editor will not read are refused with a code, a line and a column', () => {
  const cases = [
    ['a second document', 'a: 1\n---\nb: 2\n', { code: 'second-document', line: 2, column: 1 }],
    ['an unknown tag', 'a: !custom x\n', { code: 'tag', line: 1, column: 4 }],
    ['a complex key', '? a\n: b\n', { code: 'complex-key', line: 1, column: 1 }],
    ['a directive', '%YAML 1.2\n---\na: 1\n', { code: 'directive', line: 1, column: 1 }],
    ['a tab for indentation', 'a:\n\tb: 1\n', { code: 'tab', line: 2, column: 1 }],
    ['a control character', `a: 1\n${String.fromCharCode(0)}`, { code: 'character', line: 2, column: 1 }],
    ['a merge of a scalar', 'a:\n  <<: 5\n', { code: 'merge', line: 2, column: 7 }],
    ['an unclosed flow sequence', 'a: [1, 2\n', { code: 'syntax', line: 2, column: 1 }],
  ];
  for (const [name, text, expected] of cases) {
    assert.deepEqual(refusal(text), expected, name);
  }
});

test('a text over 2 MiB is refused before it is read', () => {
  const big = `a: ${'x'.repeat(MAX_BYTES)}`;
  assert.deepEqual(refusal(big), { code: 'too-large', line: 1, column: 1 });
  assert.ok(readYaml(`a: ${'x'.repeat(1000)}`).ok);
});

test('a column counts characters, not UTF-16 units', () => {
  const emoji = String.fromCodePoint(0x1f600);
  assert.deepEqual(refusal(`[${emoji}, *x]`), { code: 'alias', line: 1, column: 5 });
});

test('a refusal leaves no nodes behind', () => {
  const doc = readYaml('a: &x 1\nb: *x\n');
  assert.equal(doc.root, null);
  assert.equal(doc.value, undefined);
});
