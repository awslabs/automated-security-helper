// Tests for the configuration editor's document state: edits through the re-read
// gate, and the history behind undo and redo.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { applyEdit, createState } from '../content/assets/javascripts/config-editor/state.js';
import { Reference } from '../content/assets/javascripts/config-editor/yaml-scalars.js';

const SET_A = { op: 'set', path: ['a'], value: 5 };

// A planner that proposes text which does not mean what the edit meant.
const writes = (text) => () => ({ ok: true, how: 'patch', text, droppedComments: 0 });

test('an edit that passes the gate is a patch', () => {
  assert.deepEqual(applyEdit('a: 1\nb: 2\n', SET_A), {
    ok: true,
    how: 'patch',
    text: 'a: 5\nb: 2\n',
    droppedComments: 0,
  });
});

test('an edit that changes nothing is reported as nothing', () => {
  assert.deepEqual(applyEdit('a: 1\n', { op: 'delete', path: ['x'] }), {
    ok: true,
    how: 'none',
    text: 'a: 1\n',
    droppedComments: 0,
  });
});

test('a shape a patch cannot handle is written again, and the status line says what it cost', () => {
  const result = applyEdit('list: [a, b] # note\nother: 1\n', { op: 'append', path: ['list'], value: 'c' });
  assert.equal(result.ok, true);
  assert.equal(result.how, 'reemit');
  assert.equal(result.text, 'list:\n  - a\n  - b\n  - c\nother: 1\n');
  assert.equal(result.droppedComments, 1);
  assert.equal(result.label, 'list');
  assert.equal(result.message, 'Comments inside list were not kept.');
  const plain = applyEdit('a: {x: 1}\n', { op: 'set', path: ['a', 'y'], value: 2 });
  assert.equal(plain.how, 'reemit');
  assert.equal(plain.message, 'a was written again in block style.');
});

test('an edit the editor will not make is refused with its reason and leaves the text alone', () => {
  const cases = [
    ['a repeated key', 'a: 1\na: 2\n', SET_A, 'duplicate-key'],
    ['a merge key', 'd:\n  <<: {x: 1}\n  y: 2\n', { op: 'set', path: ['d', 'y'], value: 3 }, 'merge-key'],
    ['an alias', 'a: &x 1\nb: *x\n', SET_A, 'unreadable'],
    ['text that does not parse', 'a: [\n', SET_A, 'unreadable'],
  ];
  for (const [name, text, edit, reason] of cases) {
    const result = applyEdit(text, edit);
    assert.equal(result.ok, false, name);
    assert.equal(result.how, 'refused', name);
    assert.equal(result.reason, reason, name);
    assert.equal(typeof result.message, 'string', name);
    assert.equal('text' in result, false, name);
  }
});

test('a patch that reads back as another value fails the gate and the entry is written again', () => {
  const result = applyEdit('a: 1\nb: 2\n', SET_A, { patch: writes('a: 6\nb: 2\n') });
  assert.equal(result.how, 'reemit');
  assert.equal(result.text, 'a: 5\nb: 2\n');
  assert.equal(result.label, 'a');
});

test('the gate compares types: the text 5 is not the number 5', () => {
  const result = applyEdit('a: 1\n', SET_A, { patch: writes('a: "5"\n') });
  assert.equal(result.how, 'reemit');
  assert.equal(result.text, 'a: 5\n');
});

test('the gate compares reference tokens: a quoted reference is text, a tagged one is the same reference', () => {
  const edit = { op: 'set', path: ['a'], value: new Reference('${HOME}', false) };
  const text = applyEdit('a: x\n', edit, { patch: writes('a: "${HOME}"\n') });
  assert.equal(text.how, 'reemit');
  assert.equal(text.text, 'a: ${HOME}\n');
  const tagged = applyEdit('a: x\n', edit, { patch: writes('a: !ENV ${HOME}\n') });
  assert.equal(tagged.how, 'patch');
  assert.equal(tagged.text, 'a: !ENV ${HOME}\n');
});

test('a patch that does not even parse fails the gate', () => {
  const result = applyEdit('a: 1\n', SET_A, { patch: writes('a: [\n') });
  assert.equal(result.how, 'reemit');
  assert.equal(result.text, 'a: 5\n');
});

test('when the text written again fails the gate too, nothing is offered and the field is named', () => {
  const wrong = writes('a: 6\n');
  const result = applyEdit('a: 1\n', SET_A, { patch: wrong, reemit: wrong });
  assert.equal(result.ok, false);
  assert.equal(result.how, 'refused');
  assert.equal(result.reason, 'gate');
  assert.match(result.message, /\ba\b/);
  assert.equal('text' in result, false);
});

test('a planner that cannot handle the edit passes it on', () => {
  const unsupported = () => ({ ok: false, final: false, reason: 'unsupported' });
  const result = applyEdit('a: 1\n', SET_A, { patch: unsupported });
  assert.equal(result.how, 'reemit');
  assert.equal(result.text, 'a: 5\n');
});

test('writing a flow mapping again keeps its floats floats', () => {
  const result = applyEdit('opts: {ratio: 1.0, list: [a]}\n', {
    op: 'append',
    path: ['opts', 'list'],
    value: 'b',
  });
  assert.equal(result.ok, true, result.message);
  assert.equal(result.how, 'reemit');
  assert.equal(result.text, 'opts:\n  ratio: 1.0\n  list:\n    - a\n    - b\n');
});

test('the gate tells an integer from a float', () => {
  // The patch writes the float 5.0 where the edit meant the integer 5.
  const patched = applyEdit('a: 1.0\n', SET_A, { patch: writes('a: 5.0\n') });
  assert.equal(patched.how, 'reemit');
  assert.equal(patched.text, 'a: 5\n');
  // A rewrite that turns a float into an integer in a place the edit did not name.
  const text = 'opts: {ratio: 1.0, list: [a]}\n';
  const edit = { op: 'append', path: ['opts', 'list'], value: 'b' };
  const wrong = writes('opts:\n  ratio: 1\n  list:\n    - a\n    - b\n');
  const result = applyEdit(text, edit, { reemit: wrong });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'gate');
});

test('a rewrite keeps the type of every key', () => {
  const edit = { op: 'set', path: ['m', 'z'], value: 1 };
  const cases = [
    ['an integer key', 'm: {1: a, l: x}\n', 'm:\n  1: a\n  l: x\n  z: 1\n'],
    ['null and boolean keys', 'm: {null: a, on: b, l: x}\n', 'm:\n  null: a\n  true: b\n  l: x\n  z: 1\n'],
    ['a float key', 'm: {1.5: a, l: x}\n', 'm:\n  1.5: a\n  l: x\n  z: 1\n'],
    ['an integer key and the text of it', 'm: {1: a, "1": b}\n', 'm:\n  1: a\n  "1": b\n  z: 1\n'],
  ];
  for (const [name, text, after] of cases) {
    const result = applyEdit(text, edit);
    assert.equal(result.how, 'reemit', name);
    assert.equal(result.text, after, name);
  }
});

test('the gate refuses a rewrite that turns a key into text', () => {
  const edit = { op: 'set', path: ['m', 'z'], value: 1 };
  const cases = [
    ['an integer key', 'm: {1: a, l: x}\n', 'm:\n  "1": a\n  l: x\n  z: 1\n'],
    ['a null key', 'm: {null: a, l: x}\n', 'm:\n  "null": a\n  l: x\n  z: 1\n'],
    ['a boolean key', 'm: {on: a, l: x}\n', 'm:\n  "on": a\n  l: x\n  z: 1\n'],
    ['a float key', 'm: {1.5: a, l: x}\n', 'm:\n  "1.5": a\n  l: x\n  z: 1\n'],
    ['one key where the file had two', 'm: {1: a, "1": b}\n', 'm:\n  "1": b\n  z: 1\n'],
  ];
  for (const [name, text, wrong] of cases) {
    const result = applyEdit(text, edit, { reemit: writes(wrong) });
    assert.equal(result.ok, false, name);
    assert.equal(result.reason, 'gate', name);
  }
});

test('the gate tells a reference key from the same text in quotes', () => {
  const text = 'opts:\n  ${KEY}: a\n  list: x\n';
  const edit = { op: 'set', path: ['opts', 'list'], value: 'y' };
  const result = applyEdit(text, edit, { patch: writes('opts:\n  "${KEY}": a\n  list: y\n') });
  assert.equal(result.how, 'reemit');
  assert.equal(result.text, 'opts:\n  ${KEY}: a\n  list: y\n');
});

test('a gate trip in a block-only path writes the entry again with its floats and escapes intact', () => {
  // A new key after a last block scalar that keeps its final blank line moves that line
  // into the scalar, so the patch fails the gate and the entry is written again.
  const text = 'scanners:\n  bandit:\n    ratio: 1.0\n    note: |+\n      text\n\nother: 1\n';
  const result = applyEdit(text, { op: 'set', path: ['scanners', 'bandit', 'extra'], value: 2 });
  assert.equal(result.how, 'reemit');
  assert.equal(result.label, 'scanners.bandit');
  assert.equal(
    result.text,
    'scanners:\n  bandit:\n    ratio: 1.0\n    note: "text\\n\\n"\n    extra: 2\n\nother: 1\n',
  );
});

test('the gate refuses a patch that loses a comment outside the entry it edits', () => {
  const text = 'a: 1 # keep this\nb: 2\n';
  const edit = { op: 'set', path: ['b'], value: 3 };
  const lossy = writes('a: 1\nb: 3\n');
  const result = applyEdit(text, edit, { patch: lossy });
  assert.equal(result.ok, true, result.message);
  assert.equal(result.how, 'reemit');
  assert.equal(result.text, 'a: 1 # keep this\nb: 3\n');
  const refused = applyEdit(text, edit, { patch: lossy, reemit: lossy });
  assert.equal(refused.ok, false);
  assert.equal(refused.reason, 'gate');
});

test('the gate refuses a rewrite that touches the lines of a neighbor of the entry it names', () => {
  const text = 'a:\n  - x: 1\n    y: 2\n  # next\n  - x: 3\n    y: 4\nb: [1]\n';
  const edit = { op: 'delete', path: ['a', 1, 'x'] };
  const wholeList = writes('a:\n  - x: 1\n    y: 2\n  - y: 4\nb: [1]\n');
  const result = applyEdit(text, edit, { patch: wholeList, reemit: wholeList });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'gate');
  const real = applyEdit(text, edit);
  assert.equal(real.how, 'patch');
  assert.equal(real.text, 'a:\n  - x: 1\n    y: 2\n  # next\n  - y: 4\nb: [1]\n');
  assert.equal(real.droppedComments, 0);
});

test('the gate refuses a delete that loses the comment line above the key that moves up', () => {
  const text = 'l:\n  - a: 1 # one\n    # about b\n    b: 2\n  - c: 3\n';
  const edit = { op: 'delete', path: ['l', 0, 'a'] };
  // The text a line patch once wrote: `# about b` belongs to the key that stays, and is gone.
  const result = applyEdit(text, edit, { patch: writes('l:\n  - b: 2\n  - c: 3\n') });
  assert.equal(result.ok, true, result.message);
  assert.equal(result.how, 'reemit');
  assert.equal(result.label, 'l[0]');
  assert.equal(result.droppedComments, 2);
  assert.equal(result.message, 'Comments inside l[0] were not kept.');
  const real = applyEdit(text, edit);
  assert.equal(real.how, 'patch');
  assert.equal(real.text, 'l:\n  - # about b\n    b: 2\n  - c: 3\n');
  assert.equal(real.droppedComments, 1);
});

test('the gate refuses a delete that loses a comment on the parent key or above the only child', () => {
  const edit = { op: 'delete', path: ['scanners', 'bandit', 'enabled'] };
  const onKey = 'scanners:\n  bandit: # keep bandit strict\n    enabled: false\n';
  const lostOnKey = applyEdit(onKey, edit, { patch: writes('scanners:\n  bandit: {}\n') });
  assert.equal(lostOnKey.how, 'reemit');
  assert.equal(lostOnKey.label, 'scanners.bandit');
  assert.equal(lostOnKey.droppedComments, 1);
  assert.equal(lostOnKey.message, 'Comments inside scanners.bandit were not kept.');
  const keptOnKey = applyEdit(onKey, edit);
  assert.equal(keptOnKey.how, 'patch');
  assert.equal(keptOnKey.text, 'scanners:\n  bandit: {} # keep bandit strict\n');
  const above = 'scanners:\n  bandit:\n    # about enabled\n    enabled: false\nother: 1\n';
  const lostAbove = applyEdit(above, edit, { patch: writes('scanners:\n  bandit: {}\nother: 1\n') });
  assert.equal(lostAbove.how, 'reemit');
  assert.equal(lostAbove.message, 'Comments inside scanners.bandit were not kept.');
  const keptAbove = applyEdit(above, edit);
  assert.equal(keptAbove.how, 'patch');
  assert.equal(keptAbove.text, 'scanners:\n  bandit: {}\n    # about enabled\nother: 1\n');
  const list = 'suppressions: # reviewed quarterly\n  - id: a\nother: 1\n';
  const last = { op: 'delete', path: ['suppressions', 0] };
  const lostOnList = applyEdit(list, last, { patch: writes('suppressions: []\nother: 1\n') });
  assert.equal(lostOnList.how, 'reemit');
  assert.equal(lostOnList.label, 'suppressions');
  const keptOnList = applyEdit(list, last);
  assert.equal(keptOnList.how, 'patch');
  assert.equal(keptOnList.text, 'suppressions: [] # reviewed quarterly\nother: 1\n');
});

test('the gate refuses a delete that also takes the comment line above the entry', () => {
  const text = 'g:\n  a: 1 # one\n  # about b\n  b: 2\n  c: 3\n';
  const edit = { op: 'delete', path: ['g', 'b'] };
  const result = applyEdit(text, edit, { patch: writes('g:\n  a: 1 # one\n  c: 3\n') });
  assert.equal(result.how, 'reemit');
  assert.equal(result.label, 'g');
  assert.equal(result.message, 'Comments inside g were not kept.');
  const real = applyEdit(text, edit);
  assert.equal(real.how, 'patch');
  assert.equal(real.text, 'g:\n  a: 1 # one\n  # about b\n  c: 3\n');
  assert.equal(real.droppedComments, 0);
});

test('the gate keeps every digit of an integer beyond 2**53', () => {
  const text = 'limit: 9007199254740993\nother: 1\n';
  const edit = { op: 'set', path: ['other'], value: 2 };
  // A patch that rounds the integer to the one a double holds, and one that writes it as
  // the float that a double holds.
  for (const rounded of ['limit: 9007199254740992\nother: 2\n', 'limit: 9007199254740993.0\nother: 2\n']) {
    const result = applyEdit(text, edit, { patch: writes(rounded) });
    assert.equal(result.ok, true, result.message);
    assert.equal(result.how, 'reemit', rounded);
    assert.equal(result.text, 'limit: 9007199254740993\nother: 2\n', rounded);
    const refused = applyEdit(text, edit, { patch: writes(rounded), reemit: writes(rounded) });
    assert.equal(refused.ok, false, rounded);
    assert.equal(refused.reason, 'gate', rounded);
  }
  const real = applyEdit(text, edit);
  assert.equal(real.how, 'patch');
  assert.equal(real.text, 'limit: 9007199254740993\nother: 2\n');
});

test('an edit of an integer beyond 2**53 writes every digit, and a plain number that large is refused', () => {
  const text = 'limit: 9007199254740993 # cap\nother: 1\n';
  const set = applyEdit(text, { op: 'set', path: ['limit'], value: 9007199254740995n });
  assert.equal(set.ok, true, set.message);
  assert.equal(set.how, 'patch');
  assert.equal(set.text, 'limit: 9007199254740995 # cap\nother: 1\n');
  // Its digits are gone before the edit arrives, so the editor does not write it.
  const lossy = applyEdit(text, { op: 'set', path: ['limit'], value: 2 ** 53 + 2 });
  assert.equal(lossy.ok, false);
  assert.equal(lossy.how, 'refused');
  assert.equal(lossy.reason, 'number');
  assert.equal(typeof lossy.message, 'string');
  assert.equal('text' in lossy, false);
  // A patch that makes the same mistake, a rounded integer written where the edit meant
  // the next one, fails the gate and is written again with every digit.
  const edit = { op: 'set', path: ['limit'], value: 9007199254740995n };
  const rounded = applyEdit(text, edit, { patch: writes('limit: 9007199254740994 # cap\nother: 1\n') });
  assert.equal(rounded.how, 'reemit');
  assert.equal(rounded.text, 'limit: 9007199254740995\nother: 1\n');
});

test('the state applies edits and steps back and forward through them', () => {
  const state = createState('a: 1\n');
  assert.equal(state.text, 'a: 1\n');
  assert.equal(state.canUndo, false);
  assert.equal(state.applyEdit({ op: 'set', path: ['a'], value: 2 }).ok, true);
  assert.equal(state.applyEdit({ op: 'set', path: ['b'], value: 3 }).ok, true);
  assert.equal(state.text, 'a: 2\nb: 3\n');
  assert.equal(state.undo(), true);
  assert.equal(state.text, 'a: 2\n');
  assert.equal(state.undo(), true);
  assert.equal(state.text, 'a: 1\n');
  assert.equal(state.undo(), false);
  assert.equal(state.redo(), true);
  assert.equal(state.text, 'a: 2\n');
  assert.equal(state.applyEdit({ op: 'set', path: ['c'], value: 4 }).ok, true);
  assert.equal(state.canRedo, false);
  assert.equal(state.redo(), false);
});

test('a refused edit and an edit that changes nothing add no step', () => {
  const refused = createState('a: 1\na: 2\n');
  assert.equal(refused.applyEdit(SET_A).ok, false);
  assert.equal(refused.canUndo, false);
  const same = createState('a: 1\n');
  assert.equal(same.applyEdit({ op: 'set', path: ['a'], value: 1 }).how, 'none');
  assert.equal(same.canUndo, false);
});

test('typing is one step while the pauses between changes stay short', () => {
  let clock = 0;
  const state = createState('x: 1\n', { now: () => clock });
  clock = 100;
  state.setText('x: 2\n', { group: 'type' });
  clock = 600;
  state.setText('x: 23\n', { group: 'type' });
  clock = 2000;
  state.setText('x: 234\n', { group: 'type' });
  assert.equal(state.text, 'x: 234\n');
  state.undo();
  assert.equal(state.text, 'x: 23\n');
  state.undo();
  assert.equal(state.text, 'x: 1\n');
  assert.equal(state.canUndo, false);
  state.redo();
  state.redo();
  assert.equal(state.text, 'x: 234\n');
});

test('a form edit ends a run of typing', () => {
  let clock = 0;
  const state = createState('x: 1\n', { now: () => clock });
  clock = 10;
  state.setText('x: 2\n', { group: 'type' });
  clock = 20;
  state.applyEdit({ op: 'set', path: ['y'], value: 1 });
  clock = 30;
  state.setText('x: 2\ny: 12\n', { group: 'type' });
  state.undo();
  assert.equal(state.text, 'x: 2\ny: 1\n');
});

test('the state keeps the last reading that succeeded while the text does not parse', () => {
  const state = createState('a: 1\n');
  state.setText('a: [\n');
  assert.equal(state.doc.ok, false);
  assert.equal(state.doc.refusal.code, 'syntax');
  assert.deepStrictEqual(state.lastGood.value, { a: 1 });
  state.setText('a: 2\n');
  assert.equal(state.doc.ok, true);
  assert.deepStrictEqual(state.lastGood.value, { a: 2 });
});

test('listeners hear about every change until they stop listening', () => {
  const state = createState('a: 1\n');
  let calls = 0;
  const stop = state.subscribe(() => {
    calls += 1;
  });
  state.applyEdit(SET_A);
  state.undo();
  stop();
  state.redo();
  assert.equal(calls, 2);
});

test('starting over forgets the history, and the history has a limit', () => {
  const state = createState('a: 1\n');
  state.applyEdit(SET_A);
  state.reset('z: 1\n');
  assert.equal(state.text, 'z: 1\n');
  assert.equal(state.canUndo, false);
  const short = createState('0', { limit: 3 });
  for (const text of ['1', '2', '3', '4']) {
    short.setText(text);
  }
  let steps = 0;
  while (short.undo()) {
    steps += 1;
  }
  assert.equal(steps, 2);
  assert.equal(short.text, '2');
});
