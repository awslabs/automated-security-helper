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
