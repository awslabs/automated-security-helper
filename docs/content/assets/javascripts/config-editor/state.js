// The configuration editor's document state.
//
// The YAML text is the document. A form change is an edit (`set`, `delete` or
// `append` at a path); the writer proposes the new text, and the re-read gate
// reads that text again and checks two things.
//
// - The typed tree of the new text is the typed tree of the old text with the edit
//   applied: every integer, float, string, boolean, null, date and reference as ASH's
//   loader builds it, every mapping key by what it resolves to (the key 1, the key
//   "1", null and `on` are four keys), and every list and mapping in full.
// - Every byte outside the part of the text the edit may reach is as it was, comments
//   included. A line patch may reach the lines of the smallest block that holds the edit
//   (see `patchBound` in yaml-write.js); a delete reaches only the deleted entry's own
//   lines, the line it pulls up beside a dash, and the empty `{}` or `[]` it leaves after
//   the key of its parent, or, for the only entry of the whole file, only that entry's own
//   text, which the `{}` or `[]` takes the place of. An entry written again may reach the
//   lines of that entry or list item (see `editBound`).
//
// A line patch that fails the gate, or that the writer cannot make, is retried by
// writing the smallest block that holds the edit again; if that fails the gate too,
// nothing is written and the edit is refused.
//
// DOM-free. Imports only its siblings.

import { readYaml } from "./yaml-read.js";
import {
  applyToValue,
  editBound,
  formatPath,
  lineBreakProblem,
  patchBound,
  planPatch,
  planReemit,
  sameValue,
} from "./yaml-write.js";

// Whether the new text differs from the old one only inside the windows: the spans
// `[from, to]` of the old text that the edit may change, in order. The text before the
// first window, the text between two windows and the text after the last one must all
// still be there, in that order. No windows (null) means the edit may reach the whole file.
function unchangedOutside(before, after, windows) {
  if (windows === null) {
    return true;
  }
  const pieces = [];
  let from = 0;
  for (const [start, end] of windows) {
    pieces.push(before.slice(from, start));
    from = end;
  }
  pieces.push(before.slice(from));
  const head = pieces[0];
  const tail = pieces[pieces.length - 1];
  if (after.length < head.length + tail.length || !after.startsWith(head) || !after.endsWith(tail)) {
    return false;
  }
  let at = head.length;
  const limit = after.length - tail.length;
  for (const piece of pieces.slice(1, -1)) {
    const found = after.indexOf(piece, at);
    if (found === -1 || found + piece.length > limit) {
      return false;
    }
    at = found + piece.length;
  }
  return true;
}

function passesGate(before, text, intended, windows) {
  const reread = readYaml(text);
  return reread.ok && sameValue(intended, reread.typed) && unchangedOutside(before, text, windows);
}

function refused(reason, message) {
  return { ok: false, how: "refused", reason, message };
}

/**
 * Applies one edit to YAML text: `{op: "set" | "delete" | "append", path, value}`.
 * The result is `{ok: true, how, text, droppedComments}` where how is "patch",
 * "reemit" (with `label` and `message` saying which entry was written again and
 * what that cost) or "none" (the text does not change), or
 * `{ok: false, how: "refused", reason, message}` and the text stays as it was.
 *
 * `options.doc` is the text already read; `options.patch` and `options.reemit`
 * replace the writer's two planners, which is how the tests plant a wrong patch.
 *
 * A file whose lines break at a character the writer's line arithmetic does not see
 * (a lone carriage return, a next-line, line-separator or paragraph-separator character)
 * is refused for every edit, before either planner runs: what an edit may reach is
 * measured in lines, and there the file would count as one.
 */
export function applyEdit(text, edit, options = {}) {
  const patch = options.patch ?? planPatch;
  const reemit = options.reemit ?? planReemit;
  const doc = options.doc ?? readYaml(text);
  const lineBreaks = lineBreakProblem(doc);
  if (lineBreaks !== null) {
    return refused(lineBreaks.reason, lineBreaks.message);
  }
  const first = patch(doc, edit);
  if (!first.ok && first.final) {
    return refused(first.reason, first.message);
  }
  if (first.ok && first.how === "none") {
    return { ok: true, how: "none", text, droppedComments: 0 };
  }
  if (!doc.ok) {
    return refused("unreadable", "The YAML cannot be read, so the form leaves it alone.");
  }
  const intended = applyToValue(doc.typed, edit);
  if (first.ok && passesGate(text, first.text, intended, patchBound(doc, edit))) {
    return { ok: true, how: "patch", text: first.text, droppedComments: first.droppedComments };
  }
  const second = reemit(doc, edit);
  if (!second.ok && second.final) {
    return refused(second.reason, second.message);
  }
  const block = editBound(doc, edit);
  if (second.ok && passesGate(text, second.text, intended, block === null ? null : [block])) {
    const kept = second.droppedComments === 0;
    return {
      ok: true,
      how: "reemit",
      text: second.text,
      droppedComments: second.droppedComments,
      label: second.label,
      message: kept
        ? `${second.label} was written again in block style.`
        : `Comments inside ${second.label} were not kept.`,
    };
  }
  return refused(
    "gate",
    `The editor could not change ${formatPath(edit.path)} without risking a different meaning, so nothing was written.`,
  );
}

/**
 * The document the page works on: the current text, its reading, and a history
 * of text snapshots for undo and redo. A form edit is one step. Typing in the
 * YAML pane (`setText` with a `group`) is one step while the pauses between
 * changes stay within `groupMs`.
 */
export function createState(initialText = "", options = {}) {
  const now = options.now ?? Date.now;
  const groupMs = options.groupMs ?? 1000;
  const limit = options.limit ?? 200;
  const listeners = new Set();
  let snapshots = [{ text: initialText, group: null, at: 0 }];
  let position = 0;
  let cached = null;
  let lastGood = null;

  const current = () => snapshots[position];

  // Function declarations are hoisted, so `read` and `changed` can be used above.
  read();

  function read() {
    const { text } = current();
    if (cached === null || cached.text !== text) {
      cached = { text, doc: readYaml(text) };
      if (cached.doc.ok) {
        lastGood = cached.doc;
      }
    }
    return cached.doc;
  }

  function notify() {
    for (const listener of listeners) {
      listener();
    }
  }

  function push(text, group) {
    const top = current();
    const at = now();
    const sameRun =
      group !== null &&
      top.group === group &&
      position === snapshots.length - 1 &&
      at - top.at <= groupMs;
    if (sameRun) {
      snapshots[position] = { text, group, at };
    } else {
      snapshots = snapshots.slice(0, position + 1);
      snapshots.push({ text, group, at });
      if (snapshots.length > limit) {
        snapshots.shift();
      }
      position = snapshots.length - 1;
    }
    changed();
  }

  // Every text is read as soon as it becomes the current one, so that the last
  // reading that succeeded is always known.
  function changed() {
    read();
    notify();
  }

  return {
    get text() {
      return current().text;
    },
    /** The reading of the current text (check `ok`). */
    get doc() {
      return read();
    },
    /** The latest reading that succeeded, or null if none has. */
    get lastGood() {
      read();
      return lastGood;
    },
    get canUndo() {
      return position > 0;
    },
    get canRedo() {
      return position < snapshots.length - 1;
    },
    applyEdit(edit) {
      const result = applyEdit(current().text, edit, { doc: read() });
      if (result.ok && result.how !== "none") {
        push(result.text, null);
      }
      return result;
    },
    setText(text, { group = null } = {}) {
      if (text !== current().text) {
        push(text, group);
      }
    },
    /** Starts over from a text, forgetting the history. */
    reset(text) {
      snapshots = [{ text, group: null, at: 0 }];
      position = 0;
      cached = null;
      lastGood = null;
      changed();
    },
    undo() {
      if (position === 0) {
        return false;
      }
      position -= 1;
      changed();
      return true;
    },
    redo() {
      if (position === snapshots.length - 1) {
        return false;
      }
      position += 1;
      changed();
      return true;
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}
