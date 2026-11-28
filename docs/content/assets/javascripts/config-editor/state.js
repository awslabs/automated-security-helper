// The configuration editor's document state.
//
// The YAML text is the document. A form change is an edit (`set`, `delete` or
// `append` at a path); the writer proposes the new text, and the re-read gate
// reads that text again and compares it with what the edit meant, types and
// reference tokens included. A line patch that fails the gate, or that the writer
// cannot make, is retried by writing the smallest enclosing entry again; if that
// fails the gate too, nothing is written and the edit is refused.
//
// DOM-free. Imports only its siblings.

import { readYaml } from "./yaml-read.js";
import { applyToValue, formatPath, planPatch, planReemit, sameValue } from "./yaml-write.js";

function passesGate(text, intended) {
  const reread = readYaml(text);
  return reread.ok && sameValue(intended, reread.value);
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
 */
export function applyEdit(text, edit, options = {}) {
  const patch = options.patch ?? planPatch;
  const reemit = options.reemit ?? planReemit;
  const doc = options.doc ?? readYaml(text);
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
  const intended = applyToValue(doc.value, edit);
  if (first.ok && passesGate(first.text, intended)) {
    return { ok: true, how: "patch", text: first.text, droppedComments: first.droppedComments };
  }
  const second = reemit(doc, edit);
  if (!second.ok && second.final) {
    return refused(second.reason, second.message);
  }
  if (second.ok && passesGate(second.text, intended)) {
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
