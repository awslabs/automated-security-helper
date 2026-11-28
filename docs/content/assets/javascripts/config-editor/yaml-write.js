// The configuration editor's YAML writer.
//
// An edit to the form becomes the smallest change to the text: one scalar
// replaced, a key inserted after its siblings, an entry's own lines removed, a
// list item appended. Comments, quoting, indentation, line endings and the final
// newline stay as the file had them. Where a change cannot be made line by line
// (inside a flow collection, or when the patch would not read back as intended),
// the smallest enclosing entry is written again in block style and the caller
// is told how many comments that dropped.
//
// This module only proposes text. Reading the text back and comparing it with
// what the edit meant is the caller's job (state.js).
//
// DOM-free. Imports only its siblings.

import {
  Reference,
  Timestamp,
  matchReference,
  plainSafe,
  plainSyntaxOk,
  quoteDouble,
  quoteSingle,
} from "./yaml-scalars.js";

// Values.

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !(value instanceof Reference) &&
    !(value instanceof Timestamp)
  );
}

function isCollection(value) {
  return Array.isArray(value) || isPlainObject(value);
}

function isEmptyCollection(value) {
  return Array.isArray(value) ? value.length === 0 : Object.keys(value).length === 0;
}

function own(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key) ? object[key] : undefined;
}

function define(object, key, value) {
  Object.defineProperty(object, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

function copyObject(object) {
  const copy = {};
  for (const key of Object.keys(object)) {
    define(copy, key, object[key]);
  }
  return copy;
}

function getAt(node, path) {
  let current = node;
  for (const step of path) {
    if (typeof step === "number") {
      if (!Array.isArray(current) || step >= current.length) {
        return undefined;
      }
      current = current[step];
    } else {
      if (!isPlainObject(current) || own(current, step) === undefined) {
        return undefined;
      }
      current = own(current, step);
    }
  }
  return current;
}

function setAt(node, path, value) {
  if (path.length === 0) {
    return value;
  }
  const [head, ...rest] = path;
  if (typeof head === "number") {
    const items = Array.isArray(node) ? [...node] : [];
    items[head] = setAt(items[head], rest, value);
    return items;
  }
  const mapping = isPlainObject(node) ? copyObject(node) : {};
  define(mapping, head, setAt(own(mapping, head), rest, value));
  return mapping;
}

function deleteAt(node, path) {
  const [head, ...rest] = path;
  if (typeof head === "number") {
    if (!Array.isArray(node) || head >= node.length) {
      return node;
    }
    const items = [...node];
    if (rest.length > 0) {
      items[head] = deleteAt(items[head], rest);
    } else {
      items.splice(head, 1);
    }
    return items;
  }
  if (!isPlainObject(node) || own(node, head) === undefined) {
    return node;
  }
  const mapping = copyObject(node);
  if (rest.length > 0) {
    define(mapping, head, deleteAt(own(mapping, head), rest));
  } else {
    delete mapping[head];
  }
  return mapping;
}

/**
 * The data an edit means, as a new value tree: the document's value with the edit
 * applied. `set` replaces (creating what is missing on the way), `delete` removes
 * (a missing path changes nothing) and `append` adds to a list (a missing or
 * non-list value becomes a one-item list).
 */
export function applyToValue(root, edit) {
  const { op, path } = edit;
  if (op === "set") {
    return setAt(root, path, edit.value);
  }
  if (op === "delete") {
    return deleteAt(root, path);
  }
  if (op === "append") {
    const current = getAt(root, path);
    return setAt(root, path, [...(Array.isArray(current) ? current : []), edit.value]);
  }
  throw new TypeError(`unknown edit operation ${op}`);
}

/**
 * Whether two value trees mean the same: types and reference tokens included.
 * A reference counts by its text, so the plain and the tagged form of one
 * reference are the same.
 */
export function sameValue(expected, actual) {
  if (expected instanceof Reference || actual instanceof Reference) {
    return (
      expected instanceof Reference && actual instanceof Reference && expected.text === actual.text
    );
  }
  if (expected instanceof Timestamp || actual instanceof Timestamp) {
    return (
      expected instanceof Timestamp &&
      actual instanceof Timestamp &&
      expected.kind === actual.kind &&
      expected.iso === actual.iso
    );
  }
  if (Array.isArray(expected) || Array.isArray(actual)) {
    return (
      Array.isArray(expected) &&
      Array.isArray(actual) &&
      expected.length === actual.length &&
      expected.every((item, index) => sameValue(item, actual[index]))
    );
  }
  if (isPlainObject(expected) || isPlainObject(actual)) {
    if (!isPlainObject(expected) || !isPlainObject(actual)) {
      return false;
    }
    const keys = Object.keys(expected);
    return (
      keys.length === Object.keys(actual).length &&
      keys.every((key) => own(actual, key) !== undefined && sameValue(expected[key], actual[key]))
    );
  }
  if (typeof expected === "number" && typeof actual === "number") {
    return Object.is(expected, actual);
  }
  return expected === actual;
}

/** A path as people write it: `scanners.bandit.options` and `items[0].name`. */
export function formatPath(path) {
  let text = "";
  for (const step of path) {
    if (typeof step === "number") {
      text += `[${step}]`;
    } else {
      text += text === "" ? step : `.${step}`;
    }
  }
  return text;
}

// Writing scalars.

/** A number as a YAML scalar that ASH's loader reads back as the same number. */
export function formatNumber(number) {
  if (typeof number === "bigint") {
    return number.toString();
  }
  if (Number.isNaN(number)) {
    return ".nan";
  }
  if (number === Infinity) {
    return ".inf";
  }
  if (number === -Infinity) {
    return "-.inf";
  }
  if (Object.is(number, -0)) {
    return "-0.0";
  }
  if (Number.isInteger(number)) {
    return BigInt(number).toString();
  }
  const text = String(number);
  // YAML 1.1 wants a dot before an exponent: 1e-7 is text, 1.0e-7 is a float.
  return text.includes("e") && !text.includes(".") ? text.replace("e", ".0e") : text;
}

/**
 * A string as a scalar: plain only when ASH's loader and a YAML 1.2 reader both
 * read the plain form as the same string, otherwise quoted. `preferred` keeps
 * the quote style the old value had ("single" or "double") where it can.
 */
export function formatString(text, preferred = null, inFlow = false) {
  if (preferred === "single") {
    return quoteSingle(text) ?? quoteDouble(text);
  }
  if (preferred === "double") {
    return quoteDouble(text);
  }
  return plainSafe(text, inFlow) ? text : quoteDouble(text);
}

function formatReference(reference, inFlow) {
  const text = reference.text;
  if (
    !reference.explicit &&
    !inFlow &&
    plainSyntaxOk(text) &&
    matchReference(text) !== null
  ) {
    return text;
  }
  return `!ENV ${!inFlow && plainSyntaxOk(text) ? text : quoteDouble(text)}`;
}

/** A null, boolean, number, string, reference or date as the text of a scalar. */
export function formatScalar(value, options = {}) {
  const { preferred = null, inFlow = false } = options;
  if (value === null || value === undefined) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number" || typeof value === "bigint") {
    return formatNumber(value);
  }
  if (typeof value === "string") {
    return formatString(value, preferred, inFlow);
  }
  if (value instanceof Reference) {
    return formatReference(value, inFlow);
  }
  if (value instanceof Timestamp) {
    return value.iso;
  }
  throw new TypeError("the value is not a scalar");
}

function formatInline(value, preferred = null) {
  if (Array.isArray(value)) {
    return "[]";
  }
  if (isPlainObject(value)) {
    return "{}";
  }
  return formatScalar(value, { preferred });
}

function formatKey(key) {
  return plainSafe(key) ? key : quoteDouble(key);
}

// Writing blocks.

function orderedKeys(object, order) {
  const keys = Object.keys(object);
  if (!order) {
    return keys;
  }
  const known = order.filter((key) => keys.includes(key));
  return [...known, ...keys.filter((key) => !known.includes(key))];
}

function entryLines(head, value, indent, context) {
  if (isCollection(value) && !isEmptyCollection(value)) {
    const childIndent =
      Array.isArray(value) && context.seq === "indentless" ? indent : indent + context.unit;
    return [head, ...blockLines(value, childIndent, { ...context, order: null })];
  }
  return [`${head} ${formatInline(value)}`];
}

function mapLines(object, indent, context) {
  const pad = " ".repeat(indent);
  const lines = [];
  for (const key of orderedKeys(object, context.order)) {
    lines.push(...entryLines(`${pad}${formatKey(key)}:`, object[key], indent, context));
  }
  return lines;
}

function seqItemLines(item, dashColumn, context) {
  const pad = " ".repeat(dashColumn);
  if (isCollection(item) && !isEmptyCollection(item)) {
    const inner = blockLines(item, dashColumn + 2, context);
    inner[0] = `${pad}- ${inner[0].slice(dashColumn + 2)}`;
    return inner;
  }
  return [`${pad}- ${formatInline(item)}`];
}

function blockLines(value, indent, context) {
  if (Array.isArray(value)) {
    const inner = { ...context, order: null };
    return value.flatMap((item) => seqItemLines(item, indent, inner));
  }
  return mapLines(value, indent, context);
}

/**
 * A value as block-style YAML text, without a final newline. A scalar or an empty
 * collection is one line; `indent` is the column the first line starts at.
 */
export function emitBlock(value, options = {}) {
  const { indent = 0, unit = 2, seq = "indented", newline = "\n" } = options;
  if (!isCollection(value) || isEmptyCollection(value)) {
    return formatInline(value);
  }
  return blockLines(value, indent, { unit, seq, order: null }).join(newline);
}

/**
 * The text of a new configuration file: the schema comment line the caller
 * passes, then `project_name`, and nothing else; unset defaults are never written.
 */
export function newDocumentText(options = {}) {
  const { modeline = "", projectName = null, newline = "\n" } = options;
  const lines = [];
  if (modeline !== "") {
    lines.push(modeline.startsWith("#") ? modeline : `# ${modeline}`);
  }
  if (projectName !== null && projectName !== undefined) {
    lines.push(`project_name: ${formatString(projectName)}`);
  }
  return lines.length === 0 ? "" : lines.join(newline) + newline;
}

// Text positions.

function lineStartOf(text, index) {
  return index === 0 ? 0 : text.lastIndexOf("\n", index - 1) + 1;
}

function lineEndOf(text, index) {
  const at = text.indexOf("\n", index);
  if (at === -1) {
    return text.length;
  }
  return at > 0 && text[at - 1] === "\r" ? at - 1 : at;
}

function breakLengthAt(text, index) {
  if (text.startsWith("\r\n", index)) {
    return 2;
  }
  return text[index] === "\n" ? 1 : 0;
}

function splice(text, from, to, insert) {
  return text.slice(0, from) + insert + text.slice(to);
}

function countComments(doc, from, to) {
  return doc.comments.filter((comment) => comment.start >= from && comment.start < to).length;
}

// Finding the path in the nodes.

function locate(root, path) {
  const trail = [];
  let node = root;
  for (let depth = 0; depth < path.length; depth += 1) {
    const step = path[depth];
    let hit = null;
    if (node !== null && node.kind === "map" && typeof step === "string") {
      const entries = node.entries.filter(
        (entry) => entry.key.kind === "scalar" && entry.key.type !== "merge" && entry.key.text === step,
      );
      if (entries.length > 0) {
        const entry = entries[entries.length - 1];
        hit = { parent: node, entry, node: entry.value, ambiguous: entries.length > 1 };
      }
    } else if (
      node !== null &&
      node.kind === "seq" &&
      Number.isInteger(step) &&
      step >= 0 &&
      step < node.items.length
    ) {
      hit = { parent: node, index: step, node: node.items[step], ambiguous: false };
    }
    if (hit === null) {
      return { trail, node, depth, missing: true };
    }
    trail.push(hit);
    node = hit.node;
  }
  return { trail, node, depth: path.length, missing: false };
}

function refusal(reason, message) {
  return { ok: false, final: true, reason, message };
}

const UNSUPPORTED = { ok: false, final: false, reason: "unsupported" };

function lockProblem(loc, path) {
  const place = (length) => formatPath(path.slice(0, length)) || "the top level";
  for (let index = 0; index < loc.trail.length; index += 1) {
    const hit = loc.trail[index];
    if (hit.parent.locked === "merge-key") {
      return refusal(
        "merge-key",
        `${place(index)} uses a merge key (<<), so the form leaves it alone. Change it in the YAML.`,
      );
    }
    if (hit.ambiguous || (hit.entry && hit.entry.locked)) {
      return refusal(
        "duplicate-key",
        `${place(index + 1)} is written more than once in the file, so the form cannot tell which copy to change. Remove the repeated key in the YAML first.`,
      );
    }
  }
  if (loc.missing && loc.node !== null && loc.node.kind === "map" && loc.node.locked === "merge-key") {
    return refusal(
      "merge-key",
      `${place(loc.depth)} uses a merge key (<<), so the form leaves it alone. Change it in the YAML.`,
    );
  }
  return null;
}

function hasLock(node) {
  if (node.kind === "map") {
    return (
      node.locked !== undefined ||
      node.entries.some((entry) => entry.locked !== undefined || hasLock(entry.value))
    );
  }
  return node.kind === "seq" ? node.items.some(hasLock) : false;
}

function check(doc, edit) {
  if (!doc.ok) {
    const { line, column, message } = doc.refusal;
    return {
      problem: refusal(
        "unreadable",
        `The YAML cannot be read (line ${line}, column ${column}: ${message}), so the form leaves it alone.`,
      ),
    };
  }
  const path = edit.path;
  const valid =
    Array.isArray(path) &&
    path.length > 0 &&
    path.every((step) => typeof step === "string" || (Number.isInteger(step) && step >= 0));
  if (!valid) {
    return { problem: refusal("path", "The edit does not name a place in the file.") };
  }
  const loc = locate(doc.root, path);
  const problem = lockProblem(loc, path);
  return problem === null ? { loc } : { problem };
}

function styleContext(doc) {
  return { unit: doc.style.indent > 0 ? doc.style.indent : 2, seq: doc.style.seq, order: null };
}

function patched(doc, from, to, insert) {
  const text = splice(doc.text, from, to, insert);
  if (text === doc.text) {
    return { ok: true, how: "none", text, droppedComments: 0 };
  }
  return { ok: true, how: "patch", text, droppedComments: countComments(doc, from, to) };
}

// Patches.

const INVALID = Symbol("invalid chain");

function buildChain(steps, value) {
  if (steps.length === 0) {
    return value;
  }
  const [head, ...rest] = steps;
  const inner = buildChain(rest, value);
  if (inner === INVALID) {
    return INVALID;
  }
  if (typeof head === "string") {
    const mapping = {};
    define(mapping, head, inner);
    return mapping;
  }
  return head === 0 ? [inner] : INVALID;
}

function styleOf(node) {
  return node.kind === "scalar" && (node.style === "single" || node.style === "double")
    ? node.style
    : null;
}

function regionStart(hit) {
  return hit.entry ? hit.entry.colon + 1 : hit.node.dashEnd;
}

function nodeEnd(node) {
  return node.empty && node.dashEnd !== undefined ? node.dashEnd : node.end;
}

function lastChildEnd(node) {
  return node.kind === "map"
    ? node.entries[node.entries.length - 1].end
    : nodeEnd(node.items[node.items.length - 1]);
}

function insertLines(doc, anchorEnd, lines) {
  const at = lineEndOf(doc.text, anchorEnd);
  return patched(doc, at, at, doc.newline + lines.join(doc.newline));
}

function replaceScalar(doc, node, value, inFlow) {
  const text = formatScalar(value, { preferred: styleOf(node), inFlow });
  if (node.empty) {
    return patched(doc, node.start, node.end, ` ${text}`);
  }
  return patched(doc, node.start, node.end, text);
}

function replaceValue(doc, hit, value, context) {
  const node = hit.node;
  const from = regionStart(hit);
  if (!isCollection(value) || isEmptyCollection(value)) {
    return patched(doc, from, node.end, ` ${formatInline(value, styleOf(node))}`);
  }
  if (hit.entry) {
    const keyColumn = hit.entry.key.column;
    const indent = Array.isArray(value) && context.seq === "indentless" ? keyColumn : keyColumn + context.unit;
    const lines = blockLines(value, indent, context);
    return patched(doc, from, node.end, doc.newline + lines.join(doc.newline));
  }
  const dashColumn = hit.node.dashColumn;
  const lines = blockLines(value, dashColumn + 2, context);
  const rest = lines.slice(1).map((line) => doc.newline + line).join("");
  return patched(doc, from, node.end, ` ${lines[0].slice(dashColumn + 2)}${rest}`);
}

function siblingOrder(seq) {
  const last = seq.items[seq.items.length - 1];
  return last !== undefined && last.kind === "map"
    ? last.entries.filter((entry) => entry.key.kind === "scalar").map((entry) => entry.key.text)
    : null;
}

function insertSeqItem(doc, seq, value, context) {
  const lines = seqItemLines(value, seq.indent, { ...context, order: siblingOrder(seq) });
  return insertLines(doc, lastChildEnd(seq), lines);
}

function appendToDocument(doc, chain, context) {
  if (!isPlainObject(chain)) {
    return refusal("path", "A new file starts with a key, not a list item.");
  }
  const lines = mapLines(chain, 0, context);
  const end = doc.text.length;
  const lead = doc.text === "" || doc.text.endsWith("\n") ? "" : doc.newline;
  return patched(doc, end, end, lead + lines.join(doc.newline) + doc.newline);
}

function patchSet(doc, loc, edit, context) {
  const { path, value } = edit;
  if (!loc.missing) {
    const hit = loc.trail[loc.trail.length - 1];
    const node = hit.node;
    const inFlow = hit.parent.style === "flow";
    if (!isCollection(value) && node.kind === "scalar") {
      return replaceScalar(doc, node, value, inFlow);
    }
    return inFlow ? UNSUPPORTED : replaceValue(doc, hit, value, context);
  }
  const deepest = loc.node;
  const remaining = path.slice(loc.depth);
  if (deepest !== null && deepest.kind === "seq" && typeof remaining[0] === "number") {
    if (deepest.style !== "block") {
      return UNSUPPORTED;
    }
    if (remaining[0] !== deepest.items.length) {
      return refusal("path", "A list item can only be added at the end of the list.");
    }
    const item = buildChain(remaining.slice(1), value);
    return item === INVALID
      ? refusal("path", "The edit does not name a place the form can create.")
      : insertSeqItem(doc, deepest, item, context);
  }
  const chain = buildChain(remaining, value);
  if (chain === INVALID) {
    return refusal("path", "The edit does not name a place the form can create.");
  }
  if (deepest === null) {
    return appendToDocument(doc, chain, context);
  }
  if (deepest.kind === "map" && typeof remaining[0] === "number") {
    return refusal("path", "A key is needed here, not a list position.");
  }
  if (deepest.kind === "map" && deepest.style === "block") {
    return insertLines(doc, lastChildEnd(deepest), mapLines(chain, deepest.indent, context));
  }
  const hit = loc.trail[loc.trail.length - 1];
  if (isFlowCollection(deepest) && !isEmptyNode(deepest)) {
    return UNSUPPORTED;
  }
  if (hit === undefined) {
    return isFlowCollection(deepest)
      ? UNSUPPORTED
      : refusal("root", "The top level of this file is not a mapping, so the form leaves it alone.");
  }
  return hit.parent.style === "flow" ? UNSUPPORTED : replaceValue(doc, hit, chain, context);
}

function isEmptyNode(node) {
  return node.kind === "map" ? node.entries.length === 0 : node.kind === "seq" && node.items.length === 0;
}

function patchAppend(doc, loc, edit, context) {
  if (!loc.missing) {
    const node = loc.trail[loc.trail.length - 1].node;
    if (node.kind === "seq" && node.style === "block") {
      return insertSeqItem(doc, node, edit.value, context);
    }
    if (node.kind === "seq" && node.items.length > 0) {
      return UNSUPPORTED;
    }
  }
  return patchSet(doc, loc, { ...edit, op: "set", value: [edit.value] }, context);
}

function removeChild(doc, hit) {
  const text = doc.text;
  const childStart = hit.entry ? hit.entry.start : hit.node.dash;
  const childEnd = hit.entry ? hit.entry.end : nodeEnd(hit.node);
  const start = lineStartOf(text, childStart);
  if (text.slice(start, childStart).trim() !== "") {
    return UNSUPPORTED;
  }
  const end = lineEndOf(text, childEnd);
  const length = breakLengthAt(text, end);
  if (length > 0) {
    return patched(doc, start, end + length, "");
  }
  // The last line has no break after it: take the one before it instead.
  const before = start >= 2 && text.startsWith("\r\n", start - 2) ? 2 : start > 0 ? 1 : 0;
  return patched(doc, start - before, end, "");
}

function emptyParent(doc, loc) {
  const parent = loc.trail[loc.trail.length - 1].parent;
  const empty = parent.kind === "map" ? "{}" : "[]";
  if (loc.trail.length === 1) {
    return patched(doc, parent.start, parent.end, empty);
  }
  const holder = loc.trail[loc.trail.length - 2];
  return patched(doc, regionStart(holder), parent.end, ` ${empty}`);
}

function patchDelete(doc, loc) {
  if (loc.missing) {
    return { ok: true, how: "none", text: doc.text, droppedComments: 0 };
  }
  const hit = loc.trail[loc.trail.length - 1];
  const parent = hit.parent;
  if (parent.style === "flow") {
    return UNSUPPORTED;
  }
  const count = parent.kind === "map" ? parent.entries.length : parent.items.length;
  return count === 1 ? emptyParent(doc, loc) : removeChild(doc, hit);
}

/**
 * The text after an edit, changing only the lines the edit touches. Returns
 * `{ok: true, how, text, droppedComments}` (how is "patch", or "none" when the
 * text does not change), `{ok: false, final: true, reason, message}` for an edit
 * the editor will not make (an unreadable file, a repeated key, a merge key, a
 * path it cannot create), or `{ok: false, final: false}` where the shape is not
 * one a line patch handles and the entry has to be written again.
 */
export function planPatch(doc, edit) {
  const checked = check(doc, edit);
  if (checked.problem) {
    return checked.problem;
  }
  const context = styleContext(doc);
  if (edit.op === "set") {
    return patchSet(doc, checked.loc, edit, context);
  }
  if (edit.op === "append") {
    return patchAppend(doc, checked.loc, edit, context);
  }
  return edit.op === "delete" ? patchDelete(doc, checked.loc) : refusal("path", "Unknown edit.");
}

// Writing an entry again.

function isFlowCollection(node) {
  return node.kind !== "scalar" && node.style === "flow";
}

/**
 * The text after an edit with the smallest enclosing entry written again in block
 * style: the entry that holds the first flow collection on the path, or, when the
 * path runs through blocks only, the entry two levels down (a plugin section).
 * Everything outside that entry stays. Returns the same shapes as `planPatch`,
 * with `label` naming the entry and `droppedComments` counting the comments in it.
 */
export function planReemit(doc, edit) {
  const checked = check(doc, edit);
  if (checked.problem) {
    return checked.problem;
  }
  const { loc } = checked;
  const { path } = edit;
  const context = styleContext(doc);
  const intended = applyToValue(doc.value, edit);
  if (doc.root !== null && isFlowCollection(doc.root)) {
    const range = [doc.root.start, lineEndOf(doc.text, doc.root.end)];
    const text = emitBlock(intended, { unit: context.unit, seq: context.seq, newline: doc.newline });
    return reemitted(doc, range, text, "the top level");
  }
  let index = loc.trail.findIndex((hit) => isFlowCollection(hit.node));
  if (index === -1) {
    index = Math.min(1, loc.trail.length - 1);
  }
  if (edit.op === "delete") {
    index = Math.min(index, path.length - 2);
  }
  index = Math.min(index, loc.trail.length - 1);
  if (index < 0) {
    return UNSUPPORTED;
  }
  const hit = loc.trail[index];
  if (hasLock(hit.node)) {
    return refusal(
      "duplicate-key",
      `${formatPath(path.slice(0, index + 1))} holds a repeated key or a merge key, so the form leaves it alone.`,
    );
  }
  const subPath = path.slice(0, index + 1);
  const sub = applyToValue(getAt(doc.value, subPath), { ...edit, path: path.slice(index + 1) });
  const label = formatPath(subPath);
  if (hit.entry) {
    const key = doc.text.slice(hit.entry.key.start, hit.entry.key.end);
    const lines = entryLines(`${key}:`, sub, hit.entry.key.column, context);
    const range = [hit.entry.start, lineEndOf(doc.text, hit.entry.end)];
    return reemitted(doc, range, lines.join(doc.newline), label);
  }
  const dashColumn = hit.node.dashColumn;
  const lines = seqItemLines(sub, dashColumn, context);
  const range = [hit.node.dash, lineEndOf(doc.text, nodeEnd(hit.node))];
  return reemitted(doc, range, lines.join(doc.newline).slice(dashColumn), label);
}

function reemitted(doc, [from, to], insert, label) {
  return {
    ok: true,
    how: "reemit",
    text: splice(doc.text, from, to, insert),
    droppedComments: countComments(doc, from, to),
    label,
  };
}
