// The configuration editor's YAML reader.
//
// ASH reads its configuration with PyYAML's SafeLoader. This reader follows that
// loader's scanner and parser rules, token by token, so it accepts and rejects the
// same text and builds the same values. On top of that it keeps what the loader
// throws away: the offset, line and column of every node, how each scalar was
// written, the indentation of every block and where the comments are. The patcher
// uses these to change only the lines an edit touches.
//
// What ASH's loader accepts and the editor does not: aliases (ASH refuses them
// too), a second document, tags other than the environment tag and the core tags,
// explicit `?` keys, directives, and input over 2 MiB. They are refused with the
// line and column, never guessed.
//
// DOM-free. Imports only its sibling module.

import {
  Reference,
  ScalarError,
  constructTagged,
  resolvePlain,
  utf8Length,
} from "./yaml-scalars.js";

export const MAX_BYTES = 2 * 1024 * 1024;

const NUL = String.fromCharCode(0);
const NEL = String.fromCharCode(0x85);
const LS = String.fromCharCode(0x2028);
const PS = String.fromCharCode(0x2029);
const BOM = String.fromCharCode(0xfeff);
const BREAKS = `\r\n${NEL}${LS}${PS}`;
const NUL_BREAKS = NUL + BREAKS;
const SPACE_NUL_BREAKS = `${NUL} ${BREAKS}`;
const BLANK_NUL_BREAKS = `${NUL} \t${BREAKS}`;
const PLAIN_STOPPERS = `${NUL} \t${BREAKS}-?:,[]{}#&*!|>'"%@\``;
const HEX = "0123456789ABCDEFabcdef";

/** A reason the text is not read. line and column are 0-based marks inside. */
export class YamlError extends Error {
  constructor(code, message, mark) {
    super(message);
    this.code = code;
    this.mark = mark;
  }
}

const TOKEN_IDS = {
  StreamStart: "<stream start>",
  StreamEnd: "<stream end>",
  Directive: "<directive>",
  DocumentStart: "<document start>",
  DocumentEnd: "<document end>",
  BlockSequenceStart: "<block sequence start>",
  BlockMappingStart: "<block mapping start>",
  BlockEnd: "<block end>",
  FlowSequenceStart: "[",
  FlowMappingStart: "{",
  FlowSequenceEnd: "]",
  FlowMappingEnd: "}",
  BlockEntry: "-",
  FlowEntry: ",",
  Key: "?",
  Value: ":",
  Alias: "<alias>",
  Anchor: "<anchor>",
  Tag: "<tag>",
  Scalar: "<scalar>",
};

function describe(character) {
  const shown = JSON.stringify(character);
  return `'${shown.slice(1, -1)}'`;
}

class Scanner {
  constructor(text) {
    this.text = text;
    this.length = text.length;
    this.index = 0;
    this.line = 0;
    this.column = 0;
    this.comments = [];
    this.done = false;
    this.flowLevel = 0;
    this.tokens = [];
    this.tokensTaken = 0;
    this.indent = -1;
    this.indents = [];
    this.allowSimpleKey = true;
    this.possibleSimpleKeys = new Map();
    this.fetchStreamStart();
  }

  // Reader.

  peek(offset = 0) {
    const position = this.index + offset;
    return position < this.length ? this.text[position] : NUL;
  }

  prefix(length = 1) {
    return this.text.slice(this.index, this.index + length);
  }

  forward(length = 1) {
    let remaining = length;
    while (remaining > 0) {
      const ch = this.text[this.index];
      this.index += 1;
      if (
        ch === "\n" ||
        ch === NEL ||
        ch === LS ||
        ch === PS ||
        (ch === "\r" && this.text[this.index] !== "\n")
      ) {
        this.line += 1;
        this.column = 0;
      } else if (ch !== BOM) {
        this.column += 1;
      }
      remaining -= 1;
    }
  }

  mark() {
    return { index: this.index, line: this.line, column: this.column };
  }

  fail(code, message, mark = this.mark()) {
    throw new YamlError(code, message, mark);
  }

  // Tokens.

  checkToken(...types) {
    while (this.needMoreTokens()) {
      this.fetchMoreTokens();
    }
    if (this.tokens.length > 0) {
      if (types.length === 0) {
        return true;
      }
      return types.includes(this.tokens[0].type);
    }
    return false;
  }

  peekToken() {
    while (this.needMoreTokens()) {
      this.fetchMoreTokens();
    }
    return this.tokens.length > 0 ? this.tokens[0] : null;
  }

  getToken() {
    while (this.needMoreTokens()) {
      this.fetchMoreTokens();
    }
    if (this.tokens.length > 0) {
      this.tokensTaken += 1;
      return this.tokens.shift();
    }
    return null;
  }

  needMoreTokens() {
    if (this.done) {
      return false;
    }
    if (this.tokens.length === 0) {
      return true;
    }
    this.stalePossibleSimpleKeys();
    return this.nextPossibleSimpleKey() === this.tokensTaken;
  }

  fetchMoreTokens() {
    this.scanToNextToken();
    this.stalePossibleSimpleKeys();
    this.unwindIndent(this.column);
    const ch = this.peek();
    if (ch === NUL) {
      this.fetchStreamEnd();
    } else if (ch === "%" && this.column === 0) {
      this.fail("directive", "YAML directives (%YAML, %TAG) are not supported");
    } else if (ch === "-" && this.checkDocumentIndicator("---")) {
      this.fetchDocumentIndicator("DocumentStart");
    } else if (ch === "." && this.checkDocumentIndicator("...")) {
      this.fetchDocumentIndicator("DocumentEnd");
    } else if (ch === "[") {
      this.fetchFlowCollectionStart("FlowSequenceStart");
    } else if (ch === "{") {
      this.fetchFlowCollectionStart("FlowMappingStart");
    } else if (ch === "]") {
      this.fetchFlowCollectionEnd("FlowSequenceEnd");
    } else if (ch === "}") {
      this.fetchFlowCollectionEnd("FlowMappingEnd");
    } else if (ch === ",") {
      this.fetchFlowEntry();
    } else if (ch === "-" && this.isBlankAt(1)) {
      this.fetchBlockEntry();
    } else if (ch === "?" && (this.flowLevel > 0 || this.isBlankAt(1))) {
      this.fetchKey();
    } else if (ch === ":" && (this.flowLevel > 0 || this.isBlankAt(1))) {
      this.fetchValue();
    } else if (ch === "*") {
      this.fetchAnchor("Alias");
    } else if (ch === "&") {
      this.fetchAnchor("Anchor");
    } else if (ch === "!") {
      this.fetchTag();
    } else if (ch === "|" && this.flowLevel === 0) {
      this.fetchBlockScalar("|");
    } else if (ch === ">" && this.flowLevel === 0) {
      this.fetchBlockScalar(">");
    } else if (ch === "'") {
      this.fetchFlowScalar("'");
    } else if (ch === '"') {
      this.fetchFlowScalar('"');
    } else if (this.checkPlain()) {
      this.fetchPlain();
    } else if (ch === "\t") {
      this.fail(
        "tab",
        "found a tab where YAML needs spaces: tabs cannot indent or separate YAML",
      );
    } else {
      this.fail("syntax", `found character ${describe(ch)} that cannot start any token`);
    }
  }

  isBlankAt(offset) {
    return BLANK_NUL_BREAKS.includes(this.peek(offset));
  }

  checkDocumentIndicator(word) {
    return (
      this.column === 0 && this.prefix(3) === word && this.isBlankAt(3)
    );
  }

  checkPlain() {
    const ch = this.peek();
    return (
      !PLAIN_STOPPERS.includes(ch) ||
      (!this.isBlankAt(1) && (ch === "-" || (this.flowLevel === 0 && "?:".includes(ch))))
    );
  }

  // Simple keys.

  nextPossibleSimpleKey() {
    let minimum = null;
    for (const key of this.possibleSimpleKeys.values()) {
      if (minimum === null || key.tokenNumber < minimum) {
        minimum = key.tokenNumber;
      }
    }
    return minimum;
  }

  stalePossibleSimpleKeys() {
    for (const level of [...this.possibleSimpleKeys.keys()]) {
      const key = this.possibleSimpleKeys.get(level);
      if (key.line !== this.line || this.index - key.index > 1024) {
        if (key.required) {
          // PyYAML reports the place the scanner has reached, not the key.
          this.fail("syntax", "could not find expected ':'");
        }
        this.possibleSimpleKeys.delete(level);
      }
    }
  }

  savePossibleSimpleKey() {
    const required = this.flowLevel === 0 && this.indent === this.column;
    if (this.allowSimpleKey) {
      this.removePossibleSimpleKey();
      this.possibleSimpleKeys.set(this.flowLevel, {
        tokenNumber: this.tokensTaken + this.tokens.length,
        required,
        index: this.index,
        line: this.line,
        column: this.column,
        mark: this.mark(),
      });
    }
  }

  removePossibleSimpleKey() {
    const key = this.possibleSimpleKeys.get(this.flowLevel);
    if (key !== undefined) {
      if (key.required) {
        this.fail("syntax", "could not find expected ':'");
      }
      this.possibleSimpleKeys.delete(this.flowLevel);
    }
  }

  // Indentation.

  unwindIndent(column) {
    if (this.flowLevel > 0) {
      return;
    }
    while (this.indent > column) {
      const mark = this.mark();
      this.indent = this.indents.pop();
      this.tokens.push({ type: "BlockEnd", start: mark, end: mark });
    }
  }

  addIndent(column) {
    if (this.indent < column) {
      this.indents.push(this.indent);
      this.indent = column;
      return true;
    }
    return false;
  }

  // Fetchers.

  fetchStreamStart() {
    const mark = this.mark();
    this.tokens.push({ type: "StreamStart", start: mark, end: mark });
  }

  fetchStreamEnd() {
    this.unwindIndent(-1);
    this.removePossibleSimpleKey();
    this.allowSimpleKey = false;
    this.possibleSimpleKeys = new Map();
    const mark = this.mark();
    this.tokens.push({ type: "StreamEnd", start: mark, end: mark });
    this.done = true;
  }

  fetchDocumentIndicator(type) {
    this.unwindIndent(-1);
    this.removePossibleSimpleKey();
    this.allowSimpleKey = false;
    const start = this.mark();
    this.forward(3);
    this.tokens.push({ type, start, end: this.mark() });
  }

  fetchFlowCollectionStart(type) {
    this.savePossibleSimpleKey();
    this.flowLevel += 1;
    this.allowSimpleKey = true;
    const start = this.mark();
    this.forward();
    this.tokens.push({ type, start, end: this.mark() });
  }

  fetchFlowCollectionEnd(type) {
    this.removePossibleSimpleKey();
    this.flowLevel -= 1;
    this.allowSimpleKey = false;
    const start = this.mark();
    this.forward();
    this.tokens.push({ type, start, end: this.mark() });
  }

  fetchFlowEntry() {
    this.allowSimpleKey = true;
    this.removePossibleSimpleKey();
    const start = this.mark();
    this.forward();
    this.tokens.push({ type: "FlowEntry", start, end: this.mark() });
  }

  fetchBlockEntry() {
    if (this.flowLevel === 0) {
      if (!this.allowSimpleKey) {
        this.fail("syntax", "sequence entries are not allowed here");
      }
      if (this.addIndent(this.column)) {
        const mark = this.mark();
        this.tokens.push({ type: "BlockSequenceStart", start: mark, end: mark });
      }
    }
    this.allowSimpleKey = true;
    this.removePossibleSimpleKey();
    const start = this.mark();
    this.forward();
    this.tokens.push({ type: "BlockEntry", start, end: this.mark() });
  }

  fetchKey() {
    if (this.flowLevel === 0) {
      if (!this.allowSimpleKey) {
        this.fail("syntax", "mapping keys are not allowed here");
      }
      if (this.addIndent(this.column)) {
        const mark = this.mark();
        this.tokens.push({ type: "BlockMappingStart", start: mark, end: mark });
      }
    }
    this.allowSimpleKey = this.flowLevel === 0;
    this.removePossibleSimpleKey();
    const start = this.mark();
    this.forward();
    this.tokens.push({ type: "Key", start, end: this.mark(), explicit: true });
  }

  fetchValue() {
    const key = this.possibleSimpleKeys.get(this.flowLevel);
    if (key !== undefined) {
      this.possibleSimpleKeys.delete(this.flowLevel);
      const position = key.tokenNumber - this.tokensTaken;
      this.tokens.splice(position, 0, { type: "Key", start: key.mark, end: key.mark });
      if (this.flowLevel === 0) {
        if (this.addIndent(key.column)) {
          this.tokens.splice(position, 0, {
            type: "BlockMappingStart",
            start: key.mark,
            end: key.mark,
          });
        }
      }
      this.allowSimpleKey = false;
    } else {
      if (this.flowLevel === 0) {
        if (!this.allowSimpleKey) {
          this.fail("syntax", "mapping values are not allowed here");
        }
        if (this.addIndent(this.column)) {
          const mark = this.mark();
          this.tokens.push({ type: "BlockMappingStart", start: mark, end: mark });
        }
      }
      this.allowSimpleKey = this.flowLevel === 0;
      this.removePossibleSimpleKey();
    }
    const start = this.mark();
    this.forward();
    this.tokens.push({ type: "Value", start, end: this.mark() });
  }

  fetchAnchor(type) {
    this.savePossibleSimpleKey();
    this.allowSimpleKey = false;
    this.tokens.push(this.scanAnchor(type));
  }

  fetchTag() {
    this.savePossibleSimpleKey();
    this.allowSimpleKey = false;
    this.tokens.push(this.scanTag());
  }

  fetchBlockScalar(style) {
    this.allowSimpleKey = true;
    this.removePossibleSimpleKey();
    this.tokens.push(this.scanBlockScalar(style));
  }

  fetchFlowScalar(style) {
    this.savePossibleSimpleKey();
    this.allowSimpleKey = false;
    this.tokens.push(this.scanFlowScalar(style));
  }

  fetchPlain() {
    this.savePossibleSimpleKey();
    this.allowSimpleKey = false;
    this.tokens.push(this.scanPlain());
  }

  // Scanners.

  scanToNextToken() {
    if (this.index === 0 && this.peek() === BOM) {
      this.forward();
    }
    let found = false;
    while (!found) {
      while (this.peek() === " ") {
        this.forward();
      }
      if (this.peek() === "#") {
        const start = this.index;
        const line = this.line;
        while (!NUL_BREAKS.includes(this.peek())) {
          this.forward();
        }
        this.comments.push({ start, end: this.index, line });
      }
      if (this.scanLineBreak() !== "") {
        if (this.flowLevel === 0) {
          this.allowSimpleKey = true;
        }
      } else {
        found = true;
      }
    }
  }

  scanLineBreak() {
    const ch = this.peek();
    if (ch === "\r" || ch === "\n" || ch === NEL) {
      if (this.prefix(2) === "\r\n") {
        this.forward(2);
      } else {
        this.forward();
      }
      return "\n";
    }
    if (ch === LS || ch === PS) {
      this.forward();
      return ch;
    }
    return "";
  }

  scanAnchor(type) {
    const start = this.mark();
    const name = type === "Alias" ? "alias" : "anchor";
    this.forward();
    let length = 0;
    let ch = this.peek(length);
    while (/[0-9A-Za-z_-]/.test(ch)) {
      length += 1;
      ch = this.peek(length);
    }
    if (length === 0) {
      this.fail(
        "syntax",
        `while scanning an ${name}: expected alphabetic or numeric character, but found ${describe(ch)}`,
      );
    }
    const value = this.prefix(length);
    this.forward(length);
    ch = this.peek();
    if (!`${SPACE_NUL_BREAKS}\t?:,]}%@\``.includes(ch)) {
      this.fail(
        "syntax",
        `while scanning an ${name}: expected alphabetic or numeric character, but found ${describe(ch)}`,
      );
    }
    return { type, value, start, end: this.mark() };
  }

  scanTag() {
    const start = this.mark();
    let ch = this.peek(1);
    let handle;
    let suffix;
    if (ch === "<") {
      handle = null;
      this.forward(2);
      suffix = this.scanTagUri("tag");
      if (this.peek() !== ">") {
        this.fail("syntax", `while parsing a tag: expected '>', but found ${describe(this.peek())}`);
      }
      this.forward();
    } else if (BLANK_NUL_BREAKS.includes(ch)) {
      handle = null;
      suffix = "!";
      this.forward();
    } else {
      let length = 1;
      let useHandle = false;
      while (!SPACE_NUL_BREAKS.includes(ch)) {
        if (ch === "!") {
          useHandle = true;
          break;
        }
        length += 1;
        ch = this.peek(length);
      }
      if (useHandle) {
        handle = this.scanTagHandle();
      } else {
        handle = "!";
        this.forward();
      }
      suffix = this.scanTagUri("tag");
    }
    ch = this.peek();
    if (!SPACE_NUL_BREAKS.includes(ch)) {
      this.fail("syntax", `while scanning a tag: expected ' ', but found ${describe(ch)}`);
    }
    return { type: "Tag", handle, suffix, start, end: this.mark() };
  }

  scanTagHandle() {
    let ch = this.peek();
    if (ch !== "!") {
      this.fail("syntax", `while scanning a tag: expected '!', but found ${describe(ch)}`);
    }
    let length = 1;
    ch = this.peek(length);
    if (ch !== " ") {
      while (/[0-9A-Za-z_-]/.test(ch)) {
        length += 1;
        ch = this.peek(length);
      }
      if (ch !== "!") {
        this.forward(length);
        this.fail("syntax", `while scanning a tag: expected '!', but found ${describe(ch)}`);
      }
      length += 1;
    }
    const value = this.prefix(length);
    this.forward(length);
    return value;
  }

  scanTagUri() {
    const chunks = [];
    let length = 0;
    let ch = this.peek(length);
    while (/[0-9A-Za-z]/.test(ch) || "-;/?:@&=+$,_.!~*'()[]%".includes(ch)) {
      if (ch === "%") {
        chunks.push(this.prefix(length));
        this.forward(length);
        length = 0;
        chunks.push(this.scanUriEscapes());
      } else {
        length += 1;
      }
      ch = this.peek(length);
    }
    if (length > 0) {
      chunks.push(this.prefix(length));
      this.forward(length);
    }
    if (chunks.length === 0) {
      this.fail("syntax", `while parsing a tag: expected URI, but found ${describe(ch)}`);
    }
    return chunks.join("");
  }

  scanUriEscapes() {
    let encoded = "";
    while (this.peek() === "%") {
      this.forward();
      for (let k = 0; k < 2; k += 1) {
        if (!HEX.includes(this.peek(k))) {
          this.fail("syntax", "while scanning a tag: expected URI escape sequence of 2 hexadecimal numbers");
        }
      }
      encoded += `%${this.prefix(2)}`;
      this.forward(2);
    }
    try {
      return decodeURIComponent(encoded);
    } catch {
      return this.fail("syntax", "while scanning a tag: the URI escapes are not UTF-8");
    }
  }

  scanBlockScalar(style) {
    const folded = style === ">";
    const chunks = [];
    const start = this.mark();
    this.forward();
    const { chomping, increment } = this.scanBlockScalarIndicators();
    this.scanBlockScalarIgnoredLine();
    let minIndent = this.indent + 1;
    if (minIndent < 1) {
      minIndent = 1;
    }
    let breaks;
    let end;
    let indent;
    if (increment === null) {
      const found = this.scanBlockScalarIndentation();
      breaks = found.chunks;
      end = found.end;
      indent = Math.max(minIndent, found.maxIndent);
    } else {
      indent = minIndent + increment - 1;
      const found = this.scanBlockScalarBreaks(indent);
      breaks = found.chunks;
      end = found.end;
    }
    let lineBreak = "";
    while (this.column === indent && this.peek() !== NUL) {
      chunks.push(...breaks);
      const leadingNonSpace = !" \t".includes(this.peek());
      let length = 0;
      while (!NUL_BREAKS.includes(this.peek(length))) {
        length += 1;
      }
      chunks.push(this.prefix(length));
      this.forward(length);
      lineBreak = this.scanLineBreak();
      const found = this.scanBlockScalarBreaks(indent);
      breaks = found.chunks;
      end = found.end;
      if (this.column === indent && this.peek() !== NUL) {
        if (folded && lineBreak === "\n" && leadingNonSpace && !" \t".includes(this.peek())) {
          if (breaks.length === 0) {
            chunks.push(" ");
          }
        } else {
          chunks.push(lineBreak);
        }
      } else {
        break;
      }
    }
    if (chomping !== false) {
      chunks.push(lineBreak);
    }
    if (chomping === true) {
      chunks.push(...breaks);
    }
    return { type: "Scalar", value: chunks.join(""), plain: false, style, start, end };
  }

  scanBlockScalarIndicators() {
    let chomping = null;
    let increment = null;
    let ch = this.peek();
    const bad = () =>
      this.fail(
        "syntax",
        "while scanning a block scalar: expected indentation indicator in the range 1-9, but found 0",
      );
    if (ch === "+" || ch === "-") {
      chomping = ch === "+";
      this.forward();
      ch = this.peek();
      if ("0123456789".includes(ch)) {
        increment = Number(ch);
        if (increment === 0) {
          bad();
        }
        this.forward();
      }
    } else if ("0123456789".includes(ch)) {
      increment = Number(ch);
      if (increment === 0) {
        bad();
      }
      this.forward();
      ch = this.peek();
      if (ch === "+" || ch === "-") {
        chomping = ch === "+";
        this.forward();
      }
    }
    ch = this.peek();
    if (!SPACE_NUL_BREAKS.includes(ch)) {
      this.fail(
        "syntax",
        `while scanning a block scalar: expected chomping or indentation indicators, but found ${describe(ch)}`,
      );
    }
    return { chomping, increment };
  }

  scanBlockScalarIgnoredLine() {
    while (this.peek() === " ") {
      this.forward();
    }
    if (this.peek() === "#") {
      const start = this.index;
      const line = this.line;
      while (!NUL_BREAKS.includes(this.peek())) {
        this.forward();
      }
      this.comments.push({ start, end: this.index, line });
    }
    const ch = this.peek();
    if (!NUL_BREAKS.includes(ch)) {
      this.fail(
        "syntax",
        `while scanning a block scalar: expected a comment or a line break, but found ${describe(ch)}`,
      );
    }
    this.scanLineBreak();
  }

  scanBlockScalarIndentation() {
    const chunks = [];
    let maxIndent = 0;
    let end = this.mark();
    while (` ${BREAKS}`.includes(this.peek())) {
      if (this.peek() !== " ") {
        chunks.push(this.scanLineBreak());
        end = this.mark();
      } else {
        this.forward();
        if (this.column > maxIndent) {
          maxIndent = this.column;
        }
      }
    }
    return { chunks, maxIndent, end };
  }

  scanBlockScalarBreaks(indent) {
    const chunks = [];
    let end = this.mark();
    while (this.column < indent && this.peek() === " ") {
      this.forward();
    }
    while (BREAKS.includes(this.peek())) {
      chunks.push(this.scanLineBreak());
      end = this.mark();
      while (this.column < indent && this.peek() === " ") {
        this.forward();
      }
    }
    return { chunks, end };
  }

  scanFlowScalar(style) {
    const double = style === '"';
    const chunks = [];
    const start = this.mark();
    const quote = this.peek();
    this.forward();
    chunks.push(...this.scanFlowScalarNonSpaces(double));
    while (this.peek() !== quote) {
      chunks.push(...this.scanFlowScalarSpaces(double));
      chunks.push(...this.scanFlowScalarNonSpaces(double));
    }
    this.forward();
    return { type: "Scalar", value: chunks.join(""), plain: false, style, start, end: this.mark() };
  }

  scanFlowScalarNonSpaces(double) {
    const chunks = [];
    const escapes = {
      0: NUL,
      a: String.fromCharCode(7),
      b: String.fromCharCode(8),
      t: "\t",
      "\t": "\t",
      n: "\n",
      v: String.fromCharCode(11),
      f: String.fromCharCode(12),
      r: "\r",
      e: String.fromCharCode(27),
      " ": " ",
      '"': '"',
      "\\": "\\",
      "/": "/",
      N: NEL,
      _: String.fromCharCode(0xa0),
      L: LS,
      P: PS,
    };
    const codes = { x: 2, u: 4, U: 8 };
    for (;;) {
      let length = 0;
      while (!`'"\\${NUL_BREAKS} \t`.includes(this.peek(length))) {
        length += 1;
      }
      if (length > 0) {
        chunks.push(this.prefix(length));
        this.forward(length);
      }
      let ch = this.peek();
      if (!double && ch === "'" && this.peek(1) === "'") {
        chunks.push("'");
        this.forward(2);
      } else if ((double && ch === "'") || (!double && '"\\'.includes(ch))) {
        chunks.push(ch);
        this.forward();
      } else if (double && ch === "\\") {
        this.forward();
        ch = this.peek();
        if (Object.prototype.hasOwnProperty.call(escapes, ch)) {
          chunks.push(escapes[ch]);
          this.forward();
        } else if (Object.prototype.hasOwnProperty.call(codes, ch)) {
          const count = codes[ch];
          this.forward();
          for (let k = 0; k < count; k += 1) {
            if (!HEX.includes(this.peek(k))) {
              this.fail(
                "syntax",
                `while scanning a double-quoted scalar: expected escape sequence of ${count} hexadecimal numbers, but found ${describe(this.peek(k))}`,
              );
            }
          }
          const code = parseInt(this.prefix(count), 16);
          if (code > 0x10ffff) {
            this.fail("syntax", "while scanning a double-quoted scalar: the escape is not a character");
          }
          chunks.push(String.fromCodePoint(code));
          this.forward(count);
        } else if (BREAKS.includes(ch)) {
          this.scanLineBreak();
          chunks.push(...this.scanFlowScalarBreaks());
        } else {
          this.fail(
            "syntax",
            `while scanning a double-quoted scalar: found unknown escape character ${describe(ch)}`,
          );
        }
      } else {
        return chunks;
      }
    }
  }

  scanFlowScalarSpaces() {
    const chunks = [];
    let length = 0;
    while (" \t".includes(this.peek(length))) {
      length += 1;
    }
    const whitespaces = this.prefix(length);
    this.forward(length);
    const ch = this.peek();
    if (ch === NUL) {
      this.fail("syntax", "while scanning a quoted scalar: found unexpected end of stream");
    } else if (BREAKS.includes(ch)) {
      const lineBreak = this.scanLineBreak();
      const breaks = this.scanFlowScalarBreaks();
      if (lineBreak !== "\n") {
        chunks.push(lineBreak);
      } else if (breaks.length === 0) {
        chunks.push(" ");
      }
      chunks.push(...breaks);
    } else {
      chunks.push(whitespaces);
    }
    return chunks;
  }

  scanFlowScalarBreaks() {
    const chunks = [];
    for (;;) {
      const prefix = this.prefix(3);
      if ((prefix === "---" || prefix === "...") && this.isBlankAt(3)) {
        this.fail("syntax", "while scanning a quoted scalar: found unexpected document separator");
      }
      while (" \t".includes(this.peek())) {
        this.forward();
      }
      if (BREAKS.includes(this.peek())) {
        chunks.push(this.scanLineBreak());
      } else {
        return chunks;
      }
    }
  }

  scanPlain() {
    const chunks = [];
    const start = this.mark();
    let end = start;
    const indent = this.indent + 1;
    let spaces = [];
    for (;;) {
      let length = 0;
      if (this.peek() === "#") {
        break;
      }
      for (;;) {
        const ch = this.peek(length);
        const stoppers = this.flowLevel > 0 ? `${BLANK_NUL_BREAKS},[]{}` : BLANK_NUL_BREAKS;
        if (
          BLANK_NUL_BREAKS.includes(ch) ||
          (ch === ":" && stoppers.includes(this.peek(length + 1))) ||
          (this.flowLevel > 0 && ",?[]{}".includes(ch))
        ) {
          break;
        }
        length += 1;
      }
      if (length === 0) {
        break;
      }
      this.allowSimpleKey = false;
      chunks.push(...spaces);
      chunks.push(this.prefix(length));
      this.forward(length);
      end = this.mark();
      spaces = this.scanPlainSpaces();
      if (
        spaces === null ||
        spaces.length === 0 ||
        this.peek() === "#" ||
        (this.flowLevel === 0 && this.column < indent)
      ) {
        break;
      }
    }
    return { type: "Scalar", value: chunks.join(""), plain: true, style: null, start, end };
  }

  scanPlainSpaces() {
    const chunks = [];
    let length = 0;
    while (this.peek(length) === " ") {
      length += 1;
    }
    const whitespaces = this.prefix(length);
    this.forward(length);
    const ch = this.peek();
    if (BREAKS.includes(ch)) {
      const lineBreak = this.scanLineBreak();
      this.allowSimpleKey = true;
      let prefix = this.prefix(3);
      if ((prefix === "---" || prefix === "...") && this.isBlankAt(3)) {
        return null;
      }
      const breaks = [];
      while (SPACE_NUL_BREAKS.slice(1).includes(this.peek())) {
        if (this.peek() === " ") {
          this.forward();
        } else {
          breaks.push(this.scanLineBreak());
          prefix = this.prefix(3);
          if ((prefix === "---" || prefix === "...") && this.isBlankAt(3)) {
            return null;
          }
        }
      }
      if (lineBreak !== "\n") {
        chunks.push(lineBreak);
      } else if (breaks.length === 0) {
        chunks.push(" ");
      }
      chunks.push(...breaks);
    } else if (whitespaces !== "") {
      chunks.push(whitespaces);
    }
    return chunks;
  }
}

// Composer: tokens to nodes.

const CORE_TAG_PREFIX = "tag:yaml.org,2002:";
const CORE_TAG_NAMES = new Set(["str", "int", "float", "bool", "null", "map", "seq"]);
const STYLE_NAMES = { "'": "single", '"': "double", "|": "literal", ">": "folded" };

function markOf(node) {
  return { index: node.start, line: node.line, column: node.column };
}

function emptyScalar(mark) {
  return {
    kind: "scalar",
    style: "plain",
    start: mark.index,
    end: mark.index,
    line: mark.line,
    column: mark.column,
    tag: null,
    anchor: null,
    text: "",
    type: "null",
    value: null,
    empty: true,
  };
}

class Composer {
  constructor(scanner) {
    this.scanner = scanner;
  }

  tokenName(token) {
    return TOKEN_IDS[token.type];
  }

  expectedBlockEnd(context, token) {
    this.scanner.fail(
      "syntax",
      `while parsing a ${context}: expected <block end>, but found '${this.tokenName(token)}'`,
      token.start,
    );
  }

  compose() {
    const scanner = this.scanner;
    scanner.getToken(); // StreamStart
    let root = null;
    if (scanner.checkToken("DocumentStart")) {
      scanner.getToken();
      if (!scanner.checkToken("DocumentStart", "DocumentEnd", "StreamEnd")) {
        root = this.parseNode(true, false);
      }
    } else if (!scanner.checkToken("StreamEnd")) {
      root = this.parseNode(true, false);
    }
    while (scanner.checkToken("DocumentEnd")) {
      scanner.getToken();
    }
    if (!scanner.checkToken("StreamEnd")) {
      const token = scanner.peekToken();
      if (token.type === "DocumentStart") {
        scanner.fail("second-document", "expected a single document in the stream, but found another document", token.start);
      }
      scanner.fail(
        "syntax",
        `expected '<document start>', but found '${this.tokenName(token)}'`,
        token.start,
      );
    }
    return root;
  }

  tagText(token) {
    const { handle, suffix } = token;
    if (handle === "!!" && CORE_TAG_NAMES.has(suffix)) {
      return CORE_TAG_PREFIX + suffix;
    }
    if (handle === "!" && suffix === "ENV") {
      return "!ENV";
    }
    const written = this.scanner.text.slice(token.start.index, token.end.index);
    return this.scanner.fail(
      "tag",
      `unknown tag ${written}: the editor reads the tags !ENV, !!str, !!int, !!float, !!bool, !!null, !!map and !!seq`,
      token.start,
    );
  }

  parseNode(block, indentlessSequence) {
    const scanner = this.scanner;
    if (scanner.checkToken("Alias")) {
      const token = scanner.getToken();
      scanner.fail(
        "alias",
        `found the alias *${token.value}; ASH configuration does not accept YAML aliases, so write the value out where it is used`,
        token.start,
      );
    }
    let anchor = null;
    let tag = null;
    let startMark = null;
    let endMark = null;
    if (scanner.checkToken("Anchor")) {
      let token = scanner.getToken();
      startMark = token.start;
      endMark = token.end;
      anchor = token.value;
      if (scanner.checkToken("Tag")) {
        token = scanner.getToken();
        endMark = token.end;
        tag = this.tagText(token);
      }
    } else if (scanner.checkToken("Tag")) {
      let token = scanner.getToken();
      startMark = token.start;
      endMark = token.end;
      tag = this.tagText(token);
      if (scanner.checkToken("Anchor")) {
        token = scanner.getToken();
        endMark = token.end;
        anchor = token.value;
      }
    }
    if (startMark === null) {
      startMark = scanner.peekToken().start;
      endMark = startMark;
    }
    const properties = { anchor, tag, startMark };
    let node;
    if (indentlessSequence && scanner.checkToken("BlockEntry")) {
      node = this.parseIndentlessSequence(properties);
    } else if (scanner.checkToken("Scalar")) {
      node = this.scalarNode(scanner.getToken(), properties);
    } else if (scanner.checkToken("FlowSequenceStart")) {
      node = this.parseFlowSequence(properties);
    } else if (scanner.checkToken("FlowMappingStart")) {
      node = this.parseFlowMapping(properties);
    } else if (block && scanner.checkToken("BlockSequenceStart")) {
      node = this.parseBlockSequence(properties);
    } else if (block && scanner.checkToken("BlockMappingStart")) {
      node = this.parseBlockMapping(properties);
    } else if (anchor !== null || tag !== null) {
      node = this.scalarNode(
        { type: "Scalar", value: "", plain: true, style: null, start: endMark, end: endMark },
        properties,
      );
    } else {
      const token = scanner.peekToken();
      scanner.fail(
        "syntax",
        `while parsing a ${block ? "block" : "flow"} node: expected the node content, but found '${this.tokenName(token)}'`,
        token.start,
      );
    }
    this.checkTag(node);
    return node;
  }

  checkTag(node) {
    if (node.tag === null || node.tag === "!ENV") {
      if (node.tag === "!ENV" && node.kind !== "scalar") {
        this.scanner.fail("constructor", "the tag !ENV goes on a scalar", markOf(node));
      }
      return;
    }
    const name = node.tag.slice(CORE_TAG_PREFIX.length);
    const wanted = { map: "map", seq: "seq" }[name] || "scalar";
    if (node.kind !== wanted) {
      this.scanner.fail("constructor", `the tag !!${name} does not fit ${node.kind === "scalar" ? "a scalar" : `a ${node.kind}`}`, markOf(node));
    }
  }

  scalarNode(token, properties) {
    const style = token.plain ? "plain" : STYLE_NAMES[token.style];
    let start = token.start.index;
    let { line, column } = token.start;
    if (properties.startMark !== null && properties.startMark.index <= token.start.index) {
      start = properties.startMark.index;
      line = properties.startMark.line;
      column = properties.startMark.column;
    }
    const node = {
      kind: "scalar",
      style,
      start,
      end: token.end.index,
      line,
      column,
      tag: properties.tag,
      anchor: properties.anchor,
      text: token.value,
      contentStart: token.start.index,
    };
    if (style === "literal" || style === "folded") {
      node.end = this.trimBlockEnd(token.start.index, token.end.index);
    }
    this.resolve(node);
    return node;
  }

  // A block scalar's token runs on through the blank lines after it; the node
  // ends at its last content character, or at its header when it has no content.
  trimBlockEnd(start, end) {
    const text = this.scanner.text;
    const headerEnd = start + /^[|>][-+0-9]{0,2}/.exec(text.slice(start, start + 3))[0].length;
    let position = end;
    while (position > headerEnd && " \t\r\n".includes(text[position - 1])) {
      position -= 1;
    }
    return position;
  }

  resolve(node) {
    let resolved;
    try {
      if (node.tag === null) {
        resolved = node.style === "plain" ? resolvePlain(node.text) : { type: "str", value: node.text };
      } else if (node.tag === "!ENV") {
        resolved = { type: "env", value: node.text };
      } else {
        resolved = constructTagged(node.tag.slice(CORE_TAG_PREFIX.length), node.text);
      }
    } catch (error) {
      if (error instanceof ScalarError) {
        this.scanner.fail("constructor", error.message, markOf(node));
      }
      throw error;
    }
    node.type = resolved.type;
    node.value = resolved.value;
    if (resolved.type === "env") {
      node.ref = new Reference(node.text, node.tag === "!ENV");
      node.value = node.ref;
    }
    if (resolved.type === "int") {
      node.digits = resolved.digits;
      node.exact = resolved.exact;
    }
  }

  finishCollection(node, children) {
    let end = node.start;
    for (const child of children) {
      end = Math.max(end, child.end);
    }
    if (node.style === "block") {
      node.end = end;
    }
    return node;
  }

  parseBlockMapping(properties) {
    const scanner = this.scanner;
    const first = scanner.getToken(); // BlockMappingStart
    const node = {
      kind: "map",
      style: "block",
      start: properties.startMark.index,
      end: first.start.index,
      line: properties.startMark.line,
      column: properties.startMark.column,
      tag: properties.tag,
      anchor: properties.anchor,
      entries: [],
      indent: first.start.column,
    };
    for (;;) {
      if (scanner.checkToken("Key")) {
        const key = scanner.getToken();
        if (key.explicit) {
          scanner.fail("complex-key", "explicit keys (?) are not supported; write the key on one line", key.start);
        }
        let keyNode;
        if (!scanner.checkToken("Key", "Value", "BlockEnd")) {
          keyNode = this.parseNode(true, true);
        } else {
          keyNode = emptyScalar(key.end);
        }
        let valueNode;
        let colon = -1;
        if (scanner.checkToken("Value")) {
          const value = scanner.getToken();
          colon = value.start.index;
          if (!scanner.checkToken("Key", "Value", "BlockEnd")) {
            valueNode = this.parseNode(true, true);
          } else {
            valueNode = emptyScalar(value.end);
          }
        } else {
          valueNode = emptyScalar(scanner.peekToken().start);
        }
        node.entries.push(this.entry(keyNode, valueNode, colon));
        continue;
      }
      if (!scanner.checkToken("BlockEnd")) {
        this.expectedBlockEnd("block mapping", scanner.peekToken());
      }
      scanner.getToken();
      break;
    }
    node.start = node.entries.length > 0 ? Math.min(node.start, node.entries[0].start) : node.start;
    return this.finishCollection(node, node.entries.map((item) => item));
  }

  entry(key, value, colon) {
    let end = value.empty && colon >= 0 ? colon + 1 : value.end;
    if (value.empty && colon < 0) {
      end = key.end;
    }
    return { key, value, colon, start: key.start, end };
  }

  parseBlockSequence(properties) {
    const scanner = this.scanner;
    const first = scanner.getToken(); // BlockSequenceStart
    const node = {
      kind: "seq",
      style: "block",
      start: properties.startMark.index,
      end: first.start.index,
      line: properties.startMark.line,
      column: properties.startMark.column,
      tag: properties.tag,
      anchor: properties.anchor,
      items: [],
      indent: first.start.column,
    };
    for (;;) {
      if (scanner.checkToken("BlockEntry")) {
        const dash = scanner.getToken();
        let item;
        if (!scanner.checkToken("BlockEntry", "BlockEnd")) {
          item = this.parseNode(true, false);
        } else {
          item = emptyScalar(dash.end);
        }
        item.dash = dash.start.index;
        item.dashEnd = dash.end.index;
        item.dashColumn = dash.start.column;
        node.items.push(item);
        continue;
      }
      if (!scanner.checkToken("BlockEnd")) {
        this.expectedBlockEnd("block collection", scanner.peekToken());
      }
      scanner.getToken();
      break;
    }
    node.start = node.items.length > 0 ? Math.min(node.start, node.items[0].dash) : node.start;
    return this.finishCollection(
      node,
      node.items.map((item) => ({ end: item.empty ? item.dashEnd : item.end })),
    );
  }

  parseIndentlessSequence(properties) {
    const scanner = this.scanner;
    const node = {
      kind: "seq",
      style: "block",
      start: properties.startMark.index,
      end: properties.startMark.index,
      line: properties.startMark.line,
      column: properties.startMark.column,
      tag: properties.tag,
      anchor: properties.anchor,
      items: [],
      indent: scanner.peekToken().start.column,
      indentless: true,
    };
    while (scanner.checkToken("BlockEntry")) {
      const dash = scanner.getToken();
      let item;
      if (!scanner.checkToken("BlockEntry", "Key", "Value", "BlockEnd")) {
        item = this.parseNode(true, false);
      } else {
        item = emptyScalar(dash.end);
      }
      item.dash = dash.start.index;
      item.dashEnd = dash.end.index;
      item.dashColumn = dash.start.column;
      node.items.push(item);
    }
    node.start = node.items[0].dash;
    return this.finishCollection(
      node,
      node.items.map((item) => ({ end: item.empty ? item.dashEnd : item.end })),
    );
  }

  parseFlowSequence(properties) {
    const scanner = this.scanner;
    const open = scanner.getToken();
    const node = {
      kind: "seq",
      style: "flow",
      start: properties.startMark.index,
      end: open.end.index,
      line: properties.startMark.line,
      column: properties.startMark.column,
      tag: properties.tag,
      anchor: properties.anchor,
      items: [],
      open: open.start.index,
    };
    let first = true;
    for (;;) {
      if (!scanner.checkToken("FlowSequenceEnd")) {
        if (!first) {
          if (scanner.checkToken("FlowEntry")) {
            scanner.getToken();
          } else {
            const token = scanner.peekToken();
            scanner.fail(
              "syntax",
              `while parsing a flow sequence: expected ',' or ']', but got '${this.tokenName(token)}'`,
              token.start,
            );
          }
        }
        first = false;
        if (scanner.checkToken("Key")) {
          node.items.push(this.parseFlowSingleMapping());
          continue;
        }
        if (!scanner.checkToken("FlowSequenceEnd")) {
          node.items.push(this.parseNode(false, false));
          continue;
        }
      }
      const close = scanner.getToken();
      node.end = close.end.index;
      break;
    }
    return node;
  }

  parseFlowSingleMapping() {
    const scanner = this.scanner;
    const key = scanner.getToken();
    if (key.explicit) {
      scanner.fail("complex-key", "explicit keys (?) are not supported; write the key on one line", key.start);
    }
    let keyNode;
    if (!scanner.checkToken("Value", "FlowEntry", "FlowSequenceEnd")) {
      keyNode = this.parseNode(false, false);
    } else {
      keyNode = emptyScalar(key.end);
    }
    let valueNode;
    let colon = -1;
    if (scanner.checkToken("Value")) {
      const value = scanner.getToken();
      colon = value.start.index;
      if (!scanner.checkToken("FlowEntry", "FlowSequenceEnd")) {
        valueNode = this.parseNode(false, false);
      } else {
        valueNode = emptyScalar(value.end);
      }
    } else {
      valueNode = emptyScalar(scanner.peekToken().start);
    }
    const entry = this.entry(keyNode, valueNode, colon);
    return {
      kind: "map",
      style: "flow",
      single: true,
      start: key.start.index,
      end: entry.end,
      line: key.start.line,
      column: key.start.column,
      tag: null,
      anchor: null,
      entries: [entry],
    };
  }

  parseFlowMapping(properties) {
    const scanner = this.scanner;
    const open = scanner.getToken();
    const node = {
      kind: "map",
      style: "flow",
      start: properties.startMark.index,
      end: open.end.index,
      line: properties.startMark.line,
      column: properties.startMark.column,
      tag: properties.tag,
      anchor: properties.anchor,
      entries: [],
      open: open.start.index,
    };
    let first = true;
    for (;;) {
      if (!scanner.checkToken("FlowMappingEnd")) {
        if (!first) {
          if (scanner.checkToken("FlowEntry")) {
            scanner.getToken();
          } else {
            const token = scanner.peekToken();
            scanner.fail(
              "syntax",
              `while parsing a flow mapping: expected ',' or '}', but got '${this.tokenName(token)}'`,
              token.start,
            );
          }
        }
        first = false;
        if (scanner.checkToken("Key")) {
          const key = scanner.getToken();
          if (key.explicit) {
            scanner.fail("complex-key", "explicit keys (?) are not supported; write the key on one line", key.start);
          }
          let keyNode;
          if (!scanner.checkToken("Value", "FlowEntry", "FlowMappingEnd")) {
            keyNode = this.parseNode(false, false);
          } else {
            keyNode = emptyScalar(key.end);
          }
          let valueNode;
          let colon = -1;
          if (scanner.checkToken("Value")) {
            const value = scanner.getToken();
            colon = value.start.index;
            if (!scanner.checkToken("FlowEntry", "FlowMappingEnd")) {
              valueNode = this.parseNode(false, false);
            } else {
              valueNode = emptyScalar(value.end);
            }
          } else {
            valueNode = emptyScalar(scanner.peekToken().start);
          }
          node.entries.push(this.entry(keyNode, valueNode, colon));
          continue;
        }
        if (!scanner.checkToken("FlowMappingEnd")) {
          const keyNode = this.parseNode(false, false);
          node.entries.push(this.entry(keyNode, emptyScalar(scanner.peekToken().start), -1));
          continue;
        }
      }
      const close = scanner.getToken();
      node.end = close.end.index;
      break;
    }
    return node;
  }
}

// Values.

function markFor(node) {
  return markOf(node);
}

function keyIdentity(key) {
  if (key.type === "bool") {
    return `n:${key.value ? 1 : 0}`;
  }
  if (key.type === "int" || key.type === "float") {
    return `n:${key.value}`;
  }
  if (key.type === "timestamp") {
    return `t:${key.value.iso}`;
  }
  if (key.type === "null") {
    return "null";
  }
  return `s:${key.text}`;
}

/** The pairs of a mapping node with merge keys applied, as the loader orders them. */
export function mappingPairs(node, fail) {
  const merged = [];
  const own = [];
  for (const entry of node.entries) {
    const key = entry.key;
    if (key.kind === "scalar" && key.type === "merge") {
      const value = entry.value;
      if (value.kind === "map") {
        merged.push(...mappingPairs(value, fail));
      } else if (value.kind === "seq") {
        const parts = [];
        for (const item of value.items) {
          if (item.kind !== "map") {
            fail("merge", `expected a mapping for merging, but found ${item.kind}`, markFor(item));
          }
          parts.push(mappingPairs(item, fail));
        }
        parts.reverse();
        for (const pairs of parts) {
          merged.push(...pairs);
        }
      } else {
        fail(
          "merge",
          "expected a mapping or list of mappings for merging, but found a scalar",
          markFor(value),
        );
      }
    } else {
      own.push([key, entry.value]);
    }
  }
  return merged.concat(own);
}

function buildValue(node, context) {
  if (node.kind === "scalar") {
    if (node.type === "merge" || node.type === "value") {
      context.fail(
        "constructor",
        `could not determine a constructor for the tag of "${node.text}"`,
        markFor(node),
      );
    }
    return node.value;
  }
  if (node.kind === "seq") {
    return node.items.map((item) => buildValue(item, context));
  }
  const result = {};
  // A mapping with a merge key is locked as a whole; a key written twice locks
  // both of its entries, so the editor never has to say which one it changed.
  const first = new Map();
  for (const entry of node.entries) {
    const key = entry.key;
    if (key.kind !== "scalar") {
      continue;
    }
    if (key.type === "merge") {
      node.locked = "merge-key";
      continue;
    }
    const identity = keyIdentity(key);
    const earlier = first.get(identity);
    if (earlier === undefined) {
      first.set(identity, entry);
    } else {
      earlier.locked = "duplicate-key";
      entry.locked = "duplicate-key";
      context.warnings.push({
        code: "duplicate-key",
        message: `the key "${key.text}" is written more than once; the last value is used`,
        line: key.line + 1,
        column: key.column + 1,
        firstLine: earlier.key.line + 1,
      });
    }
  }
  if (node.locked === "merge-key") {
    const scalarEntries = node.entries.filter((entry) => entry.key.kind === "scalar");
    const own = new Set(scalarEntries.filter((entry) => entry.key.type !== "merge").map((entry) => entry.key.text));
    const merged = [...new Set(mappingPairs(node, context.fail).map(([key]) => key.text))].filter(
      (name) => !own.has(name),
    );
    const at = scalarEntries.find((entry) => entry.key.type === "merge").key;
    context.warnings.push({
      code: "merge-key",
      message:
        merged.length > 0
          ? `the keys ${merged.join(", ")} come from a merge key (<<)`
          : "a merge key (<<) adds no keys that are not written here",
      line: at.line + 1,
      column: at.column + 1,
    });
  }
  for (const [key, value] of mappingPairs(node, context.fail)) {
    if (key.kind !== "scalar") {
      context.fail("constructor", "found unhashable key", markFor(key));
    }
    const name = key.text;
    Object.defineProperty(result, name, {
      value: buildValue(value, context),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return result;
}

// Document.

function checkPrintable(text) {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        index += 1;
        continue;
      }
    }
    const allowed =
      code === 0x09 ||
      code === 0x0a ||
      code === 0x0d ||
      (code >= 0x20 && code <= 0x7e) ||
      code === 0x85 ||
      (code >= 0xa0 && code <= 0xd7ff) ||
      (code >= 0xe000 && code <= 0xfffd);
    if (!allowed) {
      return { index, code };
    }
  }
  return null;
}

function positionOf(text, index) {
  let line = 0;
  let lineStart = 0;
  for (let position = 0; position < index; position += 1) {
    if (text[position] === "\n") {
      line += 1;
      lineStart = position + 1;
    }
  }
  return { index, line, column: index - lineStart };
}

function displayColumn(text, mark) {
  const lineStart = mark.index - mark.column;
  let count = 0;
  for (let position = lineStart; position < mark.index; position += 1) {
    const code = text.charCodeAt(position);
    if (!(code >= 0xdc00 && code <= 0xdfff)) {
      count += 1;
    }
  }
  return count + 1;
}

function lineStartsOf(text) {
  const starts = [0];
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === "\n") {
      starts.push(index + 1);
    }
  }
  return starts;
}

function lineEndings(text) {
  const crlf = (text.match(/\r\n/g) || []).length;
  const lf = (text.match(/\n/g) || []).length - crlf;
  return crlf > lf ? "\r\n" : "\n";
}

function collectStyle(root) {
  const widths = new Map();
  let indentless = 0;
  let indented = 0;
  const visit = (node, parentIndent) => {
    if (node.kind === "map") {
      if (node.style === "block") {
        if (parentIndent !== null && node.indent > parentIndent) {
          widths.set(node.indent - parentIndent, (widths.get(node.indent - parentIndent) || 0) + 1);
        }
      }
      for (const entry of node.entries) {
        const child = entry.value;
        if (child.kind === "seq" && child.style === "block" && node.style === "block") {
          if (child.indent === node.indent) {
            indentless += 1;
          } else {
            indented += 1;
            if (child.indent > node.indent) {
              widths.set(child.indent - node.indent, (widths.get(child.indent - node.indent) || 0) + 1);
            }
          }
        }
        visit(child, node.style === "block" ? node.indent : null);
      }
    } else if (node.kind === "seq") {
      for (const item of node.items) {
        visit(item, null);
      }
    }
  };
  visit(root, null);
  let unit = 2;
  let best = 0;
  for (const [width, count] of widths) {
    if (count > best || (count === best && width < unit)) {
      unit = width;
      best = count;
    }
  }
  return { indent: unit, seq: indentless > indented ? "indentless" : "indented" };
}

/**
 * Reads YAML text the way ASH's loader does and returns the document:
 * `{ok, text, root, value, refusal, warnings, comments, lineStarts, newline, style}`.
 * `root` is the node tree (null for an empty document), `value` the loaded value
 * (mappings are plain objects, references are Reference objects, dates are
 * Timestamp objects). When the text cannot be read, ok is false and `refusal`
 * holds `{code, message, line, column, offset}` with 1-based line and column.
 */
export function readYaml(text) {
  const doc = {
    ok: false,
    text,
    root: null,
    value: undefined,
    refusal: null,
    warnings: [],
    comments: [],
    lineStarts: lineStartsOf(text),
    newline: lineEndings(text),
    plainBreaks: !/\r(?!\n)/.test(text) && !text.includes(NEL) && !text.includes(LS) && !text.includes(PS),
    style: { indent: 2, seq: "indented" },
  };
  const refuse = (code, message, mark) => {
    // A text that is refused leaves nothing half-read behind.
    doc.root = null;
    doc.value = undefined;
    doc.warnings = [];
    doc.comments = [];
    doc.refusal = {
      code,
      message,
      line: mark.line + 1,
      column: displayColumn(text, mark),
      offset: mark.index,
    };
    return doc;
  };
  if (utf8Length(text) > MAX_BYTES) {
    return refuse("too-large", "the text is larger than 2 MiB, which the editor does not open", {
      index: 0,
      line: 0,
      column: 0,
    });
  }
  const bad = checkPrintable(text);
  if (bad !== null) {
    const mark = positionOf(text, bad.index);
    return refuse(
      "character",
      `unacceptable character #x${bad.code.toString(16).padStart(4, "0")}: special characters are not allowed`,
      mark,
    );
  }
  const scanner = new Scanner(text);
  try {
    doc.root = new Composer(scanner).compose();
    const context = {
      warnings: doc.warnings,
      fail: (code, message, mark) => scanner.fail(code, message, mark),
    };
    doc.value = doc.root === null ? null : buildValue(doc.root, context);
  } catch (error) {
    if (error instanceof YamlError) {
      return refuse(error.code, error.message, error.mark);
    }
    throw error;
  }
  doc.comments = scanner.comments;
  if (doc.root !== null) {
    doc.style = collectStyle(doc.root);
  }
  doc.ok = true;
  return doc;
}
