// How a plain YAML scalar is read and written for ASH's configuration files.
//
// ASH reads YAML with PyYAML's SafeLoader (YAML 1.1) plus one extra resolver for
// environment references. This module holds the same resolution rules, so the
// editor reads `on`, `0755`, `1:30` and `2026-12-31` the way a scan does, and the
// rule for writing a string so that both YAML 1.1 and YAML 1.2 readers get the
// same text back.
//
// DOM-free. Imports nothing.

/** A reference such as ${NAME} or ${NAME:default}, kept as written. */
export class Reference {
  constructor(text, explicit) {
    this.text = text;
    this.explicit = Boolean(explicit);
    Object.freeze(this);
  }

  toString() {
    return this.text;
  }
}

/** A YAML date or timestamp, kept as the ISO text a Python reader gives it. */
export class Timestamp {
  constructor(kind, iso) {
    this.kind = kind; // 'date' or 'datetime'
    this.iso = iso;
    Object.freeze(this);
  }

  toString() {
    return this.iso;
  }
}

/** A scalar the loader cannot build, such as a date that does not exist. */
export class ScalarError extends Error {}

const RESOLVERS = {
  bool: /^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$/,
  float:
    /^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$/,
  int: /^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$/,
  merge: /^(?:<<)$/,
  null: /^(?:~|null|Null|NULL|)$/,
  timestamp:
    /^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$/,
  value: /^(?:=)$/,
};

// PyYAML tries the resolvers registered for the scalar's first character, in the
// order they were registered; ASH's reference resolver is tried after them.
const BY_FIRST_CHARACTER = new Map();

function register(name, characters) {
  for (const character of characters) {
    if (!BY_FIRST_CHARACTER.has(character)) {
      BY_FIRST_CHARACTER.set(character, []);
    }
    BY_FIRST_CHARACTER.get(character).push(name);
  }
}

register("bool", "yYnNtTfFoO");
register("float", "-+0123456789.");
register("int", "-+0123456789");
register("merge", "<");
register("null", ["~", "n", "N", ""]);
register("timestamp", "0123456789");
register("value", "=");

const BOOLEAN_WORDS = {
  yes: true,
  no: false,
  true: true,
  false: false,
  on: true,
  off: false,
};

const REFERENCE_HEAD = /^\$\{([\p{L}\p{N}_]+)(:?)([^}\r\n]*)\}/u;

/**
 * The reference a scalar starts with, as ASH's loader recognizes one: `${NAME}`
 * or `${NAME:default}` up to the first closing brace, with anything after it.
 * Returns null when the text does not start with one.
 */
export function matchReference(text) {
  const match = REFERENCE_HEAD.exec(text);
  if (match === null) {
    return null;
  }
  return { name: match[1], colon: match[2] === ":", head: match[0] };
}

function parseDigits(digits, radix) {
  if (digits === "") {
    throw new ScalarError("an integer needs at least one digit");
  }
  let result = 0n;
  const big = BigInt(radix);
  for (const character of digits) {
    const digit = parseInt(character, 36);
    if (Number.isNaN(digit) || digit >= radix) {
      throw new ScalarError(`"${character}" is not a base ${radix} digit`);
    }
    result = result * big + BigInt(digit);
  }
  return result;
}

function integerResult(big) {
  const number = Number(big);
  const exact = Number.isSafeInteger(number);
  // Beyond 2**53 a number would round the digits, so the value stays a BigInt.
  return { type: "int", value: exact ? number : big, digits: big.toString(), exact };
}

function constructInt(text) {
  let value = text.replace(/_/g, "");
  if (value === "") {
    throw new ScalarError("an integer needs at least one digit");
  }
  let negative = false;
  if (value[0] === "-") {
    negative = true;
  }
  if (value[0] === "+" || value[0] === "-") {
    value = value.slice(1);
  }
  let big;
  if (value === "0") {
    big = 0n;
  } else if (value.startsWith("0b")) {
    big = parseDigits(value.slice(2), 2);
  } else if (value.startsWith("0x")) {
    big = parseDigits(value.slice(2).toLowerCase(), 16);
  } else if (value[0] === "0") {
    big = parseDigits(value, 8);
  } else if (value.includes(":")) {
    let base = 1n;
    big = 0n;
    for (const part of value.split(":").reverse()) {
      big += parseDigits(part, 10) * base;
      base *= 60n;
    }
  } else {
    big = parseDigits(value, 10);
  }
  return integerResult(negative ? -big : big);
}

function constructFloat(text) {
  let value = text.replace(/_/g, "").toLowerCase();
  let sign = 1;
  if (value[0] === "-") {
    sign = -1;
  }
  if (value[0] === "+" || value[0] === "-") {
    value = value.slice(1);
  }
  if (value === ".inf") {
    return { type: "float", value: sign * Infinity };
  }
  if (value === ".nan") {
    return { type: "float", value: NaN };
  }
  let number;
  if (value.includes(":")) {
    let base = 1;
    number = 0;
    for (const part of value.split(":").reverse()) {
      number += Number(part) * base;
      base *= 60;
    }
  } else {
    number = Number(value);
  }
  if (Number.isNaN(number)) {
    throw new ScalarError(`could not convert "${text}" to a float`);
  }
  return { type: "float", value: sign * number };
}

const TIMESTAMP_PARTS =
  /^(?<year>[0-9][0-9][0-9][0-9])-(?<month>[0-9][0-9]?)-(?<day>[0-9][0-9]?)(?:(?:[Tt]|[ \t]+)(?<hour>[0-9][0-9]?):(?<minute>[0-9][0-9]):(?<second>[0-9][0-9])(?:\.(?<fraction>[0-9]*))?(?:[ \t]*(?<tz>Z|(?<tzSign>[-+])(?<tzHour>[0-9][0-9]?)(?::(?<tzMinute>[0-9][0-9]))?))?)?$/;

function pad(number, width) {
  return String(number).padStart(width, "0");
}

function daysInMonth(year, month) {
  if (month === 2) {
    const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function constructTimestamp(text) {
  const parts = TIMESTAMP_PARTS.exec(text);
  if (parts === null) {
    throw new ScalarError(`"${text}" is not a timestamp`);
  }
  const g = parts.groups;
  const year = Number(g.year);
  const month = Number(g.month);
  const day = Number(g.day);
  if (year < 1) {
    throw new ScalarError("year is out of range");
  }
  if (month < 1 || month > 12) {
    throw new ScalarError("month must be in 1..12");
  }
  if (day < 1 || day > daysInMonth(year, month)) {
    throw new ScalarError("day is out of range for month");
  }
  const date = `${pad(year, 4)}-${pad(month, 2)}-${pad(day, 2)}`;
  if (g.hour === undefined) {
    return { type: "timestamp", value: new Timestamp("date", date) };
  }
  const hour = Number(g.hour);
  const minute = Number(g.minute);
  const second = Number(g.second);
  if (hour > 23) {
    throw new ScalarError("hour must be in 0..23");
  }
  if (minute > 59) {
    throw new ScalarError("minute must be in 0..59");
  }
  if (second > 59) {
    throw new ScalarError("second must be in 0..59");
  }
  let iso = `${date}T${pad(hour, 2)}:${pad(minute, 2)}:${pad(second, 2)}`;
  if (g.fraction) {
    const micro = g.fraction.slice(0, 6).padEnd(6, "0");
    if (Number(micro) !== 0) {
      iso += `.${micro}`;
    }
  }
  if (g.tzSign !== undefined) {
    const minutes = Number(g.tzHour) * 60 + Number(g.tzMinute || 0);
    if (minutes >= 24 * 60) {
      throw new ScalarError("the offset must be less than 24 hours");
    }
    iso += `${g.tzSign}${pad(Math.floor(minutes / 60), 2)}:${pad(minutes % 60, 2)}`;
  } else if (g.tz !== undefined) {
    iso += "+00:00";
  }
  return { type: "timestamp", value: new Timestamp("datetime", iso) };
}

function construct(name, text) {
  if (name === "null") {
    return { type: "null", value: null };
  }
  if (name === "bool") {
    return { type: "bool", value: BOOLEAN_WORDS[text.toLowerCase()] };
  }
  if (name === "int") {
    return constructInt(text);
  }
  if (name === "float") {
    return constructFloat(text);
  }
  if (name === "timestamp") {
    return constructTimestamp(text);
  }
  return { type: name, value: text }; // merge and value
}

/**
 * How ASH's loader reads a plain scalar with no tag: `{type, value}`, where type
 * is null, bool, int, float, timestamp, merge, value, env (a reference) or str.
 * An int also carries `digits` (the exact decimal text) and `exact` (false when
 * the number is beyond 2**53). Throws ScalarError where the loader fails.
 */
export function resolvePlain(text) {
  const names = BY_FIRST_CHARACTER.get(text === "" ? "" : text[0]) || [];
  for (const name of names) {
    if (RESOLVERS[name].test(text)) {
      return construct(name, text);
    }
  }
  if (matchReference(text) !== null) {
    return { type: "env", value: text };
  }
  return { type: "str", value: text };
}

const CORE_TAGS = new Set(["str", "int", "float", "bool", "null"]);

/**
 * The value of a scalar the file tags with one of the core tags (`!!int` and
 * the like), built the way the loader builds it from the text as written.
 */
export function constructTagged(name, text) {
  if (!CORE_TAGS.has(name)) {
    throw new ScalarError(`the tag !!${name} does not take a scalar`);
  }
  if (name === "str") {
    return { type: "str", value: text };
  }
  if (name === "null") {
    return { type: "null", value: null };
  }
  if (name === "bool") {
    const word = text.toLowerCase();
    if (!Object.prototype.hasOwnProperty.call(BOOLEAN_WORDS, word)) {
      throw new ScalarError(`"${text}" is not a boolean`);
    }
    return { type: "bool", value: BOOLEAN_WORDS[word] };
  }
  return name === "int" ? constructInt(text) : constructFloat(text);
}

const YAML12 = {
  null: /^(?:~|null|Null|NULL|)$/,
  bool: /^(?:true|True|TRUE|false|False|FALSE)$/,
  int: /^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$/,
  float:
    /^(?:[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$/,
};

/** How a YAML 1.2 core reader (most editors) reads a plain scalar: a type name. */
export function yaml12Type(text) {
  for (const name of ["null", "bool", "int", "float"]) {
    if (YAML12[name].test(text)) {
      return name;
    }
  }
  return "str";
}

/** The type ASH's loader gives a plain scalar, or "error" where the loader fails on it. */
function ashType(text) {
  try {
    return resolvePlain(text).type;
  } catch (error) {
    if (error instanceof ScalarError) {
      return "error";
    }
    throw error;
  }
}

function yaml12Integer(text) {
  const sign = text[0] === "-" ? -1n : 1n;
  // BigInt reads the 0o and 0x forms and, for decimal text, ignores leading zeros.
  return sign * BigInt(text.replace(/^[-+]/, ""));
}

/**
 * Whether ASH's loader and a YAML 1.2 reader read the plain scalar differently:
 * `on` is true to one and text to the other, `0755` is 493 to one and 755 to the
 * other. A reference is text to a 1.2 reader, so it does not count.
 */
export function readingsDiffer(text) {
  const asAsh = ashType(text);
  const asOther = yaml12Type(text);
  if (asAsh !== asOther) {
    return !(asAsh === "env" && asOther === "str");
  }
  if (asAsh === "int") {
    const reading = resolvePlain(text);
    return BigInt(reading.digits) !== yaml12Integer(text);
  }
  return false;
}

const INDICATORS = "-?:,[]{}#&*!|>'\"%@`";
const FLOW_INDICATORS = ",[]{}";

function isHighSurrogate(code) {
  return code >= 0xd800 && code <= 0xdbff;
}

function isLowSurrogate(code) {
  return code >= 0xdc00 && code <= 0xdfff;
}

// A surrogate counts as a character only inside a pair; a lone one is not text a
// YAML file can hold as it is.
function hasUnsafeCharacter(text) {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code < 0x20 || (code >= 0x7f && code <= 0xa0)) {
      return true;
    }
    if (code === 0x2028 || code === 0x2029 || code === 0xfeff) {
      return true;
    }
    if (isHighSurrogate(code) && isLowSurrogate(text.charCodeAt(index + 1))) {
      index += 1;
    } else if (isHighSurrogate(code) || isLowSurrogate(code)) {
      return true;
    }
  }
  return false;
}

/**
 * Whether the text is a valid plain scalar by its syntax alone: no leading
 * indicator, no `: ` or ` #`, no edge spaces, nothing a line cannot hold. What
 * the loader would make of it is not looked at. In a flow collection the flow
 * indicators are refused too.
 */
export function plainSyntaxOk(text, inFlow = false) {
  if (text === "" || hasUnsafeCharacter(text)) {
    return false;
  }
  if (text[0] === " " || text[text.length - 1] === " ") {
    return false;
  }
  if (INDICATORS.includes(text[0])) {
    return false;
  }
  if (text.startsWith("---") || text.startsWith("...")) {
    return false;
  }
  if (text.includes(": ") || text.includes(" #") || text.endsWith(":")) {
    return false;
  }
  return !(inFlow && [...FLOW_INDICATORS].some((character) => text.includes(character)));
}

/**
 * Whether the text can be written as a plain scalar and be read back as the same
 * text by ASH's loader and by a YAML 1.2 reader.
 */
export function plainSafe(text, inFlow = false) {
  return plainSyntaxOk(text, inFlow) && ashType(text) === "str" && yaml12Type(text) === "str";
}

function hex(code, width) {
  return code.toString(16).toUpperCase().padStart(width, "0");
}

/** The text as a double-quoted scalar, with escapes for what cannot stay raw. */
export function quoteDouble(text) {
  let out = '"';
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    const code = text.charCodeAt(index);
    if (character === "\\") {
      out += "\\\\";
    } else if (character === '"') {
      out += '\\"';
    } else if (character === "\n") {
      out += "\\n";
    } else if (character === "\t") {
      out += "\\t";
    } else if (character === "\r") {
      out += "\\r";
    } else if (code < 0x20 || (code >= 0x7f && code <= 0xa0)) {
      out += `\\x${hex(code, 2)}`;
    } else if (code === 0x2028 || code === 0x2029 || code === 0xfeff) {
      out += `\\${"u"}${hex(code, 4)}`;
    } else if (isHighSurrogate(code) && isLowSurrogate(text.charCodeAt(index + 1))) {
      out += character + text[index + 1];
      index += 1;
    } else if (isHighSurrogate(code) || isLowSurrogate(code)) {
      out += `\\${"u"}${hex(code, 4)}`;
    } else {
      out += character;
    }
  }
  return `${out}"`;
}

/** The text as a single-quoted scalar, or null when it holds what cannot be quoted so. */
export function quoteSingle(text) {
  if (hasUnsafeCharacter(text)) {
    return null;
  }
  return `'${text.replace(/'/g, "''")}'`;
}

/** UTF-8 length of the text, counted without encoding it. */
export function utf8Length(text) {
  let total = 0;
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code < 0x80) {
      total += 1;
    } else if (code < 0x800) {
      total += 2;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      total += 4;
      index += 1;
    } else {
      total += 3;
    }
  }
  return total;
}
