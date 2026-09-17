// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A JSON reader written against nothing but the JDK.
 *
 * <p>WHY THIS EXISTS INSTEAD OF A LIBRARY
 *
 * <p>A JetBrains plugin distribution zip bundles its runtime classpath into {@code lib/},
 * so a runtime dependency here is third-party code inside an artifact this project
 * publishes as a release asset. {@code packaging/README.md} draws that line and explains
 * why the guard against crossing it is phrased as a mechanical count rather than a
 * judgment call. {@code assert-plugin-zip-contents.py} is this plugin's version of that
 * count: it fails on any jar in {@code lib/} that is not this project's own output. Adding
 * a JSON library would make that check fail, which is the point of having it.
 *
 * <p>The IntelliJ Platform does ship JSON libraries in its own {@code lib/} directory, and
 * a {@code compileOnly} dependency on one would also keep the zip clean. That was rejected
 * for a different reason: which libraries the platform bundles is not part of the plugin
 * SDK's compatibility contract, so a plugin that compiles against one is relying on an
 * implementation detail of the IDE build it happened to be compiled against. The failure
 * mode is a {@code NoClassDefFoundError} at annotation time on some future IDE, and for a
 * security tool that surfaces as zero findings -- indistinguishable from a clean file,
 * which is the failure this whole branch exists to remove.
 *
 * <p>WHAT IT DOES AND DOES NOT ACCEPT
 *
 * <p>RFC 8259 JSON, and nothing else. No comments, no trailing commas, no single quotes,
 * no unquoted keys, no NaN or Infinity. Every rejection throws {@link SyntaxException}
 * naming the character offset. Silence is never an option: a parser that returned an empty
 * document for malformed input would put this plugin back in the position of reporting no
 * findings for a reason the user cannot see.
 *
 * <p>Values map to {@code Map<String, Object>} (insertion-ordered), {@code List<Object>},
 * {@code String}, {@code Double}, {@code Boolean} and {@code null}.
 *
 * <p>Numbers all become {@code Double}, including integers. SARIF line and column numbers
 * are integers in practice, but JSON does not distinguish, and a reader that guessed
 * {@code Long} for some inputs and {@code Double} for others would push the guess onto
 * every call site. {@link #asInt} is the one place the conversion happens.
 *
 * <p>KNOWN LIMITATIONS
 *
 * <p>Nesting depth is capped, because a recursive-descent parser on deeply nested input
 * overflows the stack, and a {@code StackOverflowError} escaping an annotator is not
 * something the platform reports usefully. The cap is far above any real SARIF document.
 *
 * <p>Duplicate object keys: the last one wins, matching most implementations. SARIF does
 * not produce them.
 */
public final class Json {

    /**
     * Deep enough for any SARIF document and shallow enough not to overflow the default
     * thread stack. ASH's own SARIF nests about ten levels; a run's {@code invocations}
     * carry a nested {@code tool.driver.properties.scanner_details.tool_invocation}, which
     * is the deepest path measured in real output.
     */
    static final int MAX_DEPTH = 200;

    private final String text;
    private int at;

    private Json(String text) {
        this.text = text;
        this.at = 0;
    }

    /** Thrown for any input this reader will not accept. Never swallowed. */
    public static final class SyntaxException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private final int offset;

        SyntaxException(String message, int offset) {
            super(message + " (at offset " + offset + ")");
            this.offset = offset;
        }

        /** The character offset the reader had reached when it gave up. */
        public int offset() {
            return offset;
        }
    }

    /**
     * Parses a whole document.
     *
     * @throws SyntaxException if the text is not a single complete JSON value, including
     *     when it is null or blank -- an empty SARIF file is a failure to report, not an
     *     empty result set.
     */
    public static Object parse(String text) {
        if (text == null) {
            throw new SyntaxException("no document to parse", 0);
        }
        Json reader = new Json(text);
        reader.skipWhitespace();
        Object value = reader.readValue(0);
        reader.skipWhitespace();
        if (reader.at != text.length()) {
            throw new SyntaxException("trailing content after the document", reader.at);
        }
        return value;
    }

    private Object readValue(int depth) {
        if (depth > MAX_DEPTH) {
            throw new SyntaxException("nesting deeper than " + MAX_DEPTH + " levels", at);
        }
        char c = peek();
        switch (c) {
            case '{':
                return readObject(depth);
            case '[':
                return readArray(depth);
            case '"':
                return readString();
            case 't':
                expectLiteral("true");
                return Boolean.TRUE;
            case 'f':
                expectLiteral("false");
                return Boolean.FALSE;
            case 'n':
                expectLiteral("null");
                return null;
            default:
                return readNumber();
        }
    }

    private Map<String, Object> readObject(int depth) {
        at++; // consume '{'
        Map<String, Object> members = new LinkedHashMap<>();
        skipWhitespace();
        if (peek() == '}') {
            at++;
            return members;
        }
        while (true) {
            skipWhitespace();
            if (peek() != '"') {
                throw new SyntaxException("object key must be a quoted string", at);
            }
            String key = readString();
            skipWhitespace();
            if (peek() != ':') {
                throw new SyntaxException("expected ':' after object key", at);
            }
            at++;
            skipWhitespace();
            members.put(key, readValue(depth + 1));
            skipWhitespace();
            char c = peek();
            if (c == ',') {
                at++;
                continue;
            }
            if (c == '}') {
                at++;
                return members;
            }
            throw new SyntaxException("expected ',' or '}' in object", at);
        }
    }

    private List<Object> readArray(int depth) {
        at++; // consume '['
        List<Object> items = new ArrayList<>();
        skipWhitespace();
        if (peek() == ']') {
            at++;
            return items;
        }
        while (true) {
            skipWhitespace();
            items.add(readValue(depth + 1));
            skipWhitespace();
            char c = peek();
            if (c == ',') {
                at++;
                continue;
            }
            if (c == ']') {
                at++;
                return items;
            }
            throw new SyntaxException("expected ',' or ']' in array", at);
        }
    }

    private String readString() {
        at++; // consume opening quote
        StringBuilder out = new StringBuilder();
        while (true) {
            if (at >= text.length()) {
                throw new SyntaxException("unterminated string", at);
            }
            char c = text.charAt(at++);
            if (c == '"') {
                return out.toString();
            }
            if (c != '\\') {
                // Unescaped control characters are invalid JSON. Accepting them would let
                // a truncated file that happens to split inside a string parse as though
                // it were whole.
                if (c < 0x20) {
                    throw new SyntaxException("unescaped control character in string", at - 1);
                }
                out.append(c);
                continue;
            }
            if (at >= text.length()) {
                throw new SyntaxException("escape at end of input", at);
            }
            char esc = text.charAt(at++);
            switch (esc) {
                case '"':
                    out.append('"');
                    break;
                case '\\':
                    out.append('\\');
                    break;
                case '/':
                    out.append('/');
                    break;
                case 'b':
                    out.append('\b');
                    break;
                case 'f':
                    out.append('\f');
                    break;
                case 'n':
                    out.append('\n');
                    break;
                case 'r':
                    out.append('\r');
                    break;
                case 't':
                    out.append('\t');
                    break;
                case 'u':
                    out.append(readHexEscape());
                    break;
                default:
                    throw new SyntaxException("unknown escape '\\" + esc + "'", at - 1);
            }
        }
    }

    private char readHexEscape() {
        if (at + 4 > text.length()) {
            throw new SyntaxException("truncated \\u escape", at);
        }
        int value = 0;
        for (int i = 0; i < 4; i++) {
            char c = text.charAt(at + i);
            int digit = Character.digit(c, 16);
            if (digit < 0) {
                throw new SyntaxException("bad hex digit '" + c + "' in \\u escape", at + i);
            }
            value = (value << 4) | digit;
        }
        at += 4;
        return (char) value;
    }

    private Double readNumber() {
        int start = at;
        if (peek() == '-') {
            at++;
        }
        // Deliberately permissive about the shape here and strict in Double.parseDouble
        // below: duplicating the grammar's integer/fraction/exponent rules by hand is how
        // a hand-written parser ends up accepting something the rest of the world does
        // not. Scan the run of characters a number can contain, then let the JDK decide.
        while (at < text.length() && isNumberChar(text.charAt(at))) {
            at++;
        }
        String literal = text.substring(start, at);
        if (literal.isEmpty() || "-".equals(literal)) {
            throw new SyntaxException("expected a value", start);
        }
        // parseDouble accepts forms JSON does not: leading '+', hex floats, "Infinity",
        // "NaN", and a trailing 'd' or 'f' suffix. Reject those before it sees them so a
        // non-JSON document cannot parse.
        if (!literal.matches("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")) {
            throw new SyntaxException("not a JSON number: '" + literal + "'", start);
        }
        return Double.valueOf(Double.parseDouble(literal));
    }

    private static boolean isNumberChar(char c) {
        return (c >= '0' && c <= '9')
                || c == '-'
                || c == '+'
                || c == '.'
                || c == 'e'
                || c == 'E';
    }

    private void expectLiteral(String literal) {
        if (!text.startsWith(literal, at)) {
            throw new SyntaxException("expected '" + literal + "'", at);
        }
        at += literal.length();
    }

    private char peek() {
        if (at >= text.length()) {
            throw new SyntaxException("unexpected end of input", at);
        }
        return text.charAt(at);
    }

    private void skipWhitespace() {
        while (at < text.length()) {
            char c = text.charAt(at);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                at++;
            } else {
                return;
            }
        }
    }

    // ---------------------------------------------------------------------------------
    // Typed accessors.
    //
    // Every one of these returns a default rather than throwing on a shape mismatch, and
    // that asymmetry with the parser above is deliberate. A malformed FILE is a failure
    // the user must be told about. A missing or differently-typed FIELD is normal: SARIF
    // makes most properties optional, and ASH's own output omits columns entirely, so a
    // reader that threw on an absent field would report nothing for a document that is
    // valid and useful.
    // ---------------------------------------------------------------------------------

    /** The value at {@code key} if it is an object, otherwise an empty map. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> asObject(Object value) {
        if (value instanceof Map<?, ?>) {
            return (Map<String, Object>) value;
        }
        return Collections.emptyMap();
    }

    /** The value if it is an array, otherwise an empty list. */
    @SuppressWarnings("unchecked")
    public static List<Object> asArray(Object value) {
        if (value instanceof List<?>) {
            return (List<Object>) value;
        }
        return Collections.emptyList();
    }

    /** The value if it is a string, otherwise {@code fallback}. */
    public static String asString(Object value, String fallback) {
        return value instanceof String s ? s : fallback;
    }

    /**
     * The value as an {@code int} if it is a number, otherwise {@code fallback}.
     *
     * <p>Fractional and out-of-range values also return {@code fallback}. SARIF region
     * members are integers; anything else is a document this reader should not pretend to
     * understand, and a silently truncated line number would point an annotation at the
     * wrong code.
     */
    public static int asInt(Object value, int fallback) {
        if (!(value instanceof Double d)) {
            return fallback;
        }
        double raw = d.doubleValue();
        if (raw != Math.floor(raw) || Double.isInfinite(raw)) {
            return fallback;
        }
        if (raw < Integer.MIN_VALUE || raw > Integer.MAX_VALUE) {
            return fallback;
        }
        return (int) raw;
    }

    /** Reads {@code key} from {@code object} without an intermediate cast at the call site. */
    public static Object get(Map<String, Object> object, String key) {
        return object.get(key);
    }
}
