// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The parser's contract, and the rejections in particular.
 *
 * <p>The rejections are the interesting half. This reader is the only thing between a
 * truncated or half-written SARIF and a plugin that reports no findings, so every input it
 * cannot understand has to throw rather than return an empty document. A parser that silently
 * produced {@code {}} for a file cut off mid-write would put this plugin back in the position
 * of showing a clean editor for a reason the user cannot see.
 */
class JsonTest {

    @Test
    @DisplayName("reads the value types SARIF uses")
    void readsScalarsAndContainers() {
        Map<String, Object> root =
                Json.asObject(
                        Json.parse(
                                "{\"s\":\"text\",\"n\":42,\"f\":1.5,\"neg\":-7,\"e\":1e3,"
                                        + "\"t\":true,\"fa\":false,\"nul\":null,"
                                        + "\"a\":[1,\"two\",{\"deep\":true}],\"o\":{}}"));

        assertEquals("text", Json.asString(root.get("s"), ""));
        assertEquals(42, Json.asInt(root.get("n"), -1));
        assertEquals(1.5d, (Double) root.get("f"), 0.0);
        assertEquals(-7, Json.asInt(root.get("neg"), 0));
        assertEquals(1000, Json.asInt(root.get("e"), 0));
        assertEquals(Boolean.TRUE, root.get("t"));
        assertEquals(Boolean.FALSE, root.get("fa"));
        assertNull(root.get("nul"));
        assertTrue(root.containsKey("nul"), "an explicit null must still be a present key");

        List<Object> array = Json.asArray(root.get("a"));
        assertEquals(3, array.size());
        assertEquals(Boolean.TRUE, Json.asObject(array.get(2)).get("deep"));
        assertTrue(Json.asObject(root.get("o")).isEmpty());
    }

    @Test
    @DisplayName("keeps object key order, so document order is reportable")
    void preservesKeyOrder() {
        Map<String, Object> root = Json.asObject(Json.parse("{\"z\":1,\"a\":2,\"m\":3}"));
        assertEquals(List.of("z", "a", "m"), List.copyOf(root.keySet()));
    }

    @Test
    @DisplayName("handles every string escape, including surrogate pairs")
    void readsEscapes() {
        String value =
                Json.asString(
                        Json.parse("\"a\\\"b\\\\c\\/d\\be\\ff\\ng\\rh\\ti\\u0041\\uD83D\\uDE00\""),
                        "");
        assertEquals("a\"b\\c/d\be\ff\ng\rh\ti" + "A" + "\uD83D\uDE00", value);
    }

    @Test
    @DisplayName("skips whitespace between tokens but not inside them")
    void skipsWhitespace() {
        assertEquals(
                1,
                Json.asInt(Json.get(Json.asObject(Json.parse("  {\n\t\"k\" :\r\n 1 }  ")), "k"), 0));
    }

    @Test
    @DisplayName("the last duplicate key wins")
    void lastDuplicateKeyWins() {
        assertEquals(2, Json.asInt(Json.get(Json.asObject(Json.parse("{\"k\":1,\"k\":2}")), "k"), 0));
    }

    @ParameterizedTest
    @DisplayName("rejects input that is not a single complete JSON document")
    @ValueSource(
            strings = {
                "", // an empty file, which is what a half-written SARIF looks like
                "   ",
                "{", // truncated object
                "[", // truncated array
                "{\"k\"", // truncated after a key
                "{\"k\":}", // no value
                "{\"k\" 1}", // missing colon
                "{k:1}", // unquoted key
                "{'k':1}", // single quotes
                "{\"k\":1,}", // trailing comma in an object
                "[1,]", // trailing comma in an array
                "[1 2]", // missing comma
                "{\"k\":1} {\"k\":2}", // two documents
                "{\"k\":1}trailing",
                "\"unterminated",
                "\"bad \\q escape\"",
                "\"truncated \\u00\"",
                "\"bad hex \\u00zz\"",
                "\"raw\u0001control\"",
                "tru",
                "nul",
                "fals",
                "+1", // JSON has no leading plus
                "01", // no leading zeros
                ".5", // no bare fraction
                "1.", // no trailing point
                "-",
                "Infinity",
                "NaN",
                "0x10",
                "1d",
                "//comment\n1",
            })
    void rejectsMalformed(String text) {
        Json.SyntaxException thrown = assertThrows(Json.SyntaxException.class, () -> Json.parse(text));
        assertTrue(
                thrown.offset() >= 0,
                "every rejection must name where the reader gave up, or a bug report is a guess");
        assertTrue(thrown.getMessage().contains("offset"));
    }

    @Test
    @DisplayName("a null document is a rejection, not an empty result")
    void rejectsNull() {
        assertThrows(Json.SyntaxException.class, () -> Json.parse(null));
    }

    @Test
    @DisplayName("refuses input nested deeper than the cap instead of overflowing the stack")
    void rejectsExcessiveNesting() {
        String deep = "[".repeat(Json.MAX_DEPTH + 5) + "]".repeat(Json.MAX_DEPTH + 5);
        Json.SyntaxException thrown = assertThrows(Json.SyntaxException.class, () -> Json.parse(deep));
        assertTrue(thrown.getMessage().contains("nesting"));
    }

    @Test
    @DisplayName("accepts nesting up to the cap")
    void acceptsNestingAtTheCap() {
        String atCap = "[".repeat(Json.MAX_DEPTH) + "]".repeat(Json.MAX_DEPTH);
        assertEquals(1, Json.asArray(Json.parse(atCap)).size());
    }

    @Test
    @DisplayName("typed accessors return the fallback on a shape mismatch rather than throwing")
    void accessorsFallBack() {
        // Deliberately asymmetric with the parser above: a malformed FILE must throw, a
        // missing or differently-typed FIELD must not. SARIF makes most members optional and
        // ASH omits columns entirely, so throwing here would report nothing for a valid file.
        assertTrue(Json.asObject("not an object").isEmpty());
        assertTrue(Json.asObject(null).isEmpty());
        assertTrue(Json.asArray("not an array").isEmpty());
        assertTrue(Json.asArray(null).isEmpty());
        assertEquals("fb", Json.asString(42d, "fb"));
        assertEquals("fb", Json.asString(null, "fb"));
        assertEquals(-1, Json.asInt("7", -1));
        assertEquals(-1, Json.asInt(null, -1));
        assertEquals(-1, Json.asInt(1.5d, -1), "a fractional line number is not a line number");
        assertEquals(-1, Json.asInt(Double.POSITIVE_INFINITY, -1));
        assertEquals(-1, Json.asInt(Double.NaN, -1));
        assertEquals(-1, Json.asInt(1e30d, -1), "out of int range must not silently truncate");
        assertEquals(-1, Json.asInt(-1e30d, -1));
        assertEquals(Integer.MAX_VALUE, Json.asInt((double) Integer.MAX_VALUE, -1));
    }

    @Test
    @DisplayName("asObject and asArray return the same instance rather than a copy")
    void accessorsDoNotCopy() {
        Object parsed = Json.parse("{\"a\":[1]}");
        assertSame(parsed, Json.asObject(parsed));
        Object array = Json.get(Json.asObject(parsed), "a");
        assertSame(array, Json.asArray(array));
    }
}
