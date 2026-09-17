// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

/**
 * Turns a configured setting into the command to spawn.
 *
 * <p>THE ENTRY-POINT CONTRACT THIS IMPLEMENTS
 *
 * <p>{@code ash} is canonical and is the default. {@code automated-security-helper} is kept
 * indefinitely and is silent, and it is the escape hatch for a host where a bare {@code ash}
 * resolves to something else -- MSYS2's Almquist shell on Windows being the case that has
 * already happened. {@code ashv3} exists and warns once on stderr; it is deprecated, so this
 * plugin never suggests it, and {@link #looksDeprecated} exists only so a user who typed it
 * into the settings field is told rather than left wondering about the stderr line.
 *
 * <p>WHY THERE IS NO PATH SEARCH HERE
 *
 * <p>An earlier shape resolved the command against PATH itself and passed an absolute path
 * to {@link AshProcess}, on the theory that resolving explicitly is safer than letting the
 * child do it. That was dropped: a plugin's idea of PATH is the IDE process's environment,
 * which on macOS and Linux desktop launchers is not the login shell's PATH, so this plugin
 * would fail to find an {@code ash} the user can run in a terminal, and would report "not
 * found" while pointing at the wrong environment. Handing the bare name to
 * {@link ProcessBuilder} makes the resolution the operating system's, which is the same
 * resolution the user's terminal does, and the settings field covers the case where that is
 * not what they want. {@link AshVersionProbe} is what makes the looser resolution safe: it
 * refuses to scan unless the thing that answered identifies itself as ASH.
 */
public final class AshExecutable {

    /** The default and canonical entry point. */
    public static final String DEFAULT = "ash";

    /**
     * The unambiguous entry point, recommended in the error message for a name collision.
     *
     * <p>Kept indefinitely by the project for this reason, so recommending it is not
     * recommending something that may be removed.
     */
    public static final String UNAMBIGUOUS = "automated-security-helper";

    /** The deprecated spelling. Never suggested; recognized so a user can be told. */
    public static final String DEPRECATED = "ashv3";

    private AshExecutable() {}

    /**
     * The command to spawn.
     *
     * @param configured whatever is in the settings field; null, empty and whitespace all
     *     mean "not configured" and yield {@link #DEFAULT}. Surrounding whitespace is
     *     stripped, because a path pasted from a terminal usually carries a trailing space
     *     and {@code ProcessBuilder} would look for a program whose name ends in one.
     */
    public static String resolve(String configured) {
        if (configured == null) {
            return DEFAULT;
        }
        String trimmed = configured.strip();
        return trimmed.isEmpty() ? DEFAULT : trimmed;
    }

    /** True when the configured value is the deprecated spelling rather than a path to it. */
    public static boolean looksDeprecated(String configured) {
        return DEPRECATED.equals(resolve(configured));
    }

    /**
     * The advisory for a user who configured {@code ashv3}.
     *
     * <p>Not an error. {@code ashv3} works; it prints a deprecation warning on stderr once,
     * and a user who sees that line in a log deserves to know where it came from.
     */
    public static String deprecationAdvice() {
        return "'"
                + DEPRECATED
                + "' is deprecated and warns on stderr. Use '"
                + DEFAULT
                + "', or '"
                + UNAMBIGUOUS
                + "' on a host where another program answers to '"
                + DEFAULT
                + "'.";
    }
}
