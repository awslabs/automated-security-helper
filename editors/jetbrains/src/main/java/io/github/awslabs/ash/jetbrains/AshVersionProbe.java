// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

/**
 * Decides whether the program that answered {@code ash --version} is actually ASH.
 *
 * <p>WHY THIS CHECK EXISTS AT ALL
 *
 * <p>{@code ash} is the canonical entry point and the one this plugin invokes. It is also
 * the name of the Almquist shell, which MSYS2 ships on Windows and which has already
 * shadowed ASH's entry point in this project's own CI, producing {@code Illegal option --}.
 * JetBrains IDEs run on Windows and this plugin spawns a process, so the collision reaches
 * users here.
 *
 * <p>The reason it cannot be left to fail naturally is the shape of the failure. A shell
 * that does not understand {@code scan --source-dir ...} writes an error and exits, ASH
 * writes no SARIF, and a plugin that only knew how to read SARIF would put zero annotations
 * on the file. Zero annotations is what a clean file looks like. So the wrong binary
 * answering would render as "ASH found nothing", which is the exact failure this branch
 * exists to remove, and it would be reported most confidently in the case where a real
 * secret was present.
 *
 * <p>WHY THE TEST IS A STRING IN ASH'S OWN OUTPUT AND NOT AN EXIT CODE
 *
 * <p>Measured: {@code ash --version} prints {@code awslabs/automated-security-helper v3.7.0}
 * and exits 0. An exit code cannot separate that from any other program that exits 0 for
 * {@code --version}, and there are many. {@link #ASH_MARKER} is the project's own
 * organization-and-repository string, which nothing else prints.
 *
 * <p>{@code --version} and not {@code -v}: {@code -v} is {@code --verbose} in ASH and has
 * been for all of v3, so a probe using it would start a verbose scan rather than print a
 * version. {@code -V} is the short spelling and would also work; the long one is used
 * because it is the spelling a user would type when checking this by hand.
 */
public final class AshVersionProbe {

    /**
     * The string ASH's own {@code --version} output contains.
     *
     * <p>Not the version number, and not the word "ash". A version number changes with every
     * release, and "ash" is the substring the Almquist shell's own error message contains.
     */
    public static final String ASH_MARKER = "awslabs/automated-security-helper";

    /**
     * Substrings that identify a non-ASH {@code ash} rather than a broken ASH.
     *
     * <p>{@code Illegal option} is what the Almquist shell wrote in this project's CI.
     * {@code unknown option} and {@code bad option} are the same message from dash and from
     * BusyBox's ash, which are the other two programs commonly installed under this name.
     *
     * <p>This list makes the ERROR MESSAGE better; it is not what makes the check correct.
     * Absence of {@link #ASH_MARKER} is what makes it correct, so a shell with an
     * unrecognized error message still fails the probe -- it lands in {@link Verdict#NOT_ASH}
     * either way and only the wording of the advice differs.
     */
    private static final String[] SHELL_TELLS = {
        "illegal option", "unknown option", "bad option", "syntax error",
    };

    private AshVersionProbe() {}

    /** What the probe concluded. */
    public enum Verdict {
        /** The marker was present. The plugin may run scans. */
        IS_ASH,
        /** Something answered, and it was not ASH. */
        NOT_ASH,
        /** Nothing answered: the program could not be started. */
        NOT_FOUND,
        /** Something started and never finished inside the deadline. */
        TIMED_OUT,
    }

    /**
     * The probe's conclusion plus the message to show the user.
     *
     * @param verdict what happened
     * @param version the version line ASH printed, or empty
     * @param message an actionable sentence, empty when {@link Verdict#IS_ASH}
     */
    public record Result(Verdict verdict, String version, String message) {
        /** True only when a scan may be attempted. */
        public boolean usable() {
            return verdict == Verdict.IS_ASH;
        }
    }

    /**
     * Classifies the outcome of running {@code <executable> --version}.
     *
     * <p>Pure: it takes the outcome rather than producing it, so every branch is reachable
     * from a test without a real {@code ash}, a real MSYS2 install or a real Windows host.
     *
     * @param executable the command that was run, quoted back to the user so they can see
     *     which one answered
     * @param outcome what {@link AshProcess#run} returned
     */
    public static Result classify(String executable, AshProcess.Outcome outcome) {
        if (outcome.timedOut()) {
            return new Result(
                    Verdict.TIMED_OUT,
                    "",
                    "'"
                            + executable
                            + " --version' did not finish within "
                            + AshProcess.PROBE_TIMEOUT.toSeconds()
                            + "s. It was stopped, and no scan was run.");
        }

        String combined = outcome.combinedOutput();
        if (combined.contains(ASH_MARKER)) {
            return new Result(Verdict.IS_ASH, versionLine(combined), "");
        }

        return new Result(Verdict.NOT_ASH, "", notAshAdvice(executable, combined));
    }

    /**
     * The message for the case where the program could not be started.
     *
     * <p>Separate from {@link #classify} because "could not start" arrives as an
     * {@link java.io.IOException} rather than as an outcome, and the advice differs: nothing
     * is shadowing anything, ASH is simply not installed or not on the IDE's PATH.
     *
     * <p>The PATH sentence is not filler. An IDE launched from a desktop launcher does not
     * inherit the shell's PATH, so {@code ash} working in a terminal and not working here is
     * the most likely first report, and the settings page is where it is fixed.
     */
    public static Result notFound(String executable, String reason) {
        return new Result(
                Verdict.NOT_FOUND,
                "",
                "Could not run '"
                        + executable
                        + "': "
                        + reason
                        + ". Install ASH, or set the full path to it in Settings | Tools | ASH."
                        + " An IDE started from a desktop launcher does not always inherit the"
                        + " PATH a terminal has, so a full path is the reliable fix.");
    }

    private static String notAshAdvice(String executable, String output) {
        StringBuilder advice = new StringBuilder();
        advice.append("'")
                .append(executable)
                .append("' is on the PATH but is not ASH: its --version output does not contain '")
                .append(ASH_MARKER)
                .append("'.");
        if (looksLikeAShell(output)) {
            // The specific, common cause, named so the user does not have to work it out.
            advice.append(
                    " The output looks like a shell rejecting an option, which is what happens"
                            + " when MSYS2's Almquist shell -- also called ash -- comes first on"
                            + " PATH.");
        }
        advice.append(
                " Set the executable to 'automated-security-helper', which is ASH's unambiguous"
                        + " entry point and is kept indefinitely for exactly this collision, or"
                        + " give the full path to ASH in Settings | Tools | ASH.");
        if (!output.isBlank()) {
            advice.append(" It printed: ").append(firstLine(output));
        }
        return advice.toString();
    }

    private static boolean looksLikeAShell(String output) {
        String lowered = output.toLowerCase(java.util.Locale.ROOT);
        for (String tell : SHELL_TELLS) {
            if (lowered.contains(tell)) {
                return true;
            }
        }
        return false;
    }

    /** The line carrying the marker, so a banner or a warning above it is not reported. */
    private static String versionLine(String output) {
        for (String line : output.split("\\R")) {
            if (line.contains(ASH_MARKER)) {
                return line.strip();
            }
        }
        return output.strip();
    }

    private static String firstLine(String output) {
        String[] lines = output.strip().split("\\R", 2);
        return lines[0].strip();
    }
}
