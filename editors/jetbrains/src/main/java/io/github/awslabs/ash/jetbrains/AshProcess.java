// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Spawns a child process, captures both streams, and gives up after a deadline.
 *
 * <p>WHY STDIN IS REDIRECTED FROM THE NULL DEVICE AND NOT LEFT ALONE
 *
 * <p>This is the single most important line in the class, and it is here because of the
 * {@code ash} name collision the entry-point contract describes. On Windows, MSYS2 ships an
 * {@code ash} of its own -- the Almquist shell -- and it can come first on PATH. A shell
 * invoked with an argument it does not understand may print a usage error and exit, but a
 * shell invoked in a way it reads as interactive READS STDIN. With stdin inherited from the
 * IDE, that child never exits and never writes anything, so the annotator waits on a
 * process that is waiting on it.
 *
 * <p>{@code Redirect.from(nullFile)} gives the child immediate EOF, so a shell that got here
 * by mistake terminates and {@link AshVersionProbe} can say what happened. The deadline
 * below is the second half of the same guard: it bounds anything that ignores EOF.
 *
 * <p>WHY THE TWO STREAMS ARE READ ON SEPARATE THREADS
 *
 * <p>A pipe has a finite buffer. Reading stdout to completion before touching stderr
 * deadlocks as soon as the child writes more to stderr than the buffer holds, and ASH is
 * verbose on stderr. {@code redirectErrorStream(true)} would avoid the deadlock by merging
 * them, and is not used: the probe needs to tell what a wrong binary wrote on stderr from
 * what ASH wrote on stdout, and merging throws that away.
 */
public final class AshProcess {

    /** The per-invocation cap for {@code ash --version}. Generous; ASH starts a Python VM. */
    public static final Duration PROBE_TIMEOUT = Duration.ofSeconds(30);

    /** The per-invocation cap for a scan. A repository scan is not fast. */
    public static final Duration SCAN_TIMEOUT = Duration.ofMinutes(15);

    private AshProcess() {}

    /** What a finished, or abandoned, child process left behind. */
    public record Outcome(int exitCode, String stdout, String stderr, boolean timedOut) {

        /**
         * The exit code reported for a process that was killed on the deadline.
         *
         * <p>Distinct from any real exit code so a caller cannot mistake a timeout for a
         * failure the tool chose to report. ASH itself exits 2 when it finds something,
         * which is exactly why "non-zero" is not usable as a failure signal here.
         */
        public static final int TIMED_OUT_EXIT_CODE = -1;

        /** Both streams joined, for a message shown to a user. */
        public String combinedOutput() {
            if (stdout.isBlank()) {
                return stderr.strip();
            }
            if (stderr.isBlank()) {
                return stdout.strip();
            }
            return stdout.strip() + System.lineSeparator() + stderr.strip();
        }
    }

    /**
     * Builds the {@link ProcessBuilder} used for every spawn.
     *
     * <p>Separate from {@link #run} and package-visible so the configuration can be asserted
     * without spawning anything: {@code ProcessBuilder#redirectInput()} reports the redirect
     * it was given, so a test can prove stdin is closed rather than trust the comment above.
     */
    static ProcessBuilder newBuilder(List<String> argv, Path workingDirectory) {
        if (argv == null || argv.isEmpty()) {
            throw new IllegalArgumentException("argv must name a program to run");
        }
        ProcessBuilder builder = new ProcessBuilder(argv);
        builder.redirectInput(ProcessBuilder.Redirect.from(nullFile()));
        // Explicit, though false is the default. The default is what a future edit changes
        // by accident, and the probe's ability to distinguish the streams depends on it.
        builder.redirectErrorStream(false);
        if (workingDirectory != null) {
            builder.directory(workingDirectory.toFile());
        }
        return builder;
    }

    /**
     * The platform's null device.
     *
     * <p>{@code /dev/null} on POSIX and {@code NUL} on Windows. Both are what
     * {@code ProcessBuilder.Redirect.from} needs -- a readable file -- and Windows is not
     * hypothetical here, since the {@code ash} collision this class guards against is a
     * Windows condition.
     */
    static File nullFile() {
        return new File(isWindows() ? "NUL" : "/dev/null");
    }

    static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win");
    }

    /**
     * Runs {@code argv} and waits up to {@code timeout}.
     *
     * @throws IOException if the program could not be started at all, which is the
     *     "no ash on PATH" case and must reach the user as such rather than as an empty
     *     result.
     */
    public static Outcome run(List<String> argv, Path workingDirectory, Duration timeout)
            throws IOException {
        Process process = newBuilder(argv, workingDirectory).start();
        StreamPump out = new StreamPump(process.getInputStream());
        StreamPump err = new StreamPump(process.getErrorStream());
        out.start();
        err.start();

        boolean finished;
        try {
            finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            // The IDE cancels background work by interrupting. Kill the child rather than
            // leaving an orphaned scan running, restore the flag, and report a timeout --
            // there is no result to report and the caller must not read one.
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            return new Outcome(Outcome.TIMED_OUT_EXIT_CODE, "", "", true);
        }

        if (!finished) {
            process.destroyForcibly();
            joinQuietly(out);
            joinQuietly(err);
            return new Outcome(Outcome.TIMED_OUT_EXIT_CODE, out.text(), err.text(), true);
        }

        joinQuietly(out);
        joinQuietly(err);
        return new Outcome(process.exitValue(), out.text(), err.text(), false);
    }

    private static void joinQuietly(StreamPump pump) {
        try {
            // Bounded. A pump can only outlive its process if the stream was inherited by a
            // grandchild, and waiting for that indefinitely would hang the IDE's inspection
            // thread on a process that is no longer ASH's business.
            pump.join(Duration.ofSeconds(5).toMillis());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    /** Drains one stream on its own thread so neither pipe can fill and deadlock. */
    private static final class StreamPump extends Thread {
        private final InputStream stream;
        private final StringBuilder sink = new StringBuilder();

        StreamPump(InputStream stream) {
            super("ash-output-pump");
            this.stream = stream;
            // Daemon so a pump that somehow outlives its process cannot keep the JVM alive.
            setDaemon(true);
        }

        @Override
        public void run() {
            byte[] buffer = new byte[8192];
            try {
                int read;
                while ((read = stream.read(buffer)) != -1) {
                    synchronized (sink) {
                        sink.append(new String(buffer, 0, read, StandardCharsets.UTF_8));
                    }
                }
            } catch (IOException closed) {
                // Expected on destroyForcibly: the stream is closed under the reader. What
                // was already captured is still worth reporting, so this is not rethrown --
                // and it is not silence either, because the caller sees timedOut.
            }
        }

        String text() {
            synchronized (sink) {
                return sink.toString();
            }
        }
    }
}
