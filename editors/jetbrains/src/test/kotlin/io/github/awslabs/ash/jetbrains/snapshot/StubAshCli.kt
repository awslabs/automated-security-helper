// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains.snapshot

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission

/**
 * A stand-in ASH CLI for the snapshot tests: a shell script that answers `--version` like ASH and,
 * for `scan`, copies a captured real run into `--output-dir` and exits with a chosen code.
 *
 * The same shape as the stub in AshScanIntegrationTest, and for the same reason: what it writes was
 * produced by a real ASH run (src/test/resources/real-cli/README.txt), so a snapshot of what the
 * user is shown is a snapshot of the plugin reading ASH's actual output.
 */
class StubAshCli(private val bin: Path) {

    private fun resource(name: String): Path =
        Path.of(requireNotNull(javaClass.getResource(name)) { "fixture $name is not on the test classpath" }.toURI())

    /**
     * @param capture a directory under real-cli/, or null to write no report.
     * @param sarif a SARIF file to write instead of the capture's.
     * @param status a status file body to write instead of the capture's.
     */
    fun write(
        name: String,
        capture: String?,
        exitCode: Int,
        sarif: Path? = null,
        status: String? = null,
    ): Path {
        val sarifFile = sarif ?: capture?.let { resource("/real-cli/$it/ash.sarif") }
        val statusFile = capture?.let { resource("/real-cli/$it/ash_aggregated_results.json") }
        val console = capture?.let { javaClass.getResource("/real-cli/$it/console-tail.txt") }?.let { Path.of(it.toURI()) }
        val body = buildString {
            appendLine("#!/bin/sh")
            appendLine("if [ \"\$1\" = --version ]; then echo 'awslabs/automated-security-helper v3.7.0'; exit 0; fi")
            appendLine("out=''")
            appendLine("while [ \$# -gt 0 ]; do case \"\$1\" in --output-dir) out=\"\$2\"; shift 2;; *) shift;; esac; done")
            if (sarifFile != null) {
                appendLine("mkdir -p \"\$out/reports\"")
                appendLine("cp '$sarifFile' \"\$out/reports/ash.sarif\"")
            }
            if (status != null) {
                val file = bin.resolve("$name-status.json")
                Files.writeString(file, status)
                appendLine("cp '$file' \"\$out/ash_aggregated_results.json\"")
            } else if (statusFile != null) {
                appendLine("cp '$statusFile' \"\$out/ash_aggregated_results.json\"")
            }
            if (console != null) appendLine("cat '$console' >&2")
            appendLine("exit $exitCode")
        }
        return writeScript(name, body)
    }

    /** An executable named [name] with exactly [body] as its script. */
    fun writeScript(name: String, body: String): Path {
        val script = bin.resolve(name)
        Files.writeString(script, body)
        Files.setPosixFilePermissions(
            script,
            setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE),
        )
        return script
    }

    fun fixture(name: String): Path = resource(name)
}
