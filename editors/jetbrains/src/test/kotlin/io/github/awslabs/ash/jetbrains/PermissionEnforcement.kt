// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import org.junit.Assert.fail
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission

/**
 * Checks that file permissions are actually enforced on this process, before a test uses them.
 *
 * Some runner tests make a file unreadable (mode 000) or a directory read-only, then check that
 * the runner refuses to read a report it cannot read, or a stale one it cannot delete. Root
 * ignores both modes, and so does any process with CAP_DAC_OVERRIDE. Under root, a mode-000 file
 * opens and a read-only directory accepts deletes, so those tests reach a different branch than
 * the one they name and fail with a message about that branch. Worse, a later change to the runner
 * could make one of them pass under root without testing anything.
 *
 * So this fails the test, naming the cause, instead of letting it run. It does not skip: a skipped
 * permission test is a gap nobody sees, and assert-tests-ran.py refuses skips anyway. The suite
 * has to run as a non-root user; verify-in-container.sh arranges that through run-unprivileged.sh.
 *
 * The probe tries the operations the tests depend on (opening a mode-000 file, and creating a file
 * in a read-only directory) rather than checking whether the uid is 0, because capabilities can
 * give a non-root uid the same bypass.
 */
internal object PermissionEnforcement {

    private val READ_ONLY_DIR = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_EXECUTE)
    private val OWNER_ALL =
        setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)

    fun require(scratch: Path) {
        val probeDir = Files.createTempDirectory(scratch, "permission-probe-")
        try {
            val uid = runCatching { Files.getAttribute(probeDir, "unix:uid") }.getOrNull() ?: "unknown"

            val unreadable = Files.writeString(probeDir.resolve("mode-000"), "probe")
            Files.setPosixFilePermissions(unreadable, emptySet())
            val readModeZero = runCatching { Files.readAllBytes(unreadable) }.isSuccess

            val readOnly = Files.createDirectory(probeDir.resolve("read-only"))
            Files.setPosixFilePermissions(readOnly, READ_ONLY_DIR)
            val wroteReadOnly = runCatching { Files.createFile(readOnly.resolve("created")) }.isSuccess
            Files.setPosixFilePermissions(readOnly, OWNER_ALL)

            val bypassed = buildList {
                if (readModeZero) add("a file with mode 000 could be read")
                if (wroteReadOnly) add("a file could be created in a read-only (r-x) directory")
            }
            if (bypassed.isNotEmpty()) {
                fail(
                    "This test needs file permissions to be enforced, and they are not: " +
                        bypassed.joinToString("; ") + ". The process runs as uid $uid" +
                        (if (uid.toString() == "0") " (root)" else "") +
                        ", and root (or CAP_DAC_OVERRIDE) bypasses permission checks, so this test " +
                        "cannot exercise the path it names. Run the suite as a non-root user: " +
                        "editors/jetbrains/verify-in-container.sh drops to the checkout's owner when " +
                        "started as root.",
                )
            }
        } finally {
            probeDir.toFile().walkTopDown().forEach { it.setWritable(true); it.setReadable(true) }
            probeDir.toFile().deleteRecursively()
        }
    }
}
