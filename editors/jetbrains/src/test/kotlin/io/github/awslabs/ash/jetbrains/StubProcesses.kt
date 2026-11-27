// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import org.junit.Assert.assertTrue

/**
 * Finds the processes a stub ASH started, so a test can check that none outlives a cancel.
 *
 * The stubs fork on purpose: `sleep 300; exit 0` under sh runs the sleep as a child of the
 * shell, the way ASH's own scanners run as children of ASH. A cancel or a timeout reaches that
 * child only because the platform's OSProcessHandler destroys the whole process tree by
 * default (shouldDestroyProcessRecursively is true); a plain Process.destroy() would kill the
 * shell and leave the sleep running. These checks exist to fail if that default stops holding.
 *
 * An orphaned child is no longer a descendant of this JVM, so the children are captured while
 * the stub is still running, and checked by handle afterwards.
 */
internal object StubProcesses {
    /** Waits until at least one descendant of this JVM runs [executableName], and returns them all. */
    fun awaitDescendants(executableName: String, timeoutMillis: Long = 30_000): List<ProcessHandle> {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (true) {
            val found = ProcessHandle.current().descendants()
                .filter { handle -> handle.info().command().map { it.substringAfterLast('/') == executableName }.orElse(false) }
                .toList()
            if (found.isNotEmpty()) return found
            assertTrue("no '$executableName' process appeared under this JVM", System.currentTimeMillis() < deadline)
            Thread.sleep(20)
        }
    }

    /** Asserts every one of [handles] has exited, allowing the kill a moment to land. */
    fun assertAllExited(handles: List<ProcessHandle>, timeoutMillis: Long = 10_000) {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (handles.any { it.isAlive } && System.currentTimeMillis() < deadline) Thread.sleep(20)
        val survivors = handles.filter { it.isAlive }.map { "${it.pid()} ${it.info().commandLine().orElse("?")}" }
        assertTrue("the stub's processes must not outlive it: $survivors", survivors.isEmpty())
    }
}
