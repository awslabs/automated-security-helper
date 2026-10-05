// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Whether `--version` came from ASH. The process side is AshScanRunnerIdeTest's; this is the
 * classification, for every shape of answer.
 */
class AshIdentityProbeTest {

    private fun notAsh(output: String, timedOut: Boolean = false): String =
        (AshIdentityProbe.classify("ash", timedOut, output) as AshIdentityProbe.Verdict.NotAsh).message

    @Test
    fun theMarkerLineIsTheVersion() {
        val verdict = AshIdentityProbe.classify("ashx", false, "warning: something\n  awslabs/automated-security-helper v4.0.0  \n")
        assertEquals(AshIdentityProbe.Verdict.IsAsh("awslabs/automated-security-helper v4.0.0"), verdict)
    }

    @Test
    fun aShellRejectingTheOptionIsNamedAsTheMsys2Collision() {
        val message = notAsh("/usr/bin/ash: Illegal option --\nusage: ...")
        assertTrue(message, message.contains("MSYS2"))
        assertTrue(message, message.contains("automated-security-helper"))
        assertTrue(message, message.contains("It printed: /usr/bin/ash: Illegal option --"))
    }

    @Test
    fun anotherProgramIsRefusedWithoutBlamingAShell() {
        val message = notAsh("ash 1.2 (some other tool)")
        assertTrue(message, message.contains("is not ASH"))
        assertFalse(message, message.contains("MSYS2"))
    }

    @Test
    fun silenceIsNotAsh() {
        val message = notAsh("   ")
        assertTrue(message, message.contains("is not ASH"))
        assertFalse("nothing was printed, so nothing is quoted", message.contains("It printed"))
    }

    @Test
    fun aTimeoutIsNotAshEvenIfTheMarkerArrived() {
        val message = notAsh("awslabs/automated-security-helper v4.0.0", timedOut = true)
        assertTrue(message, message.contains("did not finish within 30s"))
    }
}
