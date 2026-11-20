// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.ide.plugins.PluginManagerCore
import com.intellij.openapi.extensions.PluginId
import com.intellij.testFramework.fixtures.BasePlatformTestCase
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path

/**
 * Which ASH plugin the test IDE loaded: from which directory, at which version, and where its
 * classes came from.
 *
 * WHY THIS EXISTS. The real-CLI suite scans through AshScanController, and a scan proves the code
 * the IDE loaded works. It does not say WHICH code that was. Under `realCliTest` it is the
 * plugin the build put in its own sandbox; under `installedZipTest` it must be the plugin the
 * IDE's own installer unpacked from the release zip (e2e-ide-cycle.sh installs it, and
 * e2e-installed-scan.sh runs that task against it). Without this check, a task that silently
 * fell back to the sandbox would run the same scans and pass, and "a real scan through the
 * installed zip" would be a claim nothing measured. This is the JetBrains counterpart of the VS
 * Code e2e suite's suiteSetup check that the extension is loaded from the installed directory at
 * the installed version.
 *
 * The expectation comes from the Gradle task, as two system properties, and a missing one FAILS:
 * a check that skipped when it was not told what to expect would pass in exactly the case it is
 * for.
 */
class AshLoadedPluginTest : BasePlatformTestCase() {

    private fun expected(name: String): String {
        val value = System.getProperty(name)
        if (value.isNullOrBlank()) {
            fail("system property $name is not set; the Gradle task that runs this suite sets it")
        }
        return value!!
    }

    fun testTheLoadedPluginIsTheOneThisTaskWasToldToTest() {
        val wantDir = Path.of(expected(DIR_PROPERTY)).toRealPath()
        val wantVersion = expected(VERSION_PROPERTY)

        val descriptor = PluginManagerCore.getPlugin(PluginId.getId(PLUGIN_ID))
        assertNotNull("the IDE loaded no plugin with id $PLUGIN_ID", descriptor)
        val loadedDir = descriptor!!.pluginPath.toRealPath()
        val classFile = AshScanController::class.java.name.replace('.', '/') + ".class"
        val classOrigin = AshScanController::class.java.classLoader.getResource(classFile)?.toString()
        println("loaded plugin: $PLUGIN_ID ${descriptor.version} from $loadedDir; classes from $classOrigin")

        assertEquals("the loaded plugin's version", wantVersion, descriptor.version)
        assertEquals("the directory the plugin was loaded from", wantDir, loadedDir)

        // The descriptor and the classes are found separately in a test IDE: the descriptor from
        // the plugins directory, the classes from the test JVM's classpath. Both must be the
        // installed copy, or the scans that follow would run the build's classes under the
        // installed plugin's name.
        assertNotNull("cannot locate $classFile", classOrigin)
        val originJar = classOrigin!!.takeIf { it.startsWith("jar:") && it.contains("!/") }
            ?.let { Path.of(URI(it.removePrefix("jar:").substringBefore("!/"))).toRealPath() }
        val jars = Files.list(wantDir.resolve("lib")).use { list ->
            list.filter { it.toString().endsWith(".jar") }.map { it.toRealPath() }.toList()
        }
        assertTrue(
            "AshScanController was loaded from $classOrigin, not from a jar under $wantDir/lib ($jars)",
            originJar != null && originJar in jars,
        )
    }

    private companion object {
        /** META-INF/plugin.xml's <id>. */
        const val PLUGIN_ID = "io.github.awslabs.ash"
        const val DIR_PROPERTY = "ash.jb.expected.plugin.dir"
        const val VERSION_PROPERTY = "ash.jb.expected.plugin.version"
    }
}
