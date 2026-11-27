// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.testFramework.fixtures.BasePlatformTestCase
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBTextField
import com.intellij.util.ui.UIUtil

/**
 * The setting and its page, in a booted platform: the service is the registered one, the value
 * round-trips through the persisted state, and the page edits it.
 */
class AshSettingsIdeTest : BasePlatformTestCase() {

    override fun tearDown() {
        try {
            AshSettings.getInstance().executablePath = ""
        } finally {
            super.tearDown()
        }
    }

    fun testTheRegisteredServiceTrimsAndPersistsThePath() {
        val settings = AshSettings.getInstance()
        assertSame("one instance per application", settings, AshSettings.getInstance())
        settings.executablePath = "  /opt/ash/bin/ashx  "
        assertEquals("/opt/ash/bin/ashx", settings.executablePath)

        val restored = AshSettings()
        restored.loadState(settings.state)
        assertEquals("/opt/ash/bin/ashx", restored.executablePath)
    }

    fun testThePageEditsTheSettingAndSaysWhatEmptyMeans() {
        val settings = AshSettings()
        val page = AshSettingsConfigurable { settings }
        val panel = page.createComponent()
        val field = UIUtil.findComponentOfType(panel, JBTextField::class.java)!!
        assertEquals("ASH", page.displayName)
        assertEquals(AshCliLocator.PRIMARY_NAME, field.emptyText.text)
        assertTrue(
            "the hint must state the fallback",
            UIUtil.findComponentsOfType(panel, JBLabel::class.java).any { it.text.contains("when <code>ashx</code> is not installed") },
        )

        page.reset()
        assertFalse(page.isModified)
        field.text = " /usr/local/bin/automated-security-helper "
        assertTrue(page.isModified)
        page.apply()
        assertEquals("/usr/local/bin/automated-security-helper", settings.executablePath)
        assertFalse(page.isModified)

        settings.executablePath = "/elsewhere"
        page.reset()
        assertEquals("/elsewhere", field.text)
    }

    fun testTheDefaultPageReadsTheApplicationSetting() {
        AshSettings.getInstance().executablePath = "/from/the/service"
        val page = AshSettingsConfigurable()
        page.createComponent()
        page.reset()
        assertFalse("the no-argument page must be backed by the registered service", page.isModified)
    }
}
