// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains.snapshot

import com.intellij.testFramework.fixtures.BasePlatformTestCase
import com.intellij.ui.components.JBTextField
import io.github.awslabs.ash.jetbrains.AshSettings
import io.github.awslabs.ash.jetbrains.AshSettingsConfigurable
import java.awt.Container
import javax.swing.AbstractButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.text.JTextComponent

/**
 * Settings | Tools | ASH, as a component tree: every component the page builds, in order, with
 * the text it shows. The visual suite holds what it looks like; this holds what it says and how
 * it is put together, in a form a review can read.
 *
 * Rendered twice, empty and after [AshSettingsConfigurable.reset] has loaded a configured path,
 * because the empty field shows a placeholder the configured one does not.
 */
class SettingsPanelSnapshotTest : BasePlatformTestCase() {

    override fun tearDown() {
        try {
            AshSettings.getInstance().executablePath = ""
        } finally {
            super.tearDown()
        }
    }

    private fun render(component: java.awt.Component, depth: Int, out: StringBuilder) {
        out.append("  ".repeat(depth)).append(component.javaClass.simpleName.ifEmpty { component.javaClass.name })
        when (component) {
            is JLabel -> out.append(" text=").append(quote(component.text))
            is JBTextField -> out.append(" text=").append(quote(component.text))
                .append(" emptyText=").append(quote(component.emptyText.text))
            is JTextComponent -> out.append(" text=").append(quote(component.text))
            is AbstractButton -> out.append(" text=").append(quote(component.text))
        }
        if (component is JComponent && component.toolTipText != null) out.append(" tooltip=").append(quote(component.toolTipText))
        if (!component.isVisible) out.append(" (hidden)")
        out.append('\n')
        if (component is Container) component.components.forEach { render(it, depth + 1, out) }
    }

    private fun quote(text: String?): String = if (text == null) "null" else "\"" + text.replace("\"", "\\\"") + "\""

    private fun page(configurable: AshSettingsConfigurable): String {
        val out = StringBuilder()
        out.append("displayName: ").append(configurable.displayName).append('\n')
        val component = configurable.createComponent()
        configurable.reset()
        out.append("modified after reset: ").append(configurable.isModified).append('\n')
        render(component, 0, out)
        configurable.disposeUIResources()
        return out.toString()
    }

    fun testTheEmptyPage() {
        AshSettings.getInstance().executablePath = ""
        Snapshots.assertMatches(javaClass, "empty", page(AshSettingsConfigurable()))
    }

    fun testThePageWithAConfiguredExecutable() {
        AshSettings.getInstance().executablePath = "/opt/ash/bin/ashx"
        Snapshots.assertMatches(javaClass, "configured", page(AshSettingsConfigurable()))
    }
}
