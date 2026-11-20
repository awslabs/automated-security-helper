// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.openapi.options.Configurable
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBTextField
import com.intellij.util.ui.FormBuilder
import javax.swing.JComponent
import javax.swing.JPanel

/**
 * Settings | Tools | ASH.
 *
 * The hint text states the resolution order the field participates in, because an empty field
 * that silently means "ashx, then ash" is a behavior the user cannot discover otherwise.
 */
class AshSettingsConfigurable(
    private val settings: () -> AshSettings = { AshSettings.getInstance() },
) : Configurable {

    private val executableField = JBTextField()

    override fun getDisplayName(): String = "ASH"

    override fun createComponent(): JComponent {
        executableField.emptyText.text = AshCliLocator.PRIMARY_NAME
        return FormBuilder.createFormBuilder()
            .addLabeledComponent(JBLabel("ASH executable:"), executableField, 1, false)
            .addComponentToRightColumn(JBLabel(HINT), 1)
            .addComponentFillVertically(JPanel(), 0)
            .panel
    }

    override fun isModified(): Boolean = executableField.text.trim() != settings().executablePath

    override fun apply() {
        settings().executablePath = executableField.text
    }

    override fun reset() {
        executableField.text = settings().executablePath
    }

    companion object {
        val HINT: String =
            "<html>Leave empty to run <code>${AshCliLocator.PRIMARY_NAME}</code> from PATH, or " +
                "<code>${AshCliLocator.FALLBACK_NAME}</code> when <code>${AshCliLocator.PRIMARY_NAME}" +
                "</code> is not installed. A value here is run as given. On a host where another " +
                "program answers to <code>${AshCliLocator.FALLBACK_NAME}</code> (MSYS2 ships an " +
                "<code>ash</code> shell on Windows), use <code>automated-security-helper</code> " +
                "or a full path.</html>"
    }
}
