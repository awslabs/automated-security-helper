// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import com.intellij.openapi.options.Configurable;
import com.intellij.ui.components.JBCheckBox;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.FormBuilder;
import javax.swing.JComponent;
import javax.swing.JPanel;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.Nullable;

/**
 * The Settings | Tools | ASH page.
 *
 * <p>IDE GLUE. Swing wiring only, listed in coverage-exclusions.json with a line budget; see
 * the reason recorded there.
 *
 * <p>The executable field exists because of the {@code ash} name collision: on Windows,
 * MSYS2's Almquist shell is also called {@code ash} and can come first on PATH. The hint text
 * names {@code automated-security-helper} as the fix, so a user meeting the collision has the
 * answer in front of them rather than in an error message they may have dismissed.
 */
public final class AshSettingsConfigurable implements Configurable {

    private final JBTextField executableField = new JBTextField();
    private final JBCheckBox enabledBox = new JBCheckBox("Annotate files with ASH findings");
    private JPanel panel;

    @Override
    public @Nls String getDisplayName() {
        return "ASH";
    }

    @Override
    public @Nullable JComponent createComponent() {
        executableField.getEmptyText().setText(AshExecutable.DEFAULT);
        panel =
                FormBuilder.createFormBuilder()
                        .addComponent(enabledBox)
                        .addLabeledComponent(new JBLabel("ASH executable:"), executableField, 1, false)
                        .addComponentToRightColumn(
                                new JBLabel(
                                        "<html>Leave empty to use <code>"
                                                + AshExecutable.DEFAULT
                                                + "</code> from PATH. On a host where another"
                                                + " program answers to that name -- MSYS2 ships an"
                                                + " <code>ash</code> shell on Windows -- use"
                                                + " <code>"
                                                + AshExecutable.UNAMBIGUOUS
                                                + "</code> or a full path.</html>"),
                                1)
                        .addComponentFillVertically(new JPanel(), 0)
                        .getPanel();
        return panel;
    }

    @Override
    public boolean isModified() {
        AshSettings settings = AshSettings.getInstance();
        return !executableField.getText().equals(settings.executablePath)
                || enabledBox.isSelected() != settings.enabled;
    }

    @Override
    public void apply() {
        AshSettings settings = AshSettings.getInstance();
        settings.executablePath = executableField.getText().strip();
        settings.enabled = enabledBox.isSelected();
    }

    @Override
    public void reset() {
        AshSettings settings = AshSettings.getInstance();
        executableField.setText(settings.executablePath);
        enabledBox.setSelected(settings.enabled);
    }

    @Override
    public void disposeUIResources() {
        panel = null;
    }
}
