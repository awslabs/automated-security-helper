// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.Task

/**
 * "Run ASH Security Scan": runs the ASH CLI over the open project and surfaces the results in
 * the editor.
 *
 * Only the platform wiring lives here. What a scan does, and every message it can end in, is
 * [AshScanController], which the end-to-end tests drive directly.
 */
class AshScanAction : AnAction() {

    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(e: AnActionEvent) {
        // Disabled rather than hidden when there is no project: a greyed-out entry tells the
        // user the command exists and does not apply, where a missing one reads as a broken
        // install.
        //
        // Also disabled while a scan of the project runs, so a second click does not look like it
        // started a second scan. AshScanController refuses one regardless.
        val project = e.getData(CommonDataKeys.PROJECT)
        e.presentation.isEnabled = project != null && !project.isDisposed &&
            !AshScanService.getInstance(project).isScanning
    }

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.getData(CommonDataKeys.PROJECT) ?: return
        val configured = AshSettings.getInstance().executablePath
        object : Task.Backgroundable(project, "Running ASH security scan", true) {
            override fun run(indicator: ProgressIndicator) {
                indicator.isIndeterminate = true
                AshScanController.scan(project, configured, indicator = indicator)
            }
        }.queue()
    }
}
