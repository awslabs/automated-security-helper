// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains.snapshot

import com.intellij.codeInspection.LocalInspectionEP
import com.intellij.codeInspection.ex.LocalInspectionToolWrapper
import com.intellij.ide.plugins.PluginManagerCore
import com.intellij.notification.NotificationGroupManager
import com.intellij.openapi.actionSystem.ActionManager
import com.intellij.openapi.actionSystem.DefaultActionGroup
import com.intellij.openapi.actionSystem.impl.SimpleDataContext
import com.intellij.openapi.extensions.PluginId
import com.intellij.openapi.keymap.KeymapManager
import com.intellij.openapi.options.Configurable
import com.intellij.testFramework.TestActionEvent
import com.intellij.testFramework.fixtures.BasePlatformTestCase
import io.github.awslabs.ash.jetbrains.AshFindingInspection
import io.github.awslabs.ash.jetbrains.AshNotifier
import io.github.awslabs.ash.jetbrains.AshScanAction
import io.github.awslabs.ash.jetbrains.AshScanService

/**
 * What the plugin contributes to the IDE, read back from the running platform rather than from
 * plugin.xml: the descriptor the Plugins page shows, the menu action and its states, the
 * inspection as the Inspections settings list it (with the description page), the settings page's
 * place in the tree, and the notification group.
 *
 * Read from the platform because that is what the user meets. A plugin.xml edit the platform
 * reads differently than its author expected, an attribute it ignores, or an extension that does
 * not register, shows up here as a changed or missing line.
 *
 * The plugin's version is left out on purpose: it is release metadata that moves on its own
 * schedule (see build.gradle.kts), and pinning it here would demand a snapshot reason for a
 * version bump that changes nothing a user sees in the IDE's UI.
 */
class ContributionsSnapshotTest : BasePlatformTestCase() {

    private val pluginId = "io.github.awslabs.ash"

    fun testThePluginsContributions() {
        val out = StringBuilder()

        val plugin = requireNotNull(PluginManagerCore.getPlugin(PluginId.getId(pluginId))) { "$pluginId is not loaded" }
        out.append("plugin\n")
        out.append("  id: ").append(plugin.pluginId.idString).append('\n')
        out.append("  name: ").append(plugin.name).append('\n')
        out.append("  vendor: ").append(plugin.vendor).append(" <").append(plugin.vendorUrl).append(">\n")
        out.append("  since-build: ").append(plugin.sinceBuild).append('\n')
        out.append("  until-build: ").append(plugin.untilBuild).append('\n')
        out.append("  depends: ").append(plugin.dependencies.map { it.pluginId.idString }.sorted()).append('\n')
        out.append("  description:\n").append(plugin.description.orEmpty().trim().prependIndent("    ")).append('\n')

        val actions = ActionManager.getInstance()
        val actionId = AshScanAction::class.java.name
        val action = requireNotNull(actions.getAction(actionId)) { "$actionId is not registered" }
        out.append("\naction ").append(actionId).append('\n')
        out.append("  text: ").append(action.templatePresentation.text).append('\n')
        out.append("  description: ").append(action.templatePresentation.description).append('\n')
        val groups = listOf("ToolsMenu", "AnalyzeMenu", "MainMenu", "EditorPopupMenu", "ProjectViewPopupMenu")
            .filter { id ->
                (actions.getAction(id) as? DefaultActionGroup)?.getChildActionsOrStubs()?.any { actions.getId(it) == actionId } == true
            }
        out.append("  in groups: ").append(groups).append('\n')
        out.append("  shortcuts: ").append(KeymapManager.getInstance().activeKeymap.getShortcuts(actionId).map { it.toString() }).append('\n')
        out.append("  background task title: ").append(AshScanAction.TASK_TITLE).append('\n')
        out.append("  enabled with a project: ").append(enabled(SimpleDataContext.getProjectContext(project))).append('\n')
        val service = AshScanService.getInstance(project)
        assertTrue(service.tryStartScan())
        try {
            out.append("  enabled while a scan runs: ").append(enabled(SimpleDataContext.getProjectContext(project))).append('\n')
        } finally {
            service.finishScan()
        }
        out.append("  enabled with no project: ").append(enabled(SimpleDataContext.EMPTY_CONTEXT)).append('\n')

        val inspection = LocalInspectionEP.LOCAL_INSPECTION.extensionList
            .single { it.implementationClass == AshFindingInspection::class.java.name }
        out.append("\nlocalInspection ").append(inspection.shortName).append('\n')
        out.append("  displayName: ").append(inspection.displayName).append('\n')
        out.append("  groupName: ").append(inspection.groupDisplayName).append('\n')
        out.append("  level: ").append(inspection.level).append('\n')
        out.append("  enabledByDefault: ").append(inspection.enabledByDefault).append('\n')
        out.append("  language: ").append(inspection.language).append('\n')
        out.append("  description page:\n")
            .append(LocalInspectionToolWrapper(inspection).loadDescription().orEmpty().trim().prependIndent("    ")).append('\n')

        val configurable = Configurable.APPLICATION_CONFIGURABLE.extensionList.single { it.id == "io.github.awslabs.ash.settings" }
        out.append("\napplicationConfigurable ").append(configurable.id).append('\n')
        out.append("  parentId: ").append(configurable.parentId).append('\n')
        out.append("  displayName: ").append(configurable.displayName).append('\n')
        out.append("  instance: ").append(configurable.instanceClass).append('\n')

        val group = requireNotNull(NotificationGroupManager.getInstance().getNotificationGroup(AshNotifier.GROUP_ID))
        out.append("\nnotificationGroup ").append(group.displayId).append('\n')
        out.append("  displayType: ").append(group.displayType).append('\n')
        out.append("  toolWindowId: ").append(group.toolWindowId).append('\n')

        Snapshots.assertMatches(javaClass, "contributions", out.toString())
    }

    private fun enabled(context: com.intellij.openapi.actionSystem.DataContext): Boolean {
        val action = AshScanAction()
        val event = TestActionEvent.createTestEvent(action, context)
        action.update(event)
        return event.presentation.isEnabled
    }
}
