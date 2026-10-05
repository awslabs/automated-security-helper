// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.project.Project

/**
 * The plugin's only user-visible reporting channel.
 *
 * Centralized so that "did this failure get surfaced" is answerable by looking at one file.
 * Every failure path in this plugin ends in a notification; there is no arm that logs and
 * returns, because a log line the user never opens is a silent no-op with extra steps.
 */
object AshNotifier {

    /** Must match the `notificationGroup` id declared in plugin.xml. */
    const val GROUP_ID = "ASH"

    fun notify(project: Project?, title: String, content: String, type: NotificationType) {
        NotificationGroupManager.getInstance()
            .getNotificationGroup(GROUP_ID)
            .createNotification(title, content, type)
            .notify(project)
    }
}
