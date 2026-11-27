// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage

/**
 * The one setting this plugin has: which ASH executable to run.
 *
 * Application level, because the path to a binary is a property of the machine rather than of
 * a project. Empty means "search PATH", and what that search does is decided in
 * [AshCliLocator.resolve], not here, so this class holds a value and makes no decision about it.
 */
@State(name = "AshSettings", storages = [Storage("ash.xml")])
class AshSettings : PersistentStateComponent<AshSettings.State> {

    /** The serialized form. A mutable field with a default, which is what XmlSerializer reads. */
    class State {
        var executablePath: String = ""
    }

    private var state = State()

    /** The configured executable, or empty for the PATH search. */
    var executablePath: String
        get() = state.executablePath
        set(value) {
            state.executablePath = value.trim()
        }

    override fun getState(): State = state

    override fun loadState(loaded: State) {
        state = loaded
    }

    companion object {
        fun getInstance(): AshSettings =
            ApplicationManager.getApplication().getService(AshSettings::class.java)
    }
}
