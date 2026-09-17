// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.PersistentStateComponent;
import com.intellij.openapi.components.State;
import com.intellij.openapi.components.Storage;
import com.intellij.util.xmlb.XmlSerializerUtil;
import org.jetbrains.annotations.NotNull;

/**
 * The two settings this plugin has, persisted by the platform.
 *
 * <p>IDE GLUE. It holds no logic and is listed in coverage-exclusions.json with a line
 * budget for that reason; see the reason recorded there. Everything that could be wrong about
 * an executable name is decided in {@link AshExecutable}, which is measured.
 *
 * <p>Application level rather than project level: the path to the {@code ash} binary is a
 * property of the machine, and a per-project copy would have to be set once per project on
 * the same host.
 */
@State(name = "AshSettings", storages = @Storage("ash.xml"))
public final class AshSettings implements PersistentStateComponent<AshSettings> {

    /**
     * Empty means "use the default", which {@link AshExecutable#resolve} turns into
     * {@code ash}. Storing the literal default instead would freeze it: a user who never
     * touched this field would keep whatever the default was on the day they installed.
     */
    public String executablePath = "";

    /** On by default. A plugin that ships disabled is a plugin nobody finds. */
    public boolean enabled = true;

    public static AshSettings getInstance() {
        return ApplicationManager.getApplication().getService(AshSettings.class);
    }

    @Override
    public AshSettings getState() {
        return this;
    }

    @Override
    public void loadState(@NotNull AshSettings state) {
        XmlSerializerUtil.copyBean(state, this);
    }
}
