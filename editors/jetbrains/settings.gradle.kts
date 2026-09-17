// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// A standalone Gradle build, not a subproject of anything.
//
// Nothing else in this repository is built by Gradle: the Python package is hatch, the
// two TypeScript packages under deploy/ are npm, and packaging/ is shell and PowerShell.
// So there is no root settings file to add an `include` to, and creating one would put a
// Gradle build at the repository root that owns a single directory. A developer runs
// `./gradlew` from editors/jetbrains and nothing above it changes.
//
// The consequence to know about: this build is invisible to any repository-wide command.
// `.github/workflows/ash-jetbrains-ci.yml` therefore names the directory explicitly, and
// editors/jetbrains/verify-in-container.sh is the single entry point a developer and CI
// both run, so the two cannot drift.
rootProject.name = "ash-jetbrains"
