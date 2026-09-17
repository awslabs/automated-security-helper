// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

plugins {
    id("java")
    id("jacoco")
    // The IntelliJ Platform Gradle plugin, 2.x line. It resolves an IDE distribution
    // from JetBrains' CDN, compiles against it, and packages the plugin distribution.
    // It is a BUILD-time dependency: nothing it puts on the compile classpath ships,
    // because every IntelliJ Platform artifact it adds is compileOnly by construction.
    id("org.jetbrains.intellij.platform") version "2.19.0"
}

group = "io.github.awslabs.ash"

// THE PLUGIN'S OWN VERSION, AND DELIBERATELY NOT ASH'S
//
// This number is not maintained by commitizen and is not listed in pyproject.toml's
// [tool.commitizen] version_files, and that is a decision rather than an omission.
//
// Nothing in this directory pins an ASH version. The plugin ships no ASH code, resolves
// no ASH git ref, and embeds no install command: it invokes whatever `ash` is on the
// user's PATH. So there is no literal here that can go stale when ASH releases, which is
// the entire failure mode that list exists to prevent -- every entry on it is a pin
// someone else installs from.
//
// Tying the two together would also be wrong in the other direction. A JetBrains plugin
// is versioned against the IDE builds it supports: the reasons to publish a new one are
// a platform API change or a new `since-build` floor, and those move on JetBrains'
// release calendar, not ASH's. An ASH patch release would force a plugin version bump
// with no plugin change, and a plugin fix for one IDE build could not be released without
// waiting for an ASH release.
//
// There is a mechanical hazard in the same direction, and it is why this comment is long.
// commitizen matches each version_files regex per LINE and then replaces the current
// version within every line that matched. A bare `version` pattern against this file
// would also match the `version "2.19.0"` on the plugin line above and the JUnit
// coordinate below; a bare `version` pattern against META-INF/plugin.xml would match
// `<idea-version since-build=...>`. Those are the anchor accidents the version_files
// comment in pyproject.toml describes, and the cheapest way not to have one is not to
// add the entry.
version = "0.1.0"

java {
    // 21, because IntelliJ Platform 2024.2 and later run on a JBR 21 and refuse a plugin
    // compiled to a newer bytecode level than the IDE's own runtime. A toolchain rather
    // than sourceCompatibility so the build fails with "no matching toolchain" on a JDK
    // 17 host instead of compiling against whatever javac happens to be first on PATH.
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
    intellijPlatform {
        defaultRepositories()
    }
}

dependencies {
    intellijPlatform {
        // 2025.2 rather than the newest release, because this is the FLOOR the plugin
        // supports and a plugin compiled against a newer platform can reference a method
        // the floor does not have. `since-build` below is derived from this choice, and
        // the two have to move together.
        intellijIdeaCommunity("2025.2")
    }

    // Test-only, so not shipped. assert-plugin-zip-contents.py proves that rather than
    // asserting it: it opens the built distribution and fails on any jar in lib/ that is
    // not this project's own output.
    testImplementation("org.junit.jupiter:junit-jupiter:6.1.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

intellijPlatform {
    pluginConfiguration {
        ideaVersion {
            // 252 is the build number series of the 2025.2 platform resolved above.
            sinceBuild = "252"

            // No upper bound. The default behavior is to cap until-build at the resolved
            // platform's branch, which would make the plugin refuse to load on the next
            // IDE release even though it uses no API that changed. An open range is the
            // right shape for a plugin whose entire platform surface is
            // ExternalAnnotator, Configurable and PersistentStateComponent.
            untilBuild = provider { null }
        }
    }

    // Off deliberately. buildSearchableOptions starts a headless IDE to index the
    // settings page so its fields are findable in Search Everywhere. For a settings page
    // with two fields that is not worth making every build depend on an IDE process
    // starting inside a container -- and when it fails it fails as a timeout in a task
    // whose name does not mention the IDE.
    buildSearchableOptions = false
}

jacoco {
    toolVersion = "0.8.13"
}

tasks.test {
    useJUnitPlatform()

    // A Gradle `test` task with no tests SUCCEEDS. An empty test source set, a bad
    // include filter, or a JUnit platform that failed to find an engine all produce a
    // green task and an empty report, which is the same silent pass a jest run reporting
    // "0 total" produces. So count what ran and fail on zero.
    //
    // The count is taken from the task's own result object rather than by parsing the XML
    // report, because the XML is written by a listener that a failure earlier in the task
    // can skip.
    val executed = mutableListOf<Long>()
    addTestListener(object : TestListener {
        override fun beforeSuite(suite: TestDescriptor) {}
        override fun beforeTest(test: TestDescriptor) {}
        override fun afterTest(test: TestDescriptor, result: TestResult) {}
        override fun afterSuite(suite: TestDescriptor, result: TestResult) {
            if (suite.parent == null) {
                executed += result.testCount
            }
        }
    })
    doLast {
        val total = executed.sum()
        logger.lifecycle("test: $total test(s) executed")
        if (total == 0L) {
            throw GradleException(
                "the test task ran 0 tests and would otherwise have reported success. " +
                    "A suite that cannot fail passes; see the comment on this check.",
            )
        }
    }

    finalizedBy(tasks.jacocoTestReport)
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        // XML is the one assert-coverage.py reads. HTML is for a human looking at a
        // failure. CSV is off: nothing consumes it.
        xml.required = true
        html.required = true
        csv.required = false
    }

    // NO class exclusions here, on purpose, and this is the load-bearing half of the
    // coverage design.
    //
    // The report must enumerate every class compiled from src/main/java, including the
    // ones the coverage gate does not hold to a threshold. If the excluded classes were
    // filtered out here as well, they would be absent from the report rather than present
    // at 0%, and assert-coverage.py's census could not tell "deliberately out of scope"
    // from "nobody noticed this file". That is the distinction
    // .github/typescript-coverage-exclusions.json exists to preserve for jest, where the
    // problem is worse because jest omits unimported source entirely.
    //
    // The threshold is applied by assert-coverage.py over the non-excluded subset, from
    // this same report, with coverage-exclusions.json as the only list of what is out of
    // scope.
}

// The coverage gate. A Gradle task rather than a workflow-only step so that
// `./gradlew check` gates locally exactly as CI does.
//
// jacocoTestCoverageVerification is deliberately NOT used. It can express a ratio and a
// class-exclusion pattern and nothing else: it cannot pin the denominator, cannot census
// tracked files against the report, and cannot re-test whether an exclusion is still
// true. Splitting the gate across two enforcers would also mean two places to relax it.
val assertCoverage = tasks.register<Exec>("assertCoverage") {
    group = "verification"
    description = "Gates line and branch coverage, pins the denominator, and audits the exclusion list."
    dependsOn(tasks.jacocoTestReport)
    workingDir = layout.projectDirectory.asFile
    commandLine(
        "python3",
        "assert-coverage.py",
        "--report", "build/reports/jacoco/test/jacocoTestReport.xml",
        "--exclusions", "coverage-exclusions.json",
        "--source-root", "src/main/java",
        "--repo-root", "../..",
        "--min-line-ratio", "0.90",
        "--min-branch-ratio", "0.90",
        // Floors, not equalities, for the same reason assert-coverage-scope.mjs gives:
        // adding a class legitimately raises both, and a floor does not need editing
        // when it does. Removing one lowers them and fails, which is the case worth
        // catching -- a narrowed classDirectories raises the percentage by measuring
        // less, and the percentage alone cannot tell that from better tests.
        "--min-classes", "9",
        "--min-lines", "300",
    )
}

tasks.check {
    dependsOn(assertCoverage)
}

// Runs after the distribution zip exists rather than as part of it, because the check is
// about what the packaging step produced.
val assertDistributionContents = tasks.register<Exec>("assertDistributionContents") {
    group = "verification"
    description = "Fails if the built plugin distribution carries any jar but this project's own."
    dependsOn(tasks.buildPlugin)
    workingDir = layout.projectDirectory.asFile
    commandLine(
        "python3",
        "assert-plugin-zip-contents.py",
        "--dist-dir", "build/distributions",
        "--own-jar-prefix", "ash-jetbrains",
    )
}

tasks.buildPlugin {
    finalizedBy(assertDistributionContents)
}
