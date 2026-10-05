// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import org.jetbrains.intellij.platform.gradle.TestFrameworkType

plugins {
    id("java")
    id("jacoco")
    // Kotlin, because the plugin's runtime is written in it. The Kotlin standard library is NOT
    // bundled: the plugin runs against the stdlib the IntelliJ Platform ships, which JetBrains
    // documents as the supported arrangement for plugins. gradle.properties says what
    // kotlin.stdlib.default.dependency does and does not control; assert-plugin-zip-contents.py
    // is what proves no third-party jar reached lib/.
    id("org.jetbrains.kotlin.jvm") version "2.1.21"
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
// no ASH git ref, and embeds no install command: it invokes whatever ASH CLI is on the
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
// would also match the `version "2.19.0"` on the plugin line above and the Kotlin plugin
// coordinate; a bare `version` pattern against META-INF/plugin.xml would match
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

kotlin {
    compilerOptions {
        // The API level of the Kotlin stdlib the 2025.2 platform bundles. Compiling against a
        // newer API would let the plugin call a stdlib function the IDE's own stdlib lacks,
        // which fails at class-load time on the user's machine rather than here.
        apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_1)
        freeCompilerArgs.add("-Xjvm-default=all")
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
        // 2025.2.5 rather than the newest release, because this is the FLOOR the plugin
        // supports and a plugin compiled against a newer platform can reference a method
        // the floor does not have. `since-build` below is derived from this choice, and
        // the two have to move together.
        //
        // Not a 2025.3 build: the `ideaIC` artifact is not published from 2025.3 (253) on,
        // because JetBrains unified the Community and Ultimate distributions, and the
        // IntelliJ Platform Gradle plugin fails to resolve idea:ideaIC:2025.3.x.
        intellijIdeaCommunity("2025.2.5")

        // The platform test framework, which gives BasePlatformTestCase a real Application
        // and Project. It is what lets the inspection, the scan service and the end-to-end
        // scan be tested inside a booted (headless) IDE rather than against mocks of the
        // platform's own classes.
        testFramework(TestFrameworkType.Platform)

        // For the verifyPlugin task, which .github/workflows/ash-jetbrains-ci.yml runs in its
        // own job. See the pluginVerification block below.
        pluginVerifier()
    }

    // Test-only, so not shipped. assert-plugin-zip-contents.py proves that rather than
    // asserting it: it opens the built distribution and fails on any jar in lib/ that is
    // not this project's own output. JUnit 4 because BasePlatformTestCase is a JUnit 3/4
    // TestCase; one framework for every test keeps assert-tests-ran.py's view of the suite
    // simple.
    testImplementation("junit:junit:4.13.2")
}

intellijPlatform {
    pluginConfiguration {
        ideaVersion {
            // 252 is the build number series of the 2025.2 platform resolved above.
            sinceBuild = "252"

            // No upper bound. The default behavior is to cap until-build at the resolved
            // platform's branch, which would make the plugin refuse to load on the next
            // IDE release even though it uses no API that changed. The cost is real: if a
            // later platform breaks one of the APIs used here, users get a runtime failure
            // instead of a refusal to install. verifyPlugin against the recommended IDE set
            // is the check that catches that, which is why CI runs it.
            untilBuild = provider { null }
        }
    }

    pluginVerification {
        ides {
            // recommended() resolves the IDE releases matching the declared since/until range,
            // including ones newer than the build target. That is what makes the open
            // until-build above defensible, and it is also what would catch the platform
            // dropping the Gson this plugin reads JSON with (see AshSarifParser's header).
            recommended()
        }
    }

    // Off deliberately. buildSearchableOptions starts a headless IDE to index the
    // settings page so its fields are findable in Search Everywhere. For a settings page
    // with one field that is not worth making every build depend on an IDE process
    // starting inside a container -- and when it fails it fails as a timeout in a task
    // whose name does not mention the IDE.
    buildSearchableOptions = false

    // Off, and this one was forced by a measurement rather than chosen.
    //
    // instrumentCode rewrites the compiled bytecode after compilation, adding runtime
    // assertions for @NotNull annotations, and the test task then loads the REWRITTEN classes.
    // JaCoCo identifies a class by a hash of its bytecode: when the classes the report reads
    // are not the classes the tests loaded, it does not error -- it reports 0.0%. The gate
    // caught exactly that: "line coverage 0.00% is below the required 90.00%" with a full
    // denominator and every test passing. Turning instrumentation off makes the classes that
    // were compiled, the classes that were measured, and the classes that ship one set of
    // bytes. Kotlin already emits its own null checks, so nothing here relies on the
    // platform's.
    instrumentCode = false
}

jacoco {
    toolVersion = "0.8.13"
}

// THE SUITE RUNS IN THE PLATFORM TEST RUNTIME, AND JACOCO IS TOLD WHERE TO LOOK
//
// The previous Java build of this plugin ran its tests in a plain JVM, because under this task
// JaCoCo recorded 344 classes and NONE of ours: a populated report whose every value was zero.
// The cause is that the IntelliJ test runtime loads plugin classes through its own
// PathClassLoader, which defines them with no CodeSource location, and JaCoCo's agent skips a
// class with no location unless told otherwise. includeNoLocationClasses is that instruction.
// jdk.internal.* is excluded because instrumenting the JDK's own internals with that setting on
// breaks the JVM, which is the documented reason for the pairing.
//
// Running in the platform runtime rather than a plain JVM is what lets the inspection, the
// service, the scan action and the end-to-end scan be MEASURED instead of excluded with a line
// budget. assert-coverage.py's floors make sure this keeps working: if JaCoCo goes back to
// seeing nothing, the line denominator stays full and the ratio collapses to 0%, which fails.
tasks.test {
    useJUnit()

    // The IntelliJ test fixtures expect headless AWT.
    systemProperty("java.awt.headless", "true")

    extensions.configure<JacocoTaskExtension> {
        isIncludeNoLocationClasses = true
        excludes = listOf("jdk.internal.*")
    }

    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }

    // A Gradle test task with no tests SUCCEEDS, so this counts what ran and fails on zero.
    //
    // It is NOT the gate, and the difference was measured rather than reasoned about. With the
    // test sources moved aside, Gradle reported "Task :test NO-SOURCE" and BUILD
    // SUCCESSFUL: a task skipped as NO-SOURCE never runs its actions, so this block was never
    // reached in the one case it was written for. assertTestsRan below is the gate, because it
    // is a separate task that reads artifacts and therefore fires whether or not this task
    // ran. What this block still buys is a clearer message, at the moment of the run, when the
    // task does execute and finds nothing -- a bad include filter, or a runner that found no
    // tests.
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
    // The report must enumerate every class compiled from src/main, including any the
    // coverage gate does not hold to a threshold. If an excluded class were filtered out here
    // as well, it would be absent from the report rather than present at 0%, and
    // assert-coverage.py's census could not tell "deliberately out of scope" from "nobody
    // noticed this file". The threshold is applied by assert-coverage.py over the
    // non-excluded subset, from this same report, with coverage-exclusions.json as the only
    // list of what is out of scope.
}

// The gate on the suite having run at all. Separate from the test task on purpose: a task
// Gradle skips as NO-SOURCE runs none of its own actions, so an in-task guard cannot fail in
// the case that matters. This one reads the JUnit XML results and the compiled test classes
// and compares them, which also closes the stale-results hole an XML-only check would leave,
// and catches a committed include filter that runs a subset and reports green.
val assertTestsRan = tasks.register<Exec>("assertTestsRan") {
    group = "verification"
    description = "Fails unless every compiled test suite ran and reported, with none skipped."
    dependsOn(tasks.test)
    workingDir = layout.projectDirectory.asFile
    commandLine(
        "python3",
        "assert-tests-ran.py",
        "--results", "build/test-results/test",
        "--test-classes", "build/classes/kotlin/test",
        // The classes whose assertions a silent scan cannot satisfy. Named rather than left to
        // the compiled-suite comparison, so that deleting one fails with a message about this
        // class rather than about a count.
        "--require-suite", "io.github.awslabs.ash.jetbrains.AnnotationCountTest",
        "--require-suite", "io.github.awslabs.ash.jetbrains.AshScanIntegrationTest",
    )
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
        "--source-root", "src/main/kotlin",
        "--repo-root", "../..",
        "--min-line-ratio", "0.90",
        "--min-branch-ratio", "0.90",
        // Floors, not equalities, for the same reason assert-coverage-scope.mjs gives:
        // adding a class legitimately raises both, and a floor does not need editing
        // when it does. Removing one lowers them and fails, which is the case worth
        // catching -- a narrowed classDirectories raises the percentage by measuring
        // less, and the percentage alone cannot tell that from better tests.
        //
        // Measured on the revision that added the Kotlin runtime: 52 gated classes (nested
        // classes and companions count separately in a JaCoCo report) over a 733-line
        // denominator, with nothing excluded. The floors sit just below, close enough that
        // losing a class fails and loose enough that a small refactor does not.
        "--min-classes", "50",
        "--min-lines", "700",
    )
}

tasks.check {
    // assertTestsRan explicitly, because it is the only one of the three that can fail when
    // the test task is skipped as NO-SOURCE.
    dependsOn(tasks.test, assertTestsRan, assertCoverage)

    // The platform's own two checks, which the IntelliJ Platform Gradle plugin provides and
    // does not wire into `check` itself. They are the only things that read META-INF/plugin.xml
    // as the platform will: verifyPluginProjectConfiguration compares the descriptor against
    // the resolved IDE and the Java toolchain, and verifyPluginStructure runs the Plugin
    // Verifier's structural check over the built sandbox. Nothing else here would notice a
    // misspelled extension point or a since-build the platform rejects.
    //
    // NOT the full verifyPlugin task, which is the Plugin Verifier's compatibility run: it
    // downloads one additional IDE per recommended release on top of the roughly one gigabyte
    // already resolved. CI runs it as a separate job so the fast path stays fast.
    dependsOn(tasks.named("verifyPluginProjectConfiguration"))
    dependsOn(tasks.named("verifyPluginStructure"))
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
