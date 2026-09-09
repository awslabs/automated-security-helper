// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * How the ASH CLI is made available to the build container.
 *
 * Every mode installs from the ASH git repository, or expects an image that
 * already contains ASH. None installs by distribution name, because ASH is not
 * distributed on PyPI: the name `automated-security-helper` there belongs to an
 * unrelated single-release placeholder package, so installing it would both fail
 * to provide an `ash` executable and pull a third party's code into a security
 * pipeline. If ASH is published to PyPI under a name the project controls, a
 * mode that installs by name becomes worth adding; until then there isn't one.
 *
 * ASH also publishes no container image to any public registry, so there is no
 * prebuilt image to pull either.
 */
export enum ASHInstallMode {
  /**
   * Install from the ASH git repository with `pip`.
   *
   * The default, and the method this repository documents for CI. Installs
   * `git+<sourceRepository>@<version>` into the build image's Python
   * environment.
   */
  PIP = 'pip',

  /**
   * Run ASH through `uvx`, which resolves the repository into a throwaway
   * environment on each invocation.
   *
   * Nothing is installed ahead of the scan, so this needs a build image that
   * already ships `uv`.
   */
  UVX = 'uvx',

  /**
   * Emit no install commands at all, because the build image already provides
   * an `ash` executable on `PATH`.
   *
   * This is the mode to pair with an image built from the ASH `Dockerfile` in
   * this repository. ASH ships no public image, so an image used here has to be
   * one the consumer built and hosts themselves.
   */
  PREINSTALLED = 'preinstalled',
}

/**
 * The lowest finding severity that makes a scan fail.
 *
 * Findings below the selected severity are still reported; they just do not
 * change the exit code. Maps to the ASH CLI `--min-severity` option.
 */
export enum ASHSeverityThreshold {
  /**
   * Fail only on critical findings.
   *
   * Equivalent to `HIGH`: SARIF does not distinguish the two levels, so ASH
   * treats them as one.
   */
  CRITICAL = 'critical',

  /**
   * Fail on high findings and above.
   *
   * Equivalent to `CRITICAL`: SARIF does not distinguish the two levels, so
   * ASH treats them as one.
   */
  HIGH = 'high',

  /**
   * Fail on medium findings and above.
   */
  MEDIUM = 'medium',

  /**
   * Fail on low findings and above. The ASH CLI default.
   */
  LOW = 'low',

  /**
   * Never fail on findings, whatever their severity.
   *
   * The scan still runs and still reports. Only infrastructure faults, such as
   * a scanner crashing, can fail the build.
   */
  NONE = 'none',
}
