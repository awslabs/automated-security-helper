// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * How the ASH CLI is made available to the build container.
 *
 * ASH does not publish a container image to any public registry, so there is
 * no prebuilt image to pull. Every mode here either installs ASH into a
 * generic build image or assumes the consumer supplied an image that already
 * contains it.
 */
export enum ASHInstallMode {
  /**
   * Install the published `automated-security-helper` distribution with `pip`
   * into the build image's Python environment.
   *
   * The default, and the mode with the fewest moving parts.
   */
  PIP = 'pip',

  /**
   * Run ASH through `uvx`, which resolves the distribution into a throwaway
   * environment on each invocation.
   *
   * Faster cold starts than `PIP` when the build image already ships `uv`.
   */
  UVX = 'uvx',

  /**
   * Install ASH from a git reference rather than a released distribution.
   *
   * Use this to run an unreleased revision. `ASHScanStepProps.sourceRepository`
   * and `ASHScanStepProps.version` select the repository and the ref.
   */
  GIT = 'git',

  /**
   * Emit no install commands at all, because the build image already provides
   * an `ash` executable on `PATH`.
   *
   * This is the mode to pair with an image built from the ASH `Dockerfile` in
   * a registry the consumer controls. ASH ships no public image, so this mode
   * requires an image the consumer built themselves.
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
