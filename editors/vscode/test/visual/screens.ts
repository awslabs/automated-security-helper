// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Screen capture and pixel comparison for the visual suite, through ImageMagick.
 *
 * WHY THE X SERVER AND NOT ELECTRON
 *
 * An extension cannot reach the workbench's BrowserWindow, so `capturePage` is not
 * available from the extension host. The X server the window draws into is: the
 * extension host inherits DISPLAY, and ImageMagick's `import -window root` reads
 * the framebuffer Xvfb holds. That is the whole screen, at the fixed geometry
 * run.ts gives Xvfb, and it is what a user would see.
 *
 * WHY THE THRESHOLD IS ZERO
 *
 * `compare -metric AE` counts pixels that differ at all (no `-fuzz`). The suite was
 * run three times in a row in the pinned container with every capture identical to
 * the pixel, so there is no measured variance to allow for, and any tolerance would
 * only be room for a styling change to pass. See README.md beside this file,
 * "Threshold and determinism".
 *
 * WHY THE PNG IS WRITTEN WITHOUT ITS TIME CHUNKS
 *
 * ImageMagick stamps date:create and date:modify into a PNG by default, so two
 * captures of the same pixels would differ as files. `-strip` and the excluded
 * chunks keep a baseline that did not change visually byte-identical too, which is
 * what lets git, and the Snapshot-Update trailer check, see "unchanged" as unchanged.
 */

import { spawnSync } from 'child_process';

/** PNG24: 8-bit RGB, no alpha and no palette, so the encoding cannot vary with content. */
const PNG_OUTPUT = ['-depth', '8', '-strip', '-define', 'png:exclude-chunks=date,time,tIME'];

function run(program: string, args: readonly string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(program, args, { encoding: 'utf8' });
  if (result.error !== undefined) {
    throw new Error(`${program} could not run: ${result.error.message}`);
  }
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

/** Writes the whole X screen to `file` as a PNG. */
export function captureScreen(display: string, file: string): void {
  const result = run('import', ['-display', display, '-window', 'root', ...PNG_OUTPUT, `PNG24:${file}`]);
  if (result.status !== 0) {
    throw new Error(`import exited ${String(result.status)}: ${result.stderr}`);
  }
}

/** ImageMagick's signature of the decoded pixels: equal exactly when every pixel is. */
export function pixelSignature(file: string): string {
  const result = run('identify', ['-format', '%#', file]);
  if (result.status !== 0 || !/^[0-9a-f]{64}$/.test(result.stdout.trim())) {
    throw new Error(`identify gave no signature for ${file}: ${result.stderr}${result.stdout}`);
  }
  return result.stdout.trim();
}

/**
 * The number of pixels that differ between two images, writing a diff image.
 *
 * Images of different sizes are a difference too, reported as Infinity: `compare`
 * refuses them with exit 2, and that must not read as zero.
 */
export function differingPixels(baseline: string, actual: string, diff: string): number {
  const result = run('compare', ['-metric', 'AE', baseline, actual, diff]);
  // compare exits 0 when the images match, 1 when they differ, 2 on error. The
  // count goes to stderr in every case it can compute one.
  if (result.status === 2) {
    if (/widths or heights differ/i.test(result.stderr)) {
      return Number.POSITIVE_INFINITY;
    }
    throw new Error(`compare failed: ${result.stderr}`);
  }
  const count = Number(result.stderr.trim().split(/\s+/)[0]);
  if (!Number.isFinite(count)) {
    throw new Error(`compare printed no pixel count: ${JSON.stringify(result.stderr)}`);
  }
  if ((count === 0) !== (result.status === 0)) {
    throw new Error(`compare exited ${String(result.status)} but counted ${count} differing pixels`);
  }
  return count;
}
