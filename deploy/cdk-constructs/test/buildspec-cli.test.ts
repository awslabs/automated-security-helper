// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { check, main, write } from '../src/buildspec-cli';
import { generatedBuildspecs } from '../src/private/buildspec';

/**
 * Every test writes into a temporary directory rather than the package root.
 *
 * `write` overwrites the committed buildspecs, so a test that used the default
 * root would mutate the repository as a side effect of running the suite, and
 * would then make `check` pass trivially because it had just rewritten the very
 * files it compares against.
 */
function tempRoot(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'ash-buildspec-cli-'));
}

/** Captures stdout/stderr writes without letting them reach the real streams. */
function captureStreams() {
  const out: string[] = [];
  const err: string[] = [];
  const outSpy = jest
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: any) => {
      out.push(String(chunk));
      return true;
    });
  const errSpy = jest
    .spyOn(process.stderr, 'write')
    .mockImplementation((chunk: any) => {
      err.push(String(chunk));
      return true;
    });
  return {
    out,
    err,
    restore: () => {
      outSpy.mockRestore();
      errSpy.mockRestore();
    },
  };
}

describe('importing the module', () => {
  it('does not execute the CLI as an import side effect', () => {
    // The `require.main === module` guard is what makes this file testable at
    // all. Without it, importing above would already have run `main` against the
    // real package root -- rewriting the committed buildspecs -- and would have
    // set process.exitCode from a stray argv. Asserting on exitCode is the
    // cheapest observable proof the guard held.
    expect(process.exitCode).toBeUndefined();
  });
});

describe('write', () => {
  it('writes every generated buildspec with byte-exact contents', () => {
    const root = tempRoot();
    const streams = captureStreams();
    try {
      const rc = write(root);
      expect(rc).toBe(0);

      const specs = generatedBuildspecs();
      expect(specs.length).toBeGreaterThan(0);

      for (const spec of specs) {
        const onDisk = fs.readFileSync(path.join(root, spec.filename));
        // Byte equality, not a parsed comparison: the generator's exact output
        // is the contract the drift gate enforces.
        expect(onDisk.equals(Buffer.from(spec.contents, 'utf8'))).toBe(true);
      }
      // Names each file it wrote, so a CI log says what changed.
      for (const spec of specs) {
        expect(streams.out.join('')).toContain(`wrote ${spec.filename}`);
      }
    } finally {
      streams.restore();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('check', () => {
  it('returns 0 when every committed file matches the generated output', () => {
    const root = tempRoot();
    const streams = captureStreams();
    try {
      write(root);
      const rc = check(root);
      expect(rc).toBe(0);
      expect(streams.out.join('')).toContain('match the source of truth');
    } finally {
      streams.restore();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('reports a missing file and returns 1', () => {
    const root = tempRoot();
    const streams = captureStreams();
    try {
      write(root);
      const victim = generatedBuildspecs()[0].filename;
      fs.rmSync(path.join(root, victim));

      const rc = check(root);
      expect(rc).toBe(1);
      const err = streams.err.join('');
      expect(err).toContain(`${victim}: missing`);
      expect(err).toContain('Generated buildspecs are out of date');
      // The message has to say how to fix it, or the gate is a dead end.
      expect(err).toContain('npm run generate:buildspec');
    } finally {
      streams.restore();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('detects a single-byte difference and reports both lengths', () => {
    const root = tempRoot();
    const streams = captureStreams();
    try {
      write(root);
      const victim = generatedBuildspecs()[0];
      const target = path.join(root, victim.filename);
      // One appended byte. A parsed-YAML comparison would very likely still
      // pass here, which is precisely why the implementation compares bytes.
      fs.appendFileSync(target, '\n');

      const rc = check(root);
      expect(rc).toBe(1);
      const err = streams.err.join('');
      expect(err).toContain(`${victim.filename}: differs from generated output`);
      const expectedLen = Buffer.from(victim.contents, 'utf8').length;
      expect(err).toContain(`on disk ${expectedLen + 1} bytes`);
      expect(err).toContain(`generated ${expectedLen} bytes`);
    } finally {
      streams.restore();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('does not rewrite the files it is checking', () => {
    const root = tempRoot();
    const streams = captureStreams();
    try {
      write(root);
      const victim = generatedBuildspecs()[0];
      const target = path.join(root, victim.filename);
      fs.appendFileSync(target, '\n');
      const before = fs.readFileSync(target);

      check(root);

      // A check that silently repaired the drift it found would report a
      // failure once and pass forever after.
      expect(fs.readFileSync(target).equals(before)).toBe(true);
    } finally {
      streams.restore();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('main', () => {
  it('dispatches write', () => {
    const root = tempRoot();
    const streams = captureStreams();
    try {
      expect(main(['node', 'buildspec-cli.js', 'write'], root)).toBe(0);
      for (const spec of generatedBuildspecs()) {
        expect(fs.existsSync(path.join(root, spec.filename))).toBe(true);
      }
    } finally {
      streams.restore();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('dispatches check', () => {
    const root = tempRoot();
    const streams = captureStreams();
    try {
      write(root);
      expect(main(['node', 'buildspec-cli.js', 'check'], root)).toBe(0);
    } finally {
      streams.restore();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('propagates a check failure as exit 1', () => {
    const root = tempRoot();
    const streams = captureStreams();
    try {
      // Empty root: every file is missing.
      expect(main(['node', 'buildspec-cli.js', 'check'], root)).toBe(1);
    } finally {
      streams.restore();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it.each([
    ['no mode', ['node', '/some/path/buildspec-cli.js']],
    ['an unknown mode', ['node', '/some/path/buildspec-cli.js', 'publish']],
  ])('exits 2 and prints usage given %s', (_label, argv) => {
    const root = tempRoot();
    const streams = captureStreams();
    try {
      expect(main(argv as string[], root)).toBe(2);
      const err = streams.err.join('');
      // basename, not the full path, so the usage line is readable.
      expect(err).toContain('usage: buildspec-cli.js <write|check>');
    } finally {
      streams.restore();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('does not touch the filesystem when the mode is invalid', () => {
    const root = tempRoot();
    const streams = captureStreams();
    try {
      main(['node', 'buildspec-cli.js', 'nonsense'], root);
      expect(fs.readdirSync(root)).toHaveLength(0);
    } finally {
      streams.restore();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
