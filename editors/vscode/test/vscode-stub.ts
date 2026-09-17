// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * A stand-in for the `vscode` module, mapped in by jest's `moduleNameMapper`.
 *
 * WHY A STUB AND NOT @vscode/test-electron
 *
 * The real integration harness downloads a full VS Code build (about 120 MB) and
 * needs a display server. Putting that inside the coverage job would add a
 * network fetch and an xvfb dependency to a gate whose job is to hold a
 * percentage steady, and a gate that flakes gets ignored. So the diagnostic model
 * is stubbed here and the limitation is stated in README.md rather than left for
 * a reader to discover.
 *
 * WHAT THIS STUB HAS TO GET RIGHT, AND WHY
 *
 * The suite's central assertion is that a fixture carrying a planted secret ends
 * up with a NON-ZERO number of diagnostics in the editor model. That assertion is
 * only worth anything if `DiagnosticCollection` here behaves like the real one on
 * the three operations the extension performs:
 *
 *   - `set(uri, diagnostics)` keys on the URI's string form, not on object
 *     identity, because the extension builds a fresh `Uri` for every finding and
 *     a stub keyed on identity would silently store each one separately.
 *   - `clear()` empties everything, so a re-scan whose findings shrank does not
 *     leave the previous run's on screen.
 *   - `get(uri)` returns the array that was set, so a test can count it.
 *
 * `Range` clamps negatives to 0 and orders its ends, which is what the real class
 * does. Without that a mapper bug that produced line -1 would be stored as -1
 * here and the test would pass on a range VS Code would have moved.
 *
 * This file is under test/, so the coverage census treats it as the measurer
 * rather than the measured -- see .github/scripts/assert-coverage-completeness.mjs
 * and its NOT_PRODUCTION pattern.
 */

export class Position {
  public readonly line: number;
  public readonly character: number;

  public constructor(line: number, character: number) {
    this.line = Math.max(0, line);
    this.character = Math.max(0, character);
  }

  public isBefore(other: Position): boolean {
    return this.line < other.line || (this.line === other.line && this.character < other.character);
  }
}

export class Range {
  public readonly start: Position;
  public readonly end: Position;

  public constructor(
    startLine: number | Position,
    startCharacter: number | Position,
    endLine?: number,
    endCharacter?: number,
  ) {
    const first =
      startLine instanceof Position ? startLine : new Position(startLine, startCharacter as number);
    const second =
      startCharacter instanceof Position
        ? startCharacter
        : new Position(endLine as number, endCharacter as number);
    // The real Range orders its ends rather than trusting the caller.
    if (second.isBefore(first)) {
      this.start = second;
      this.end = first;
    } else {
      this.start = first;
      this.end = second;
    }
  }
}

export enum DiagnosticSeverity {
  Error = 0,
  Warning = 1,
  Information = 2,
  Hint = 3,
}

export class Diagnostic {
  public source?: string;
  /**
   * Widened to the real `vscode.Diagnostic["code"]` union on purpose. A narrower
   * `string | number` compiles until a test builds a Diagnostic through the
   * `vscode` types and hands it to the stub's collection, at which point the two
   * declarations disagree and the error lands in the test rather than in the
   * code under test.
   */
  public code?: string | number | { value: string | number; target: Uri };

  public constructor(
    public readonly range: Range,
    public readonly message: string,
    public readonly severity: DiagnosticSeverity = DiagnosticSeverity.Error,
  ) {}
}

export class Uri {
  private constructor(
    public readonly scheme: string,
    public readonly fsPath: string,
  ) {}

  public static file(fsPath: string): Uri {
    return new Uri('file', fsPath);
  }

  public static parse(value: string): Uri {
    const withoutScheme = value.replace(/^file:\/\//, '');
    return new Uri('file', decodeURIComponent(withoutScheme));
  }

  public toString(): string {
    return `${this.scheme}://${this.fsPath}`;
  }
}

export interface Disposable {
  dispose(): void;
}

export class DiagnosticCollection {
  private readonly entries = new Map<string, Diagnostic[]>();
  public disposed = false;

  public constructor(public readonly name: string) {}

  public set(uri: Uri, diagnostics: readonly Diagnostic[]): void {
    this.entries.set(uri.toString(), [...diagnostics]);
  }

  public get(uri: Uri): readonly Diagnostic[] | undefined {
    return this.entries.get(uri.toString());
  }

  public delete(uri: Uri): void {
    this.entries.delete(uri.toString());
  }

  public clear(): void {
    this.entries.clear();
  }

  public dispose(): void {
    this.disposed = true;
    this.entries.clear();
  }

  /** Test helper: total diagnostics across every file. Not part of the real API. */
  public totalDiagnostics(): number {
    let total = 0;
    for (const list of this.entries.values()) {
      total += list.length;
    }
    return total;
  }

  /** Test helper: the URIs that received diagnostics. Not part of the real API. */
  public uris(): string[] {
    return [...this.entries.keys()];
  }
}

export class OutputChannel {
  public readonly lines: string[] = [];
  public disposed = false;

  public constructor(public readonly name: string) {}

  public appendLine(line: string): void {
    this.lines.push(line);
  }

  public dispose(): void {
    this.disposed = true;
  }
}

/** Everything a test needs to observe or drive, in one place it can reset. */
export const state = {
  workspaceFolders: undefined as { uri: { fsPath: string } }[] | undefined,
  configuration: new Map<string, unknown>(),
  errors: [] as string[],
  infos: [] as string[],
  channels: [] as OutputChannel[],
  collections: [] as DiagnosticCollection[],
  commands: new Map<string, (...args: unknown[]) => unknown>(),
};

export function resetState(): void {
  state.workspaceFolders = undefined;
  state.configuration = new Map();
  state.errors = [];
  state.infos = [];
  state.channels = [];
  state.collections = [];
  state.commands = new Map();
}

export const languages = {
  createDiagnosticCollection(name: string): DiagnosticCollection {
    const collection = new DiagnosticCollection(name);
    state.collections.push(collection);
    return collection;
  },
};

export const window = {
  createOutputChannel(name: string): OutputChannel {
    const channel = new OutputChannel(name);
    state.channels.push(channel);
    return channel;
  },
  showErrorMessage(message: string): Promise<undefined> {
    state.errors.push(message);
    return Promise.resolve(undefined);
  },
  showInformationMessage(message: string): Promise<undefined> {
    state.infos.push(message);
    return Promise.resolve(undefined);
  },
};

export const workspace = {
  get workspaceFolders(): { uri: { fsPath: string } }[] | undefined {
    return state.workspaceFolders;
  },
  getConfiguration(section: string): { get<T>(key: string, fallback: T): T } {
    return {
      get<T>(key: string, fallback: T): T {
        const value = state.configuration.get(`${section}.${key}`);
        return value === undefined ? fallback : (value as T);
      },
    };
  },
};

export const commands = {
  registerCommand(id: string, callback: (...args: unknown[]) => unknown): Disposable {
    state.commands.set(id, callback);
    return { dispose: () => state.commands.delete(id) };
  },
};
