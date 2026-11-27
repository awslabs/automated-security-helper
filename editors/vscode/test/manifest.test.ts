// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Assertions about package.json that no behavior test can make, because VS Code
 * reads these fields before any of the extension's code runs.
 */

import * as fs from 'fs';
import * as path from 'path';

const manifest = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'),
) as Record<string, unknown>;

describe('package.json', () => {
  // A scan runs ASH over the workspace, and ASH reads the workspace's own config
  // (.ash/.ash.yaml, an .ashrc file, or [tool.ash] in pyproject.toml), which can
  // load plugin modules and so run code the repository supplies. No subset of this extension's settings makes that safe, so the
  // extension does not run in Restricted Mode at all. Leaving the field out has
  // the same effect, since VS Code treats an undeclared extension as not
  // supporting Workspace Trust, but declaring it records the decision and shows
  // the user the reason.
  it('declares that the extension does not run in an untrusted workspace', () => {
    const capabilities = manifest.capabilities as Record<string, unknown> | undefined;
    const untrusted = capabilities?.untrustedWorkspaces as Record<string, unknown> | undefined;

    expect(untrusted?.supported).toBe(false);
    expect(typeof untrusted?.description).toBe('string');
    expect(untrusted?.description).toContain('.ash');
    // Every config source is read the same way, so the reason names them all.
    expect(untrusted?.description).toContain('.ashrc');
    expect(untrusted?.description).toContain('[tool.ash]');
  });

  // ASH takes command-line options as the operator's: `--sandbox off`,
  // `--config-overrides sandbox.extra_read_paths=[...]` and `--ash-plugin-modules`
  // do what a config file in the scanned tree is refused. A setting the workspace
  // can set would hand them to the repository through its .vscode/settings.json,
  // so the two settings that reach the command line are machine-scoped.
  it.each(['ash.executablePath', 'ash.extraArguments'])(
    'makes %s machine-scoped, so a repository cannot set it',
    (setting) => {
      const contributes = manifest.contributes as Record<string, unknown>;
      const configuration = contributes.configuration as Record<string, unknown>;
      const properties = configuration.properties as Record<string, Record<string, unknown>>;

      expect(properties[setting]?.scope).toBe('machine');
    },
  );
});
