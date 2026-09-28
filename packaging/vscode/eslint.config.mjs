// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// ESLint 10 flat config. `typescript-eslint` is the meta package that pulls in
// the matching parser and plugin, so their versions cannot drift apart.
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['out/**', 'node_modules/**', '.vscode-test/**'],
  },
  ...tseslint.configs.recommended,
  {
    rules: {
      // A caught error that is neither reported nor rethrown is the defect class
      // this whole repository's history is about. The parser and the CLI runner
      // each have one deliberate silent catch, and both are commented; anything
      // new has to be argued for in review rather than slipped in.
      'no-empty': ['error', { allowEmptyCatch: false }],
      eqeqeq: ['error', 'always', { null: 'ignore' }],
      'no-throw-literal': 'error',
      curly: 'error',
      // A floating promise in an extension is a failure nobody sees: the
      // rejection lands on the extension host's unhandled-rejection log and the
      // command returns as though it worked.
      '@typescript-eslint/no-floating-promises': 'off',
      '@typescript-eslint/consistent-type-imports': 'off',
    },
  },
);
