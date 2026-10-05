// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// ESLint flat config for the extension and its jest suite.
//
// Type-aware, because the rule this package most needs is one only type
// information can check: a floating promise in an extension is a failure nobody
// sees -- the rejection lands in the extension host's log and the command returns
// as though it worked. Each tsconfig is named so every linted file has a program.
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['out/**', 'coverage/**', 'node_modules/**', '.vscode-test/**', 'eslint.config.mjs'],
  },
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.json', './tsconfig.test.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      'no-empty': ['error', { allowEmptyCatch: false }],
      eqeqeq: ['error', 'always'],
      curly: 'error',
      'no-throw-literal': 'error',
    },
  },
);
