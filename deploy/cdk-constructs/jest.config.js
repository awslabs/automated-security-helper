// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  testEnvironment: 'node',
  // `src` is listed alongside `test` so coverage has an honest denominator.
  // With roots confined to `test`, jest's crawler never sees a source file that
  // no test imports, so `collectCoverageFrom` below silently matches nothing for
  // those files and they are omitted from the report entirely rather than
  // appearing at 0%. That inflates the percentage with no error anywhere: this
  // package reported 97.35% while an untested 0%-covered file sat in `src`, and
  // reads 82.51% once the file is counted. `testMatch` still restricts which
  // files are treated as suites, so widening roots adds no tests.
  roots: ['<rootDir>/src', '<rootDir>/test'],
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.dev.json' }],
  },
  collectCoverageFrom: ['src/**/*.ts'],
  // CDK synthesis builds real cloud assemblies, which is slower than a plain
  // unit test. The default 5s timeout is tight enough to flake on a loaded box.
  testTimeout: 30000,
};
