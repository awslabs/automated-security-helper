// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.dev.json' }],
  },
  collectCoverageFrom: ['src/**/*.ts'],
  // CDK synthesis builds real cloud assemblies, which is slower than a plain
  // unit test. The default 5s timeout is tight enough to flake on a loaded box.
  testTimeout: 30000,
};
