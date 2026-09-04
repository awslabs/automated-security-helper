module.exports = {
  testEnvironment: 'node',
  // `lib` and `bin` are listed alongside `test` so coverage has an honest
  // denominator. With roots confined to `test`, jest's crawler never sees a
  // source file that no test imports, so such a file is omitted from the report
  // entirely rather than appearing at 0% -- which inflates the percentage with
  // no error anywhere. `testMatch` still decides which files are suites, so
  // widening roots adds no tests.
  roots: ['<rootDir>/lib', '<rootDir>/bin', '<rootDir>/test'],
  testMatch: ['**/*.test.ts'],
  // Stated explicitly rather than inferred from what the tests happened to
  // import, for the same reason.
  collectCoverageFrom: ['lib/**/*.ts', 'bin/**/*.ts'],
  // "ts" FIRST, ahead of jest's default "js". Any stale compiled sibling of a
  // source file would otherwise be preferred, and the suite would pass against
  // code that had already been edited. tsconfig.json also sends tsc output to
  // dist/ so such siblings should not exist; this states the intent for jest
  // regardless of what else writes into the tree.
  moduleFileExtensions: ['ts', 'js', 'json', 'node'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest',
  },
};
