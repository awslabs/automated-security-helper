module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  testMatch: ['**/*.test.ts'],
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
