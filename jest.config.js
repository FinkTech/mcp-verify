module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests', '<rootDir>/libs', '<rootDir>/apps'],
  testMatch: ['**/*.spec.ts', '**/*.test.ts'],

  // Transform configuration
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      diagnostics: false, // Disable TypeScript diagnostics completely
      tsconfig: {
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
        skipLibCheck: true,
        isolatedModules: true,
      },
    }],
    // Transform ESM modules from node_modules using ts-jest
    '^.+\\.m?js$': ['ts-jest', {
      tsconfig: {
        allowJs: true,
        esModuleInterop: true,
      },
    }],
  },

  // Transform ALL node_modules (aggressive approach for ESM compatibility)
  transformIgnorePatterns: [],

  // Module name mapper for ESM compatibility
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
    // Mock chalk to avoid ESM issues (last resort)
    '^chalk$': '<rootDir>/tests/__mocks__/chalk.js',
  },

  // Increase global timeout for integration tests
  testTimeout: 300000,

  // Ensure proper module resolution
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
};