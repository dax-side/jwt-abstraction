module.exports = {
  parser: '@typescript-eslint/parser',
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
  ],
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module',
  },
  rules: {
    '@typescript-eslint/explicit-function-return-type': 'off',
    // Allow 'any' for flexible user payloads and decoded tokens
    '@typescript-eslint/no-explicit-any': 'off',
    // Allow namespace for Express type augmentation
    '@typescript-eslint/no-namespace': 'off',
    // Allow unused vars with underscore prefix
    '@typescript-eslint/no-unused-vars': ['error', { 
      argsIgnorePattern: '^_',
      varsIgnorePattern: '^_',
    }],
  },
  overrides: [
    {
      // Relax rules for test files
      files: ['tests/**/*.ts'],
      rules: {
        '@typescript-eslint/no-var-requires': 'off',
      },
    },
  ],
};
