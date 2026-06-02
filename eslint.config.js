import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    ignores: ['scratch/**', 'dist/**', 'coverage/**'],
  },
  {
    files: ['**/*.ts', '**/*.tsx', '**/*.mts', '**/*.cts', '**/*.js'],
    languageOptions: {
      globals: {
        console: 'readonly',
        process: 'readonly',
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { argsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/no-explicit-any': 'warn',
      'no-useless-escape': 'warn',
      'no-useless-assignment': 'warn',
      'no-case-declarations': 'warn',
      'no-loss-of-precision': 'warn',
      'preserve-caught-error': 'warn',
    },
  }
);
