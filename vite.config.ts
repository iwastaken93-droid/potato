import { defineConfig } from 'vitest/config';
import * as path from 'path';

const config = {
  root: 'src',
  server: {
    port: 5173,
    host: true,
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: '../dist',
    emptyOutDir: true,
  },
  test: {
    include: ['../tests/**/*.test.ts', '**/*.test.ts'],
    testTimeout: 30000,
  },
};

export default defineConfig(config);
