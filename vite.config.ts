import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  server: {
    watch: {
      // Windows locks running Rust binaries; these are not frontend sources.
      ignored: ['**/target/**', '**/src-tauri/**', '**/artifacts/**', '**/test-results/**'],
    },
  },
  build: {
    outDir: 'dist',
    target: 'es2021',
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
});
