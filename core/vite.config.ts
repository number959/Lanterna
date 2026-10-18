import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// base relativa: l'interfaccia viene servita dall'agente da qualunque porta
// (in locale: un unico file da circa 1 MB si carica in pochi millisecondi)
// e funziona anche aperta come file o dentro WebView2/Android WebView.
export default defineConfig({
  base: './',
  plugins: [react()],
  build: { target: 'es2020', outDir: 'dist', assetsInlineLimit: 0, chunkSizeWarningLimit: 1200 },
  server: { proxy: { '/api': 'http://127.0.0.1:8737' } },
  test: { include: ['test/**/*.test.ts'] },
});
