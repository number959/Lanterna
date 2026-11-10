import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// Anteprima autonoma della mappa della rete (preview/): tutto incorporato in
// un'unica pagina, font compresi, per poterla aprire o pubblicare da sola.
export default defineConfig({
  root: 'preview',
  base: './',
  plugins: [react()],
  build: {
    target: 'es2020',
    outDir: '../dist-preview',
    emptyOutDir: true,
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
    modulePreload: false,
    chunkSizeWarningLimit: 4000,
    rollupOptions: { output: { inlineDynamicImports: true } },
  },
});
