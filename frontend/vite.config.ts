/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Build servi par FastAPI (domainrecon/web, dossier généré et non versionné) ;
// en développement, `npm run dev` relaie /api vers le backend local.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../domainrecon/web",
    emptyOutDir: true,
    assetsDir: "assets",
    // Les écrans sont chargés à la demande (src/router.tsx) : aucun fichier JS ne doit dépasser
    // 600 kB (src/bundle.test.ts le vérifie sur le build).
    chunkSizeWarningLimit: 600,
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8000" },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    // Vitest vide les CSS : on garde le texte brut des imports `?raw` (tokens.test.ts).
    css: { include: [/\.css\?raw$/] },
    restoreMocks: true,
    unstubGlobals: true,
  },
});
