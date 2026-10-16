import { defineConfig, devices } from "@playwright/test";

// E2E contre le vrai backend (tests/e2e_server.py : base seedée, faux scanner)
// qui sert le build de l'interface. Lancer `npm run build` avant `npm run e2e`.
const PORT = Number(process.env.E2E_PORT ?? 8765);
const PYTHON = process.env.E2E_PYTHON ?? (process.platform === "win32" ? "python" : "python3");

export default defineConfig({
  testDir: "./e2e",
  timeout: 45_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  // Un `test.only` oublié ferait passer la CI sans exécuter le reste.
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI
    ? [["github"], ["html", { open: "never" }]]
    : [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    locale: "fr-FR",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 820 } } }],
  webServer: {
    command: `"${PYTHON}" ../tests/e2e_server.py --port ${PORT}`,
    url: `http://127.0.0.1:${PORT}/api/health`,
    reuseExistingServer: !process.env.CI,
    timeout: 90_000,
    stdout: "pipe",
    stderr: "pipe",
    // Arrêt propre (le serveur supprime alors son dossier de données temporaire).
    // Sous Windows, Playwright arrête le processus lui-même : pas de signal POSIX.
    ...(process.platform === "win32" ? {} : { gracefulShutdown: { signal: "SIGTERM" as const, timeout: 5_000 } }),
  },
});
