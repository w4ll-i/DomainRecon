import { expect, scanIdFor, test } from "./fixtures";

// Captures des écrans principaux dans les deux thèmes, jointes au rapport Playwright
// (playwright-report/) et à test-results/ : elles servent à la revue visuelle. Le mouvement
// est réduit (prefers-reduced-motion) : les animations CSS et les compteurs affichent d'emblée
// leur état final, les captures sont stables d'un lancement à l'autre.
const THEMES = ["dark", "light"] as const;

for (const theme of THEMES) {
  test.describe(`écrans principaux, thème ${theme}`, () => {
    test.beforeEach(async ({ page }) => {
      await page.emulateMedia({ reducedMotion: "reduce", colorScheme: theme });
      // Choix mémorisé : le thème de la capture ne dépend pas de la préférence de la machine.
      await page.addInitScript((value) => window.localStorage.setItem("domainrecon.theme", value), theme);
    });

    const capture = async (page: import("@playwright/test").Page, info: import("@playwright/test").TestInfo, name: string) => {
      await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
      await page.waitForLoadState("networkidle");
      await info.attach(`${name}-${theme}`, { body: await page.screenshot({ fullPage: true }), contentType: "image/png" });
    };

    test("nouveau scan", async ({ page }, info) => {
      await page.goto("/");
      await expect(page.getByRole("heading", { level: 1, name: "Analyse de domaine" })).toBeVisible();
      await capture(page, info, "nouveau-scan");
    });

    test("historique", async ({ page }, info) => {
      await page.goto("/history");
      await expect(page.getByRole("table")).toBeVisible();
      await capture(page, info, "historique");
    });

    test("résultat", async ({ page, request }, info) => {
      const id = await scanIdFor(request, "shop.example.com");
      await page.goto(`/scans/${id}`);
      await expect(page.getByRole("heading", { level: 1, name: "shop.example.com" })).toBeVisible();
      await capture(page, info, "resultat");
    });

    test("résultat, détail du score", async ({ page, request }, info) => {
      const id = await scanIdFor(request, "shop.example.com");
      await page.goto(`/scans/${id}?tab=score`);
      await expect(page.getByRole("tabpanel", { name: "Détail du score" })).toBeVisible();
      await capture(page, info, "resultat-score");
    });

    test("famille web", async ({ page, request }, info) => {
      const id = await scanIdFor(request, "shop.example.com");
      await page.goto(`/scans/${id}/web`);
      await expect(page.getByRole("heading", { level: 1, name: "Web" })).toBeVisible();
      await capture(page, info, "famille-web");
    });

    test("timeline", async ({ page }, info) => {
      await page.goto("/history/example.com");
      await expect(page.getByRole("img", { name: /Évolution du score/ })).toBeVisible();
      await capture(page, info, "timeline");
    });

    test("tableau de bord", async ({ page }, info) => {
      await page.goto("/dashboard");
      await expect(page.getByRole("table", { name: "Dernier scan de chaque domaine" })).toBeVisible();
      await capture(page, info, "tableau-de-bord");
    });

    test("comparer", async ({ page }, info) => {
      await page.goto("/compare?domain=example.com");
      await expect(page.getByRole("region", { name: "Note et score" })).toBeVisible();
      await capture(page, info, "comparer");
    });

    test("lot", async ({ page }, info) => {
      await page.goto("/batch");
      await expect(page.getByRole("heading", { level: 1, name: "Scan en lot" })).toBeVisible();
      await capture(page, info, "lot");
    });

    test("surveillance", async ({ page }, info) => {
      await page.goto("/monitoring");
      await expect(page.getByRole("heading", { level: 1, name: "Surveillance" })).toBeVisible();
      await expect(page.getByRole("region", { name: "Tâche système" })).toBeVisible();
      await capture(page, info, "surveillance");
    });

    test("aide", async ({ page }, info) => {
      await page.goto("/help");
      await expect(page.getByRole("heading", { level: 1, name: "Aide" })).toBeVisible();
      await capture(page, info, "aide");
    });

    test("comprendre et corriger", async ({ page, request }, info) => {
      const id = await scanIdFor(request, "shop.example.com");
      await page.goto(`/scans/${id}`);
      const item = page.getByRole("list", { name: "À corriger" }).getByRole("listitem").filter({ hasText: "En-tête HSTS absent" });
      await item.getByRole("button", { name: /Comprendre et corriger/ }).click();
      await expect(item.getByRole("tablist", { name: "Variantes par plateforme" })).toBeVisible();
      await capture(page, info, "comprendre-et-corriger");
    });

    test("choix du profil", async ({ page }, info) => {
      await page.goto("/");
      await page.getByRole("group", { name: "Profil du scan" }).getByRole("radio", { name: /^Personnalisé/ }).check();
      await page.locator("summary", { hasText: "Réseau" }).click();
      await page.getByRole("checkbox", { name: /Ports ouverts/ }).check();
      await expect(page.getByRole("checkbox", { name: "J'ai l'autorisation de tester cette cible" })).toBeVisible();
      await capture(page, info, "choix-du-profil");
    });

    test("réglages", async ({ page }, info) => {
      await page.goto("/settings");
      await expect(page.getByRole("heading", { level: 1, name: "Réglages" })).toBeVisible();
      await capture(page, info, "reglages");
    });
  });
}
