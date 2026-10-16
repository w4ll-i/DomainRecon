import { expect, test } from "./fixtures";

// Performance : l'interface est découpée par écran (React.lazy). Le premier chargement ne tire
// que le point d'entrée et le code partagé ; chaque écran arrive à sa première visite.
const KB = 1000;

test("le fichier JS principal pèse moins de 600 Ko ; les écrans lourds ne sont chargés qu'à la visite", async ({ page }) => {
  const scripts = new Map<string, number>();
  page.on("response", (response) => {
    if (!new URL(response.url()).pathname.endsWith(".js")) return;
    void response
      .body()
      .then((body) => scripts.set(new URL(response.url()).pathname, body.length))
      .catch(() => undefined);
  });
  const loaded = (name: string) => [...scripts.keys()].some((path) => path.includes(`/assets/${name}-`));

  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "Analyse de domaine" })).toBeVisible();
  await page.waitForLoadState("networkidle");

  const entry = [...scripts.entries()].find(([path]) => /\/assets\/index-[^/]+\.js$/.test(path));
  expect(entry, "point d'entrée index-*.js").toBeDefined();
  expect(entry?.[1]).toBeLessThan(600 * KB);
  // Le premier écran ne charge aucun des écrans lourds (graphes, cartes, réglages…).
  for (const screen of ["FamilyPage", "TimelinePage", "SettingsPage", "HistoryPage", "MonitoringPage", "ResultPage"]) {
    expect(loaded(screen), `${screen} chargé trop tôt`).toBe(false);
  }
  const initial = [...scripts.values()].reduce((sum, size) => sum + size, 0);
  expect(initial).toBeLessThan(700 * KB);

  // Première visite d'un écran : son fichier est chargé à ce moment-là, et lui seul.
  await page.getByRole("navigation", { name: "Navigation principale" }).getByRole("link", { name: "Réglages" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Réglages" })).toBeVisible();
  await expect.poll(() => loaded("SettingsPage")).toBe(true);
  expect(loaded("TimelinePage")).toBe(false);

  await page.goto("/history/example.com");
  await expect(page.getByRole("heading", { level: 1, name: "Timeline de example.com" })).toBeVisible();
  await expect.poll(() => loaded("TimelinePage")).toBe(true);
  // Aucun fichier JS ne dépasse 600 Ko.
  for (const [path, size] of scripts) expect(size, path).toBeLessThan(600 * KB);
});

test("un écran qui se charge lentement montre un état de chargement sobre, dans la coquille en place", async ({ page }) => {
  await page.route("**/assets/HelpPage-*.js", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 1500));
    await route.continue();
  });
  await page.goto("/help");
  const main = page.getByRole("main");
  await expect(main.getByRole("status")).toContainText("Chargement");
  // Menu et en-tête sont déjà là pendant le chargement.
  await expect(page.getByRole("navigation", { name: "Navigation principale" })).toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: "Aide" })).toBeVisible();
  await expect(main.getByText("Chargement…")).toHaveCount(0);
});

test("naviguer entre écrans déjà visités ne recharge aucun fichier JS", async ({ page }) => {
  const requested: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.endsWith(".js")) requested.push(path);
  });
  await page.goto("/help");
  await expect(page.getByRole("heading", { level: 1, name: "Aide" })).toBeVisible();
  const nav = page.getByRole("navigation", { name: "Navigation principale" });
  await nav.getByRole("link", { name: "Réglages" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Réglages" })).toBeVisible();
  const before = requested.length;
  await nav.getByRole("link", { name: "Aide" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Aide" })).toBeVisible();
  await nav.getByRole("link", { name: "Réglages" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Réglages" })).toBeVisible();
  expect(requested.length).toBe(before);
});
