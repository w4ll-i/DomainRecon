import { createScan, expect, test } from "./fixtures";

test("historique : pagination, recherche serveur et filtres", async ({ page }) => {
  await page.goto("/history");
  await expect(page.getByRole("heading", { level: 1, name: "Historique" })).toBeVisible();
  await expect(page.getByText(/^Page 1 sur \d+$/)).toBeVisible();
  await page.getByRole("button", { name: "Page suivante" }).click();
  await expect(page).toHaveURL(/page=2/);
  // 25 scans par page : la seconde page affiche la suite (26 et au-delà).
  await expect(page.getByText(/^Page 2 sur \d+$/)).toBeVisible();
  await expect(page.getByText(/^26–\d+ sur \d+ scan\(s\)$/)).toBeVisible();
  await expect(page.getByRole("link", { name: "filler-30.example.net", exact: true })).toBeVisible();

  await page.getByRole("searchbox", { name: "Rechercher un domaine" }).fill("shop.example");
  await expect(page.getByRole("link", { name: "shop.example.com", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "example.com", exact: true })).toHaveCount(0);

  await page.getByLabel("Note", { exact: true }).selectOption("F");
  await expect(page.getByRole("row")).toHaveCount(2);
  await page.getByLabel("Statut", { exact: true }).selectOption("error");
  await expect(page.getByText("Aucun scan ne correspond à ces critères.")).toBeVisible();
});

test("timeline : courbe, changements DNS et domaines liés", async ({ page }) => {
  await page.goto("/history/example.com");
  await expect(page.getByRole("heading", { level: 1, name: "Timeline de example.com" })).toBeVisible();
  await expect(page.getByRole("img", { name: /Évolution du score/ })).toBeVisible();
  await expect(page.getByRole("table")).toContainText("+ 93.184.216.34");
  await page.getByRole("link", { name: /shop\.example\.com/ }).click();
  await expect(page).toHaveURL(/\/history\/shop\.example\.com$/);
  await expect(page.getByText("Pas assez de données")).toBeVisible();
});

test("suppression d'un scan après confirmation", async ({ page, request }) => {
  // Scan créé par le test lui-même : rejouable sur un serveur réutilisé.
  const domain = `delete-${Date.now().toString(36)}.example.org`;
  await createScan(request, domain);
  await page.goto(`/history?q=${domain}`);
  await expect(page.getByRole("link", { name: domain, exact: true })).toBeVisible();
  await page.getByRole("button", { name: `Supprimer le scan de ${domain}` }).click();
  const dialog = page.getByRole("alertdialog", { name: "Supprimer ce scan ?" });
  await dialog.getByRole("button", { name: "Supprimer" }).click();
  await expect(page.getByText("Scan supprimé")).toBeVisible();
  await expect(page.getByText("Aucun scan ne correspond à ces critères.")).toBeVisible();
});
