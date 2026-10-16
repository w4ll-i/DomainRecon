import { expect, scanIdFor, test } from "./fixtures";

// Tableau de bord : le dernier état de chaque domaine analysé (note, tendance, constats,
// surveillance), vu contre le vrai serveur et sa base seedée.

test("le tableau de bord résume chaque domaine : note, score, tendance, constats", async ({ page }) => {
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { level: 1, name: "Tableau de bord" })).toBeVisible();
  await expect(page.getByText("Le dernier état de chaque domaine analysé")).toBeVisible();

  // Quatre indicateurs d'appoint, pas davantage.
  for (const label of ["Domaines", "Score moyen", "Avec constat urgent", "Surveillés"]) {
    await expect(page.getByText(label, { exact: true }).first()).toBeVisible();
  }

  const table = page.getByRole("table", { name: "Dernier scan de chaque domaine" });
  await expect(table).toBeVisible();
  await expect(table.getByRole("columnheader")).toHaveText([
    "Domaine",
    "Note",
    "Score",
    "Tendance",
    "Constats",
    "Surveillance",
    "Statut",
    "Dernier scan",
    "Actions",
  ]);

  // example.com : trois scans (62 → 71 → 84), dernière note B, cinq constats dont aucun urgent.
  const example = table.getByRole("row").filter({ has: page.getByRole("link", { name: "example.com", exact: true }) });
  await expect(example.getByRole("img", { name: "Note B" })).toBeVisible();
  await expect(example.getByRole("cell").nth(1)).toContainText("84");
  await expect(example.getByText("5 constat(s) dont 0 urgent(s)")).toBeVisible();
  await expect(example.getByRole("img", { name: "Tendance des scores de example.com" })).toBeVisible();
  await expect(example.getByText("Réussi")).toBeVisible();

  // shop.example.com : un seul scan, note F, trois constats urgents.
  const shop = table.getByRole("row").filter({ has: page.getByRole("link", { name: "shop.example.com", exact: true }) });
  await expect(shop.getByRole("img", { name: "Note F" })).toBeVisible();
  await expect(shop.getByText("13 constat(s) dont 3 urgent(s)")).toBeVisible();
  // Pas de courbe avec un seul point, pas de lien « Comparer » avec un seul scan.
  await expect(shop.getByRole("img", { name: /Tendance/ })).toHaveCount(0);
  await expect(shop.getByRole("link", { name: "Comparer" })).toHaveCount(0);

  // Un domaine au scan partiel le dit.
  const partial = table.getByRole("row").filter({ has: page.getByRole("link", { name: "partial.example.net", exact: true }) });
  await expect(partial.getByText("Partiel")).toBeVisible();
});

test("le nom d'un domaine ouvre son dernier scan, « Comparer » ouvre la comparaison de ses scans", async ({ page, request }) => {
  await page.goto("/dashboard");
  const table = page.getByRole("table", { name: "Dernier scan de chaque domaine" });
  const id = await scanIdFor(request, "example.com");
  await table.getByRole("link", { name: "example.com", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/scans/${id}$`));
  await expect(page.getByRole("heading", { level: 1, name: "example.com" })).toBeVisible();

  await page.goBack();
  const example = table.getByRole("row").filter({ has: page.getByRole("link", { name: "example.com", exact: true }) });
  await example.getByRole("link", { name: "Comparer" }).click();
  await expect(page).toHaveURL(/\/compare\?domain=example\.com$/);
  await expect(page.getByRole("heading", { level: 1, name: "Comparer deux scans" })).toBeVisible();
  await expect(page.getByLabel("Domaine", { exact: true })).toHaveValue("example.com");
});

test("le tableau de bord suit la langue : textes anglais, mêmes données", async ({ page }) => {
  await page.addInitScript(() => window.localStorage.setItem("domainrecon.lang", "en"));
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
  const table = page.getByRole("table", { name: "Latest scan of each domain" });
  await expect(table).toBeVisible();
  const example = table.getByRole("row").filter({ has: page.getByRole("link", { name: "example.com", exact: true }) });
  await expect(example.getByRole("img", { name: "Grade B" })).toBeVisible();
});

test("tableau de bord vide ou en panne : message clair et sortie, pas d'écran blanc", async ({ page }) => {
  await page.route("**/api/dashboard*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        domains: [],
        totals: { domains: 0, shown: 0, watched: 0, average_score: null, grades: {}, findings: { critical: 0, high: 0, medium: 0, low: 0, total: 0 }, with_critical_or_high: 0 },
      }),
    }),
  );
  await page.goto("/dashboard");
  await expect(page.getByText("Aucun domaine analysé")).toBeVisible();
  await page.getByRole("link", { name: "Lancer un scan" }).click();
  await expect(page).toHaveURL(/\/$/);

  await page.unroute("**/api/dashboard*");
  await page.route("**/api/dashboard*", (route) =>
    route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ detail: "Base indisponible", code: null, params: {} }) }),
  );
  await page.goto("/dashboard");
  const alert = page.getByRole("alert");
  await expect(alert).toContainText("Base indisponible");
  await expect(alert.getByRole("button", { name: "Réessayer" })).toBeVisible();
});
