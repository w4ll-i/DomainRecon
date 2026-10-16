import { expect, scanIdFor, test } from "./fixtures";

// Comparer deux scans d'un domaine : example.com a trois scans seedés (note C 62 → C 71 → B 84).
// Par défaut, l'avant-dernier est comparé au dernier.

test("sans domaine choisi : une invitation, pas un écran vide", async ({ page }) => {
  await page.goto("/compare");
  await expect(page.getByRole("heading", { level: 1, name: "Comparer deux scans" })).toBeVisible();
  await expect(page.getByText("Aucun domaine choisi")).toBeVisible();
  await expect(page.getByText("Saisissez un domaine déjà analysé pour comparer deux de ses scans.")).toBeVisible();
  await expect(page.getByLabel("Scan de référence (le plus ancien)")).toHaveCount(0);
});

test("choisir un domaine compare ses deux derniers scans : note, constats résolus, DNS", async ({ page }) => {
  await page.goto("/compare");
  await page.getByLabel("Domaine", { exact: true }).fill("example.com");
  await page.getByRole("button", { name: "Choisir" }).click();
  await expect(page).toHaveURL(/\/compare\?domain=example\.com$/);

  // Référence : l'avant-dernier scan (C), à comparer : le dernier (B).
  const reference = page.getByLabel("Scan de référence (le plus ancien)");
  const recent = page.getByLabel("Scan à comparer (le plus récent)");
  await expect(reference).toBeVisible();
  await expect(reference.locator("option")).toHaveCount(3);
  await expect(recent.locator("option")).toHaveCount(3);
  await expect(reference.locator("option:checked")).toContainText("C · #");
  await expect(recent.locator("option:checked")).toContainText("B · #");

  const score = page.getByRole("region", { name: "Note et score" });
  await expect(score.getByRole("img", { name: "Note C" })).toBeVisible();
  await expect(score.getByRole("img", { name: "Note B" })).toBeVisible();
  await expect(score).toContainText("71 → 84");
  await expect(score).toContainText("+13 points");
  const summary = score.getByRole("list", { name: "Résumé des changements" });
  await expect(summary.getByRole("listitem")).toHaveText([
    "Note C → B (écart de score : 13).",
    "2 constat(s) résolu(s).",
    "Enregistrements DNS modifiés : A ; DMARC ; TXT.",
  ]);

  const findings = page.getByRole("region", { name: "Constats" });
  await expect(findings.getByText("Constats résolus")).toBeVisible();
  await expect(findings).toContainText("En-tête HSTS absent");
  await expect(findings.getByText("Aucun nouveau constat.")).toBeVisible();
  await expect(findings.getByText("5 constat(s) inchangé(s).")).toBeVisible();

  const dns = page.getByRole("region", { name: "Enregistrements DNS" });
  // Une ligne retirée (−) et une ligne ajoutée (+), chacune avec son nom accessible.
  await expect(dns.getByLabel("Retiré").first()).toBeVisible();
  await expect(dns.getByLabel("Ajouté").first()).toBeVisible();
  await expect(dns).toContainText("93.184.216.35");
  await expect(dns).toContainText("v=DMARC1; p=quarantine");

  // Pas de changement de ports ni de sous-domaines entre ces deux scans.
  await expect(page.getByRole("region", { name: "Ports ouverts" }).getByText("Aucun changement.")).toBeVisible();
  await expect(page.getByRole("region", { name: "Sous-domaines" }).getByText("Aucun changement.")).toBeVisible();
});

test("changer de scan de référence recalcule la comparaison ; deux fois le même scan est refusé", async ({ page, request }) => {
  await page.goto("/compare?domain=example.com");
  const reference = page.getByLabel("Scan de référence (le plus ancien)");
  const recent = page.getByLabel("Scan à comparer (le plus récent)");
  await expect(reference).toBeVisible();

  // Le plus ancien (note C, 62) contre le plus récent (B, 84) : un écart de 22 points.
  const oldest = await reference.locator("option").first().getAttribute("value");
  await reference.selectOption(oldest ?? "");
  await expect(page.getByRole("region", { name: "Note et score" })).toContainText("62 → 84");
  await expect(page.getByRole("region", { name: "Note et score" })).toContainText("+22 points");

  // Même scan des deux côtés : message, aucune comparaison.
  const latest = String(await scanIdFor(request, "example.com"));
  await reference.selectOption(latest);
  await recent.selectOption(latest);
  await expect(page.getByText("Choisissez deux scans différents.")).toBeVisible();
  await expect(page.getByRole("region", { name: "Note et score" })).toHaveCount(0);
});

test("un domaine à un seul scan : il en faut deux, avec la sortie vers un nouveau scan", async ({ page }) => {
  await page.goto("/compare?domain=shop.example.com");
  await expect(page.getByText("Deux scans nécessaires")).toBeVisible();
  await expect(page.getByText("shop.example.com n'a pas assez de scans")).toBeVisible();
  await page.getByRole("link", { name: "Lancer un scan" }).click();
  await expect(page).toHaveURL(/\/$/);
});

test("la liste de suggestions reprend les domaines du tableau de bord", async ({ page }) => {
  await page.goto("/compare");
  await expect(page.locator("datalist#compare-domains option[value='example.com']")).toHaveCount(1);
  await expect(page.locator("datalist#compare-domains option[value='shop.example.com']")).toHaveCount(1);
});
