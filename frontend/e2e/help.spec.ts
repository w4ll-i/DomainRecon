import { expect, test } from "./fixtures";

// Aide : guide, profils, cadre légal, questions fréquentes et glossaire filtrable.

test("l'aide s'organise en cinq sections atteignables depuis un sommaire", async ({ page }) => {
  await page.goto("/help");
  await expect(page.getByRole("heading", { level: 1, name: "Aide" })).toBeVisible();
  const summary = page.getByRole("navigation", { name: "Sections de l'aide" });
  await expect(summary.getByRole("link")).toHaveText([
    "Guide de démarrage",
    "Profils et modules",
    "Cadre légal",
    "Questions fréquentes",
    "Glossaire",
  ]);
  const sections = page.getByRole("heading", { level: 2 });
  await expect(sections).toHaveText(["Guide de démarrage", "Profils et modules", "Cadre légal", "Questions fréquentes", "Glossaire"]);

  // Chaque lien du sommaire mène à sa section (ancre).
  await summary.getByRole("link", { name: "Glossaire" }).click();
  await expect(page).toHaveURL(/#help-glossary$/);
  await expect(page.getByRole("heading", { level: 2, name: "Glossaire" })).toBeInViewport();
});

test("le guide a cinq étapes ; les profils et les catégories de modules sont expliqués", async ({ page }) => {
  await page.goto("/help");
  const guide = page.getByRole("region", { name: "Guide de démarrage" });
  await expect(guide.getByRole("listitem")).toHaveCount(5);

  const profiles = page.getByRole("region", { name: "Profils et modules" });
  for (const profile of ["Rapide", "Complet", "Personnalisé"]) {
    await expect(profiles.getByRole("term").filter({ hasText: profile })).toBeVisible();
  }
  // Les quatre catégories de modules, avec leur pastille.
  await expect(profiles.getByRole("heading", { level: 3 })).toHaveCount(1);
  await expect(profiles.getByRole("definition")).toHaveCount(7);
});

test("le cadre légal rappelle l'usage sur ses propres domaines", async ({ page }) => {
  await page.goto("/help");
  const legal = page.getByRole("region", { name: "Cadre légal" });
  await expect(legal.getByRole("listitem")).toHaveCount(4);
  await expect(legal).toContainText(/autorisation/i);
});

test("la foire aux questions se déplie, et renvoie vers les Réglages pour l'import d'une ancienne base", async ({ page }) => {
  await page.goto("/help");
  const faq = page.getByRole("region", { name: "Questions fréquentes" });
  const items = faq.locator("details");
  await expect(items).toHaveCount(8);
  await expect(items.first()).not.toHaveAttribute("open", "");
  await items.first().getByText("Où sont stockées mes données ?").click();
  await expect(items.first()).toHaveAttribute("open", "");
  await expect(items.first()).toContainText("Aucun résultat n'est envoyé à un serveur de DomainRecon");

  // L'import d'une ancienne base se fait désormais dans les Réglages, plus en ligne de commande.
  const migration = faq.locator("details", { hasText: "Comment importer une ancienne base ?" });
  await migration.getByText("Comment importer une ancienne base ?").click();
  await expect(migration).toContainText("Dans les Réglages");
  await expect(migration).not.toContainText("domainrecon import");

  await faq.getByRole("link", { name: "Ouvrir les Réglages" }).click();
  await expect(page).toHaveURL(/\/settings$/);
});

test("le glossaire se filtre par nom ou par définition, et dit combien de termes restent", async ({ page }) => {
  await page.goto("/help");
  const glossary = page.getByRole("region", { name: "Glossaire" });
  const count = glossary.getByRole("status");
  const total = Number(/^(\d+)/.exec((await count.textContent()) ?? "")?.[1]);
  expect(total).toBeGreaterThan(50);
  await expect(glossary.getByRole("term")).toHaveCount(total);

  const filter = glossary.getByLabel("Filtrer le glossaire");
  await filter.fill("dmarc");
  await expect(glossary.getByRole("term").filter({ hasText: "DMARC" }).first()).toBeVisible();
  const filtered = Number(/^(\d+)/.exec((await count.textContent()) ?? "")?.[1]);
  expect(filtered).toBeGreaterThan(0);
  expect(filtered).toBeLessThan(total);
  await expect(glossary.getByRole("term")).toHaveCount(filtered);

  await filter.fill("zzz-aucun-terme");
  await expect(count).toHaveText("0 terme(s)");
  await expect(glossary.getByRole("term")).toHaveCount(0);

  await filter.fill("");
  await expect(count).toHaveText(`${total} terme(s)`);
});

test("l'aide est traduite en anglais", async ({ page }) => {
  await page.addInitScript(() => window.localStorage.setItem("domainrecon.lang", "en"));
  await page.goto("/help");
  await expect(page.getByRole("heading", { level: 1, name: "Help" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Help sections" })).toBeVisible();
  const faq = page.getByRole("region", { name: "Frequently asked questions" });
  const migration = faq.locator("details", { hasText: "How do I import an old database?" });
  await migration.getByText("How do I import an old database?").click();
  await expect(migration).toContainText("In Settings");
});
