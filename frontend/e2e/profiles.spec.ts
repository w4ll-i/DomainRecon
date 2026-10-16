import type { Page } from "@playwright/test";
import { deleteScansOf, expect, test, uniqueSuffix } from "./fixtures";

// Choix du profil de scan sur « Nouveau scan » : trois profils, modules par famille pour le profil
// personnalisé, case d'autorisation exigée par les modules actifs et sensibles. Les scans lancés
// ici passent par le faux scanner du serveur de test (aucun réseau) et sont supprimés ensuite.

const scanButton = (page: Page) => page.getByRole("button", { name: "Scan", exact: true });
const profileGroup = (page: Page) => page.getByRole("group", { name: "Profil du scan" });

// Corps de la prochaine requête POST /api/scans.
function nextLaunch(page: Page) {
  return page.waitForRequest((req) => req.method() === "POST" && new URL(req.url()).pathname === "/api/scans");
}

test("trois profils décrits en clair ; « Complet » est le profil par défaut", async ({ page }) => {
  await page.goto("/");
  const profiles = profileGroup(page);
  await expect(profiles.getByRole("radio")).toHaveCount(3);
  await expect(profiles.getByRole("radio", { name: /^Complet/ })).toBeChecked();
  // Chaque profil dit ce qu'il lance ; le nombre de modules rapides vient du catalogue.
  await expect(profiles).toContainText(/Les \d+ modules passifs essentiels\. Quelques secondes, aucune sonde envoyée à la cible\./);
  await expect(profiles).toContainText("Tous les modules passifs, et ceux qui utilisent une clé d'API renseignée. Aucun module actif ni sensible.");
  await expect(profiles).toContainText("Vous choisissez les modules, famille par famille, y compris les modules actifs et sensibles.");
  // Pas de liste de modules ni de case d'autorisation hors du profil personnalisé.
  await expect(page.getByRole("checkbox")).toHaveCount(0);
});

test("le profil Complet part sans profil explicite, le profil Rapide l'annonce au serveur", async ({ page, request }) => {
  const stamp = uniqueSuffix();
  const complete = `profil-c-${stamp}.example.org`;
  const quick = `profil-r-${stamp}.example.org`;
  try {
    await page.goto("/");
    await page.getByLabel("Domaine ou URL à analyser").fill(complete);
    let launched = nextLaunch(page);
    await scanButton(page).click();
    // « Complet » est le profil par défaut du serveur : il n'est pas répété dans la requête.
    expect((await launched).postDataJSON()).toEqual({ domain: complete });
    await expect(page).toHaveURL(/\/scans\/\d+$/, { timeout: 30_000 });

    await page.goto("/");
    // Le nombre de modules rapides vient du catalogue du serveur : jamais annoncé « 0 » avant son arrivée.
    const quickLabel = profileGroup(page).locator("label").filter({ has: page.getByRole("radio", { name: /^Rapide/ }) });
    await expect(quickLabel).not.toContainText(/Les 0 modules/);
    await expect(quickLabel).toContainText(/Les [1-9][0-9]* modules passifs essentiels/);
    const description = await quickLabel.textContent();
    const quickCount = Number(/Les (\d+) modules/.exec(description ?? "")?.[1]);
    expect(quickCount).toBeGreaterThan(5);
    await profileGroup(page).getByRole("radio", { name: /^Rapide/ }).check();
    await page.getByLabel("Domaine ou URL à analyser").fill(quick);
    launched = nextLaunch(page);
    await scanButton(page).click();
    expect((await launched).postDataJSON()).toEqual({ domain: quick, profile: "rapide" });
    // Le suivi annonce le plan du profil : bien moins de modules que le profil Complet.
    await expect(page).toHaveURL(/\/scans\/live\/[0-9a-f]+$/);
    const counter = page.getByText(/^\d{1,3} modules sur \d{1,3}$/);
    await expect(counter).toBeVisible();
    const total = Number(/sur (\d+)$/.exec((await counter.textContent()) ?? "")?.[1]);
    expect(total).toBeGreaterThanOrEqual(quickCount);
    expect(total).toBeLessThan(40);
    await expect(page).toHaveURL(/\/scans\/\d+$/, { timeout: 30_000 });
  } finally {
    await deleteScansOf(request, complete);
    await deleteScansOf(request, quick);
  }
});

test("profil personnalisé : modules par famille, compteur, tout choisir ou rien", async ({ page }) => {
  await page.goto("/");
  await profileGroup(page).getByRole("radio", { name: /^Personnalisé/ }).check();
  const count = page.getByRole("status").filter({ hasText: /module\(s\) choisi\(s\) sur/ });
  await expect(count).toHaveText(/^\d+ module\(s\) choisi\(s\) sur \d+$/);
  const initial = Number(/^(\d+)/.exec((await count.textContent()) ?? "")?.[1]);
  const total = Number(/sur (\d+)$/.exec((await count.textContent()) ?? "")?.[1]);
  // Au départ : les modules passifs seulement (aucune sonde envoyée à la cible).
  expect(initial).toBeGreaterThan(10);
  expect(initial).toBeLessThan(total);

  // Une famille se déplie et se choisit d'un clic ; son compteur suit.
  const web = page.locator("details").filter({ has: page.locator("summary", { hasText: "Web" }) }).first();
  await web.locator("summary").click();
  await expect(web.getByRole("checkbox").first()).toBeVisible();
  const chosenInWeb = await web.getByRole("checkbox", { checked: true }).count();
  expect(chosenInWeb).toBeGreaterThan(0);
  await web.getByRole("button", { name: "Aucun : Web" }).click();
  await expect(web.getByRole("checkbox", { checked: true })).toHaveCount(0);
  await expect(count).toHaveText(`${initial - chosenInWeb} module(s) choisi(s) sur ${total}`);
  await web.getByRole("button", { name: "Tout choisir : Web" }).click();
  const webTotal = await web.getByRole("checkbox").count();
  await expect(web.getByRole("checkbox", { checked: true })).toHaveCount(webTotal);
  await expect(web.locator("summary")).toContainText(`${webTotal}/${webTotal}`);

  // Aucun module choisi nulle part : message et lancement impossible.
  const families = page.locator("details");
  const familyCount = await families.count();
  for (let index = 0; index < familyCount; index += 1) {
    const family = families.nth(index);
    if (!(await family.evaluate((element) => (element as HTMLDetailsElement).open))) await family.locator("summary").click();
    await family.getByRole("button", { name: /^Aucun : / }).click();
  }
  await expect(count).toHaveText(`0 module(s) choisi(s) sur ${total}`);
  await expect(page.getByText("Choisissez au moins un module.")).toBeVisible();
  await page.getByLabel("Domaine ou URL à analyser").fill("exemple-vide.example.org");
  await expect(scanButton(page)).toBeDisabled();
});

test("un module actif exige la case d'autorisation ; le scan part avec les modules choisis et l'autorisation", async ({ page, request }) => {
  const domain = `profil-p-${uniqueSuffix()}.example.org`;
  try {
    await page.goto("/");
    await page.getByLabel("Domaine ou URL à analyser").fill(domain);
    await profileGroup(page).getByRole("radio", { name: /^Personnalisé/ }).check();
    await expect(page.getByRole("checkbox", { name: /J'ai l'autorisation/ })).toHaveCount(0);
    await expect(scanButton(page)).toBeEnabled();

    // « Ports ouverts » envoie des sondes à la cible : c'est un module actif.
    const network = page.locator("details").filter({ has: page.locator("summary", { hasText: "Réseau" }) }).first();
    await network.locator("summary").click();
    const ports = network.getByRole("checkbox", { name: /Ports ouverts/ });
    await expect(ports).not.toBeChecked();
    await ports.check();

    const consent = page.getByRole("checkbox", { name: "J'ai l'autorisation de tester cette cible" });
    await expect(consent).toBeVisible();
    await expect(consent).not.toBeChecked();
    await expect(page.getByText("Obligatoire pour les modules actifs et sensibles.")).toBeVisible();
    // Tant que la case n'est pas cochée, le scan ne part pas.
    await expect(scanButton(page)).toBeDisabled();

    await consent.check();
    await expect(scanButton(page)).toBeEnabled();
    const launched = nextLaunch(page);
    await scanButton(page).click();
    const body = (await launched).postDataJSON() as { domain: string; profile: string; selected: string[]; authorized_target: boolean };
    expect(body.domain).toBe(domain);
    expect(body.profile).toBe("personnalise");
    expect(body.authorized_target).toBe(true);
    expect(body.selected).toContain("open_ports");
    expect(body.selected.length).toBeGreaterThan(10);
    await expect(page).toHaveURL(/\/scans\/live\/[0-9a-f]+$/);
    await expect(page).toHaveURL(/\/scans\/\d+$/, { timeout: 30_000 });
  } finally {
    await deleteScansOf(request, domain);
  }
});

test("décocher le dernier module actif fait disparaître la case d'autorisation", async ({ page }) => {
  await page.goto("/");
  await profileGroup(page).getByRole("radio", { name: /^Personnalisé/ }).check();
  const network = page.locator("details").filter({ has: page.locator("summary", { hasText: "Réseau" }) }).first();
  await network.locator("summary").click();
  await network.getByRole("checkbox", { name: /Ports ouverts/ }).check();
  const consent = page.getByRole("checkbox", { name: "J'ai l'autorisation de tester cette cible" });
  await expect(consent).toBeVisible();
  await consent.check();
  await network.getByRole("checkbox", { name: /Ports ouverts/ }).uncheck();
  await expect(page.getByRole("checkbox", { name: /J'ai l'autorisation/ })).toHaveCount(0);
});

test("la cible refusée par le serveur est dite près du champ, quel que soit le profil", async ({ page }) => {
  await page.goto("/");
  await profileGroup(page).getByRole("radio", { name: /^Rapide/ }).check();
  await page.getByLabel("Domaine ou URL à analyser").fill("exa mple.com");
  await scanButton(page).click();
  await expect(page.getByRole("alert")).toHaveText("Cible invalide : 'exa mple.com'");
  await expect(page).toHaveURL(/\/$/);
  // Le profil choisi est conservé.
  await expect(profileGroup(page).getByRole("radio", { name: /^Rapide/ })).toBeChecked();
});
