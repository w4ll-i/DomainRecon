import { expect, test } from "./fixtures";

test("l'accueil : héros, bouton SCAN, choix du profil et cinq scans récents qui mènent au résultat", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Reconnaissance · OSINT")).toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: "Analyse de domaine" })).toBeVisible();
  await expect(page.getByLabel("Domaine ou URL à analyser")).toBeFocused();
  await expect(page.getByRole("button", { name: "Scan", exact: true })).toBeVisible();
  // Le choix du profil est là : trois profils, « Complet » (celui du serveur) coché d'emblée.
  const profiles = page.getByRole("group", { name: "Profil du scan" });
  await expect(profiles.getByRole("radio")).toHaveCount(3);
  await expect(profiles.getByRole("radio", { name: /^Complet/ })).toBeChecked();
  await expect(profiles.getByRole("radio", { name: /^Rapide/ })).not.toBeChecked();
  await expect(profiles.getByRole("radio", { name: /^Personnalisé/ })).not.toBeChecked();
  // Aucune case d'autorisation tant qu'aucun module actif n'est choisi.
  await expect(page.getByRole("checkbox", { name: /J'ai l'autorisation/ })).toHaveCount(0);
  const cards = page.getByRole("region", { name: "Derniers scans" }).locator("ul > li");
  await expect(cards).toHaveCount(5);
  await cards.first().getByRole("link").click();
  await expect(page).toHaveURL(/\/scans\/\d+$/);
});

test("un scan se construit en direct puis bascule sur le résultat", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Domaine ou URL à analyser").fill("live-demo.example.com");
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page).toHaveURL(/\/scans\/live\/[0-9a-f]+$/);
  await expect(page.getByRole("heading", { name: "Analyse de live-demo.example.com" })).toBeVisible();
  await expect(page.getByRole("progressbar", { name: "Avancement de l'analyse" })).toBeVisible();
  // Une seule barre de progression, le texte « n modules sur N » et le chronomètre en m:ss. N est le
  // nombre de modules du profil Complet, annoncé dès le départ : bien plus que les 18 historiques.
  await expect(page.getByRole("progressbar")).toHaveCount(1);
  const counter = page.getByText(/^\d{1,3} modules sur \d{2,3}$/);
  await expect(counter).toBeVisible();
  const total = Number(/sur (\d+)$/.exec((await counter.textContent()) ?? "")?.[1]);
  expect(total).toBeGreaterThan(18);
  await expect(page.getByRole("progressbar")).toHaveAttribute("max", String(total));
  await expect(page.getByText(/^\d{1,2}:\d{2}$/)).toBeVisible();
  await expect(page).toHaveURL(/\/scans\/\d+$/, { timeout: 20_000 });
  // La note en grand : seule image dont le nom parle de couverture (les pastilles de note n'en parlent pas).
  await expect(page.getByRole("img", { name: /couverture/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: "À corriger" })).toBeVisible();
  await expect(page.getByRole("link", { name: /^Réseau :/ })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: "Analyse incomplète" })).toBeVisible();
});

test("un scan peut être annulé en cours de route", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Domaine ou URL à analyser").fill("slow.example.com");
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByText(/^1 modules sur \d+$/)).toBeVisible({ timeout: 5_000 });
  // Le premier module terminé passe à « Mesuré », avec sa durée (le faux scanner en compte une par
  // seconde pour « slow. ») ; son nom dépend de l'ordre du plan, que ce test ne fige pas.
  await expect(page.locator('li[data-status="ok"]').first()).toContainText(/Mesuré.*\d+(,\d+)? s$/);
  await page.getByRole("button", { name: "Annuler" }).click();
  await expect(page.getByText("Analyse annulée")).toBeVisible();
  await expect(page.getByRole("button", { name: "Annuler" })).toHaveCount(0);
});

test("une panne du scanner est signalée avec une sortie", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Domaine ou URL à analyser").fill("boom.example.com");
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  const alert = page.getByRole("alert");
  await expect(alert).toContainText("L'analyse a échoué");
  await expect(alert.getByRole("button", { name: "Relancer" })).toBeVisible();
});

test("une cible trop courte ou invalide est refusée sans lancer de scan", async ({ page }) => {
  let launches = 0;
  page.on("request", (req) => {
    if (req.method() === "POST" && new URL(req.url()).pathname === "/api/scans") launches += 1;
  });
  await page.goto("/");
  const input = page.getByLabel("Domaine ou URL à analyser");

  // Trop courte : refusée par l'interface, sans appel à l'API.
  await input.fill("ab");
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByRole("alert")).toHaveText("Le domaine doit faire de 3 à 255 caractères.");
  expect(launches).toBe(0);

  // Longueur correcte mais syntaxe invalide : l'interface laisse passer, le serveur refuse (400).
  await input.fill("exa mple.com");
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByRole("alert")).toHaveText("Cible invalide : 'exa mple.com'");
  expect(launches).toBe(1);
  await expect(page).toHaveURL(/\/$/);
});
