import { expect, scanIdFor, test } from "./fixtures";

// Coquille « Monochrome pro » dans un vrai navigateur, sous la CSP stricte du serveur : thème,
// en-tête collant plat, palette de commandes Ctrl+K, menu latéral. La garde de fixtures.ts fait échouer
// tout test qui provoque une violation de CSP ou un console.error.

// Playwright émule par défaut un système « clair » ; sans choix mémorisé, l'interface suit
// le système. Ces scénarios partent du thème sombre, le défaut de l'interface.
test.use({ colorScheme: "dark" });

test("bascule de thème : jetons clairs appliqués, choix mémorisé au rechargement", async ({ page }) => {
  await page.goto("/history");
  const html = page.locator("html");
  await expect(html).not.toHaveAttribute("data-theme", "light");
  const background = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  // Thème sombre : --bg #0a0a0a.
  expect(await background()).toBe("rgb(10, 10, 10)");

  await page.getByRole("button", { name: "Passer au thème clair" }).click();
  await expect(html).toHaveAttribute("data-theme", "light");
  // Thème clair : --bg #ffffff.
  expect(await background()).toBe("rgb(255, 255, 255)");

  await page.reload();
  await expect(html).toHaveAttribute("data-theme", "light");
  await page.getByRole("button", { name: "Passer au thème sombre" }).click();
  await expect(html).toHaveAttribute("data-theme", "dark");
  await page.reload();
  await expect(html).toHaveAttribute("data-theme", "dark");
});

test("premier lancement : le thème suit la préférence du système, sans choix mémorisé", async ({ browser }) => {
  const context = await browser.newContext({ colorScheme: "light", locale: "fr-FR" });
  const page = await context.newPage();
  await page.goto("/");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await context.close();
});

test("l'en-tête reste collé en haut, plein et sans flou", async ({ page }) => {
  await page.goto("/history");
  const header = page.locator("header.app-header");
  await expect(header).toBeVisible();
  const style = await header.evaluate((element) => {
    const computed = getComputedStyle(element);
    return { position: computed.position, filter: computed.backdropFilter, background: computed.backgroundColor };
  });
  expect(style.position).toBe("sticky");
  expect(style.filter).toBe("none");
  expect(style.background).toBe("rgb(10, 10, 10)");
});

test("menu latéral : huit écrans, chacun ouvre son vrai écran (plus aucune page « bientôt »)", async ({ page }) => {
  await page.goto("/history");
  const nav = page.getByRole("navigation", { name: "Navigation principale" });
  await expect(nav.getByRole("link")).toHaveText([
    "Scanner",
    "Tableau de bord",
    "Historique",
    "Lot",
    "Comparer",
    "Surveillance",
    "Aide",
    "Réglages",
  ]);
  const screens: Array<[string, RegExp, string]> = [
    ["Scanner", /\/$/, "Analyse de domaine"],
    ["Tableau de bord", /\/dashboard$/, "Tableau de bord"],
    ["Historique", /\/history$/, "Historique"],
    ["Lot", /\/batch$/, "Scan en lot"],
    ["Comparer", /\/compare$/, "Comparer deux scans"],
    ["Surveillance", /\/monitoring$/, "Surveillance"],
    ["Aide", /\/help$/, "Aide"],
    ["Réglages", /\/settings$/, "Réglages"],
  ];
  for (const [label, url, title] of screens) {
    await nav.getByRole("link", { name: label, exact: true }).click();
    await expect(page).toHaveURL(url);
    await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
    await expect(nav.getByRole("link", { name: label, exact: true })).toHaveAttribute("aria-current", "page");
    await expect(page.getByText("Bientôt disponible")).toHaveCount(0);
    // Le focus passe au contenu à chaque changement d'écran (sauf le champ du nouveau scan, qui le garde).
    if (label !== "Scanner") await expect(page.getByRole("main")).toBeFocused();
  }
});

test("palette de commandes : Ctrl+K, aller à une page, scanner un domaine, rouvrir un scan récent", async ({ page }) => {
  await page.goto("/settings");
  await page.keyboard.press("Control+k");
  // Le nom accessible départage la palette des autres listes déroulantes de l'écran (SMTP des Réglages).
  const input = page.getByRole("combobox", { name: /Scanner un domaine/ });
  await expect(input).toBeFocused();
  await input.fill("hist");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/history$/);

  await page.keyboard.press("Control+k");
  await expect(page.getByRole("option", { name: /^Résultat de / }).first()).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);

  await page.keyboard.press("Control+k");
  await page.getByRole("combobox", { name: /Scanner un domaine/ }).fill("quick-demo.example.com");
  await expect(page.getByRole("listbox", { name: "Résultats" }).getByRole("option").first()).toHaveText("Scanner quick-demo.example.com");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/scans\/live\/[0-9a-f]+$/);
  await expect(page.getByRole("heading", { name: "Analyse de quick-demo.example.com" })).toBeVisible();
});

test("état du serveur lu par une icône colorée et par un texte", async ({ page }) => {
  await page.goto("/settings");
  const status = page.getByRole("status").filter({ hasText: "Serveur en ligne" });
  await expect(status).toBeVisible();
  await expect(status).toHaveAttribute("data-state", "online");
  // L'icône est colorée par le jeton de succès (--success monochrome pro), pas seulement posée.
  const color = await status.locator("svg").evaluate((icon) => getComputedStyle(icon).color);
  expect(color).toBe("rgb(70, 167, 88)");
});

test("aucun écran ne déborde horizontalement sur téléphone et tablette", async ({ page, request }) => {
  const id = await scanIdFor(request, "shop.example.com");
  // Les textes masqués en position absolue (tableau du radar, en-têtes de colonnes d'actions,
  // menu) ne doivent pas élargir la page : ils restent dans leur conteneur.
  const screens: Array<[number, string]> = [
    [360, "/"],
    [360, `/scans/${id}`],
    [390, "/settings"],
    [768, "/history"],
    [768, `/scans/${id}/web`],
    // Les écrans ajoutés depuis : tableau de bord, comparaison, lot, surveillance, aide.
    [360, "/dashboard"],
    [360, "/compare?domain=example.com"],
    [360, "/batch"],
    [360, "/monitoring"],
    [360, "/monitoring?tab=notifications"],
    [360, "/help"],
    [768, "/dashboard"],
    [768, "/monitoring"],
  ];
  for (const [width, path] of screens) {
    await page.setViewportSize({ width, height: 800 });
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `${path} à ${width} px`).toBeLessThanOrEqual(0);
  }
});
