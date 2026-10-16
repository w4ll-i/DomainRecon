import { expect, ONBOARDING_KEY, test } from "./fixtures";
import type { Locator, Page } from "@playwright/test";

// Premier lancement : un court accueil propose la visite guidée, qui surligne les vrais éléments
// de l'interface un par un ; elle est mémorisée une fois faite ou écartée. Les autres scénarios
// partent d'un navigateur qui l'a déjà vue (fixtures.ts) ; ici, un premier lancement.

const tour = (page: Page) => page.getByTestId("guided-tour").getByRole("dialog");
// Le contenu de la bulle (la flèche, elle, dépasse volontairement du bord).

// La boîte tient entièrement dans la fenêtre du navigateur, une fois le défilement doux vers
// l'élément terminé (la bulle suit l'élément pendant qu'il défile).
async function expectInViewport(page: Page, locator: Locator) {
  await expect(async () => {
    const box = await locator.boundingBox();
    const view = page.viewportSize();
    expect(box && view).toBeTruthy();
    if (!box || !view) return;
    expect(box.x).toBeGreaterThanOrEqual(0);
    expect(box.y).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width).toBeLessThanOrEqual(view.width + 0.5);
    expect(box.y + box.height).toBeLessThanOrEqual(view.height + 0.5);
  }).toPass({ timeout: 5_000 });
}

// Aucun contenu ne déborde du cadre : ni défilement horizontal, ni enfant hors du panneau.
async function expectNoOverflow(panel: Locator) {
  const overflow = await panel.evaluate((element) => {
    const frame = element.getBoundingClientRect();
    const outside = [...element.querySelectorAll("*")]
      .filter((child) => {
        const rect = child.getBoundingClientRect();
        return rect.width > 0 && (rect.left < frame.left - 0.5 || rect.right > frame.right + 0.5);
      })
      .map((child) => child.textContent?.slice(0, 40) ?? child.tagName);
    return { scroll: element.scrollWidth - element.clientWidth, outside };
  });
  expect(overflow).toEqual({ scroll: 0, outside: [] });
}

test.describe("premier lancement", () => {
  test.use({ onboarding: "first-run" });

  test("accueil, visite des vrais éléments jusqu'au résultat, « Terminer » : rien ne revient au rechargement", async ({ page }) => {
    await page.goto("/");
    const welcome = page.getByRole("dialog", { name: "Bienvenue dans DomainRecon" });
    await expect(welcome).toBeVisible();
    await expect(welcome.getByText(/Usage autorisé uniquement/)).toBeVisible();
    await expect(welcome.getByRole("button", { name: "Commencer la visite" })).toBeFocused();
    await expectNoOverflow(welcome);
    await welcome.getByRole("button", { name: "Commencer la visite" }).click();

    const bubble = tour(page);
    await expect(bubble).toHaveAccessibleName("Recherche rapide");
    await expect(bubble.getByText(/^Étape 1 sur \d+$/)).toBeVisible();
    await expect(bubble.getByRole("button", { name: "Précédent" })).toHaveCount(0);
    await expect(bubble.getByRole("button", { name: "Suivant" })).toBeFocused();

    const seen: string[] = [];
    for (let step = 0; step < 12; step += 1) {
      await expect(bubble).toHaveAttribute("data-placed", "true");
      const name = (await bubble.getByRole("heading", { level: 2 }).textContent()) ?? "";
      seen.push(name);
      await expectInViewport(page, bubble);
      await expectNoOverflow(bubble.locator(":scope > div"));
      const finish = bubble.getByRole("button", { name: "Terminer" });
      if (await finish.isVisible()) break;
      await bubble.getByRole("button", { name: "Suivant" }).click();
      await expect(bubble.getByRole("heading", { level: 2 })).not.toHaveText(name);
    }
    // Base seedée : un scan existe, la visite ouvre son résultat.
    expect(seen).toEqual([
      "Recherche rapide",
      "Domaine à analyser",
      "Profil de scan",
      "Menu de navigation",
      "Réglages",
      "Aide et glossaire",
      "Note de sécurité",
      "Constats",
      "Familles de contrôles",
      "Actions et export",
    ]);
    await expect(page).toHaveURL(/\/scans\/\d+$/);
    await expect(bubble.getByText("Étape 10 sur 10")).toBeVisible();

    await bubble.getByRole("button", { name: "Terminer" }).click();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(page.getByTestId("guided-tour")).toHaveCount(0);
    expect(await page.evaluate((key) => window.localStorage.getItem(key), ONBOARDING_KEY)).toBe("1");

    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1, name: "Analyse de domaine" })).toBeVisible();
    await page.reload();
    await expect(page.getByRole("heading", { level: 1, name: "Analyse de domaine" })).toBeVisible();
    await expect(page.getByRole("dialog")).toHaveCount(0);
  });

  test("la découpe du voile entoure l'élément expliqué, la bulle ne le recouvre pas", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Commencer la visite" }).click();
    const bubble = tour(page);
    for (const [name, target] of [
      ["Recherche rapide", page.locator("[data-tour='palette']")],
      ["Domaine à analyser", page.locator("[data-tour='domain']")],
      ["Profil de scan", page.locator("[data-tour='profiles']")],
      ["Menu de navigation", page.locator("[data-tour='nav']")],
    ] as const) {
      await expect(bubble).toHaveAccessibleName(name);
      await expect(bubble).toHaveAttribute("data-placed", "true");
      const ring = page.getByTestId("guided-tour").locator("svg > rect:last-of-type");
      const [ringBox, targetBox, bubbleBox] = await Promise.all([ring.boundingBox(), target.boundingBox(), bubble.boundingBox()]);
      if (!ringBox || !targetBox || !bubbleBox) throw new Error(`boîtes manquantes : ${name}`);
      // La découpe contient l'élément (6 px de marge, ramenée dans l'écran).
      expect(ringBox.x).toBeLessThanOrEqual(targetBox.x + 1);
      expect(ringBox.y).toBeLessThanOrEqual(targetBox.y + 1);
      expect(ringBox.x + ringBox.width).toBeGreaterThanOrEqual(Math.min(targetBox.x + targetBox.width, 1280) - 1);
      // Bulle et élément ne se chevauchent pas.
      const apart =
        bubbleBox.x + bubbleBox.width <= targetBox.x ||
        bubbleBox.x >= targetBox.x + targetBox.width ||
        bubbleBox.y + bubbleBox.height <= targetBox.y ||
        bubbleBox.y >= targetBox.y + targetBox.height;
      expect(apart, name).toBe(true);
      await page.keyboard.press("ArrowRight");
    }
  });

  test("« Plus tard » et Échap écartent l'accueil et le marquent comme vu", async ({ page }) => {
    await page.goto("/history");
    await page.getByRole("dialog", { name: "Bienvenue dans DomainRecon" }).getByRole("button", { name: "Plus tard" }).click();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    expect(await page.evaluate((key) => window.localStorage.getItem(key), ONBOARDING_KEY)).toBe("1");

    // Échap : même effet sur un autre navigateur vierge.
    await page.evaluate((key) => window.localStorage.removeItem(key), ONBOARDING_KEY);
    await page.reload();
    await expect(page.getByRole("dialog", { name: "Bienvenue dans DomainRecon" })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);
    expect(await page.evaluate((key) => window.localStorage.getItem(key), ONBOARDING_KEY)).toBe("1");
  });

  test("clavier : flèches, focus piégé dans la bulle, Échap quitte et marque la visite faite", async ({ page }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Commencer la visite" }).click();
    const bubble = tour(page);
    // La visite ouvre l'écran de scan ; le champ domaine (autoFocus) ne lui prend pas le focus.
    await expect(page).toHaveURL(/\/$/);
    await expect(bubble).toHaveAccessibleName("Recherche rapide");
    await expect(bubble.getByRole("button", { name: "Suivant" })).toBeFocused();
    await page.keyboard.press("ArrowRight");
    await expect(bubble).toHaveAccessibleName("Domaine à analyser");
    await page.keyboard.press("ArrowLeft");
    await expect(bubble).toHaveAccessibleName("Recherche rapide");
    await page.keyboard.press("Enter");
    await expect(bubble).toHaveAccessibleName("Domaine à analyser");
    for (let i = 0; i < 6; i += 1) {
      await page.keyboard.press("Tab");
      expect(await bubble.evaluate((element) => element.contains(document.activeElement))).toBe(true);
    }
    // Ctrl+K n'ouvre pas la palette par-dessus la visite.
    await page.keyboard.press("Control+k");
    await expect(page.getByRole("combobox")).toHaveCount(0);
    // Un clic sur le voile ne ferme pas la visite et ne lui prend pas le focus.
    await page.mouse.click(1200, 790);
    await expect(bubble).toBeVisible();
    expect(await bubble.evaluate((element) => element.contains(document.activeElement))).toBe(true);
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);
    expect(await page.evaluate((key) => window.localStorage.getItem(key), ONBOARDING_KEY)).toBe("1");
  });

  test("téléphone : accueil et bulle tiennent dans l'écran, sans débordement", async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 700 });
    await page.goto("/");
    const welcome = page.getByRole("dialog", { name: "Bienvenue dans DomainRecon" });
    await expectInViewport(page, welcome);
    await expectNoOverflow(welcome);
    await welcome.getByRole("button", { name: "Commencer la visite" }).click();
    const bubble = tour(page);
    for (let step = 0; step < 4; step += 1) {
      await expect(bubble).toHaveAttribute("data-placed", "true");
      await expectInViewport(page, bubble);
      await expectNoOverflow(bubble.locator(":scope > div"));
      await page.keyboard.press("ArrowRight");
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBe(0);
  });
});

test("par défaut, les scénarios partent d'un navigateur qui a déjà vu l'accueil", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "Analyse de domaine" })).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  // Le champ du domaine a le focus : rien ne le lui a pris.
  await expect(page.getByLabel("Domaine ou URL à analyser")).toBeFocused();
});

test("l'écran Aide relance la visite guidée", async ({ page }) => {
  await page.goto("/help");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.getByRole("button", { name: "Relancer la visite guidée" }).click();
  const bubble = tour(page);
  await expect(bubble).toHaveAccessibleName("Recherche rapide");
  await expect(bubble.getByText(/^Étape 1 sur \d+$/)).toBeVisible();
  // L'accueil ne revient pas : la visite démarre directement, sur l'écran de scan.
  await expect(page.getByRole("dialog", { name: "Bienvenue dans DomainRecon" })).toHaveCount(0);
  await expect(page).toHaveURL(/\/$/);
  await bubble.getByRole("button", { name: "Passer" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("la palette de commandes (Ctrl+K) relance la visite guidée", async ({ page }) => {
  await page.goto("/history");
  await expect(page.getByRole("heading", { level: 1, name: "Historique" })).toBeVisible();
  await page.keyboard.press("Control+k");
  await page.getByRole("combobox", { name: /Scanner un domaine/ }).fill("visite");
  await expect(page.getByRole("option", { name: "Relancer la visite guidée" })).toBeVisible();
  await page.keyboard.press("Enter");
  const bubble = tour(page);
  await expect(bubble).toHaveAccessibleName("Recherche rapide");
  await expect(bubble.getByRole("button", { name: "Suivant" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test.describe("premier lancement, étape « Note »", () => {
  test.use({ onboarding: "first-run", viewport: { width: 1366, height: 768 } });

  test("l'élément surligné contient la couverture dont parle la bulle, et la bulle ne le recouvre pas", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Commencer la visite" }).click();
    const bubble = tour(page);
    for (let step = 0; step < 12; step += 1) {
      await expect(bubble).toHaveAttribute("data-placed", "true");
      if ((await bubble.getByRole("heading", { level: 2 }).textContent()) === "Note de sécurité") break;
      const name = (await bubble.getByRole("heading", { level: 2 }).textContent()) ?? "";
      await bubble.getByRole("button", { name: "Suivant" }).click();
      await expect(bubble.getByRole("heading", { level: 2 })).not.toHaveText(name);
    }
    await expect(bubble).toHaveAccessibleName("Note de sécurité");
    const target = page.locator("[data-tour='result-score']");
    await expect(target).toContainText("Couverture");
    await expect(async () => {
      const [targetBox, bubbleBox] = await Promise.all([target.boundingBox(), bubble.boundingBox()]);
      if (!targetBox || !bubbleBox) throw new Error("boîtes manquantes");
      const apart =
        bubbleBox.x + bubbleBox.width <= targetBox.x ||
        bubbleBox.x >= targetBox.x + targetBox.width ||
        bubbleBox.y + bubbleBox.height <= targetBox.y ||
        bubbleBox.y >= targetBox.y + targetBox.height;
      expect(apart).toBe(true);
    }).toPass({ timeout: 5_000 });
  });
});
