import type { Page } from "@playwright/test";
import { expect, scanIdFor, test } from "./fixtures";

// « Comprendre et corriger » : les étapes numérotées, l'extrait à copier (variantes par plateforme en
// onglets) et le lien vers la documentation viennent du catalogue des modules (fix, fix_snippet,
// fix_ref de GET /api/modules). Le conseil de l'interface ne sert que de repli.
test.use({ permissions: ["clipboard-read", "clipboard-write"] });

const finding = (page: Page, message: string) =>
  page.getByRole("list", { name: "À corriger" }).getByRole("listitem").filter({ hasText: message });

// Le presse-papiers de Windows convertit les fins de ligne en CRLF : la comparaison se fait en LF.
const readClipboard = async (page: Page) => {
  const text = await page.evaluate(() => navigator.clipboard.readText());
  return text.split("\r\n").join("\n");
};

async function openFinding(page: Page, message: string) {
  const item = finding(page, message);
  await item.getByRole("button", { name: /Comprendre et corriger/ }).click();
  const fix = item.locator("dl > div").filter({ has: page.getByText("Comment corriger", { exact: true }) });
  await expect(fix).toBeVisible();
  return { item, fix };
}

test("avec le vrai catalogue : étapes numérotées, extrait par plateforme, copie du code seul, documentation", async ({ page, request }) => {
  const id = await scanIdFor(request, "shop.example.com");
  await page.goto(`/scans/${id}`);
  const { item, fix } = await openFinding(page, "En-tête HSTS absent");

  // Ce que c'est, pourquoi c'est important : les deux autres rubriques sont là aussi.
  await expect(item.getByText("Ce que c'est", { exact: true })).toBeVisible();
  await expect(item.getByText("Pourquoi c'est important", { exact: true })).toBeVisible();

  // Étapes du catalogue : une liste numérotée (<ol>), plusieurs étapes, pas le conseil de famille.
  const steps = fix.locator("ol > li");
  expect(await steps.count()).toBeGreaterThanOrEqual(3);
  await expect(fix.getByText("Ajoutez ou corrigez les en-têtes de sécurité et les réglages du serveur web")).toHaveCount(0);
  // La numérotation est bien visible (la remise à zéro globale des listes ne l'efface pas).
  expect(await fix.locator("ol").evaluate((list) => getComputedStyle(list).listStyleType)).toBe("decimal");
  // Du code en ligne dans les étapes, jamais l'accent grave du catalogue.
  await expect(fix.locator("ol code").first()).toBeVisible();
  expect(await fix.locator("ol").textContent()).not.toContain("`");

  // Extrait : onglets par plateforme, le premier sélectionné.
  const tabs = fix.getByRole("tablist", { name: "Variantes par plateforme" });
  await expect(tabs).toBeVisible();
  const labels = await tabs.getByRole("tab").allTextContents();
  expect(labels.length).toBeGreaterThanOrEqual(2);
  expect(labels).toContain("nginx");
  await expect(tabs.getByRole("tab").first()).toHaveAttribute("aria-selected", "true");
  const code = fix.getByRole("tabpanel").locator("pre");
  const firstCode = (await code.textContent()) ?? "";
  expect(firstCode.length).toBeGreaterThan(20);
  // L'en-tête « # nginx » du catalogue n'est pas du code : il ne s'affiche pas dans le bloc.
  expect(firstCode).not.toMatch(/^# /m);

  // Copier : le code affiché, tel quel.
  await fix.getByRole("button", { name: `Copier l'extrait ${labels[0]}` }).click();
  expect(await readClipboard(page)).toBe(firstCode);
  await expect(fix.getByRole("button", { name: `Copier l'extrait ${labels[0]}` })).toContainText("Copié");

  // Autre plateforme : autre code, bouton neuf, copie de ce code-là.
  await tabs.getByRole("tab", { name: labels[1] }).click();
  await expect(tabs.getByRole("tab", { name: labels[1] })).toHaveAttribute("aria-selected", "true");
  const secondCode = (await code.textContent()) ?? "";
  expect(secondCode).not.toBe(firstCode);
  const copySecond = fix.getByRole("button", { name: `Copier l'extrait ${labels[1]}` });
  await expect(copySecond).not.toContainText("Copié");
  await copySecond.click();
  expect(await readClipboard(page)).toBe(secondCode);

  // Les flèches du clavier parcourent les onglets.
  await tabs.getByRole("tab", { name: labels[1] }).focus();
  await page.keyboard.press("ArrowLeft");
  await expect(tabs.getByRole("tab", { name: labels[0] })).toHaveAttribute("aria-selected", "true");
  await expect(code).toHaveText(firstCode);

  // Documentation officielle : adresse https, nouvel onglet sans accès à la fenêtre d'origine.
  const link = fix.getByRole("link", { name: /Documentation officielle/ });
  await expect(link).toHaveAttribute("href", /^https:\/\/[^/]+\.[^/]+/);
  await expect(link).toHaveAttribute("target", "_blank");
  expect(await link.getAttribute("rel")).toContain("noopener");
  expect(await link.getAttribute("rel")).toContain("noreferrer");
});

test("catalogue maîtrisé : code en ligne, sans HTML interprété, lien http écarté, repli par module sans conseil", async ({ page, request }) => {
  const id = await scanIdFor(request, "shop.example.com");
  const hostile = "<img src=x onerror=alert(1)>";
  await page.route("**/api/modules**", async (route) => {
    const response = await route.fetch();
    const body = (await response.json()) as { modules: Array<Record<string, unknown>> };
    for (const module of body.modules) {
      if (module.name === "security_headers") {
        module.fix = `Ouvrez la configuration du serveur web.\nAjoutez \`Strict-Transport-Security: max-age=31536000\` sur les réponses HTTPS.\n${hostile}\nRelancez le scan.`;
        module.fix_snippet = `add_header Strict-Transport-Security "max-age=31536000" always;\nserver {\n  listen 443 ssl;\n}`;
        module.fix_ref = "http://example.com/pas-en-https";
      }
      if (module.name === "redirect_chain") {
        delete module.fix;
        delete module.fix_snippet;
        delete module.fix_ref;
      }
    }
    await route.fulfill({ response, json: body });
  });
  await page.goto(`/scans/${id}`);

  const { fix } = await openFinding(page, "En-tête HSTS absent");
  await expect(fix.locator("ol > li")).toHaveCount(4);
  await expect(fix.locator("ol > li").nth(1).locator("code")).toHaveText("Strict-Transport-Security: max-age=31536000");
  // Le texte hostile reste du texte : aucune image n'est créée, la chaîne est affichée telle quelle.
  await expect(fix.locator("img")).toHaveCount(0);
  await expect(fix.locator("ol > li").nth(2)).toHaveText(hostile);
  // Un seul extrait : pas d'onglets, un bloc de code et son bouton Copier, accolades gardées.
  await expect(fix.getByRole("tablist")).toHaveCount(0);
  await expect(fix.locator("pre")).toHaveText(`add_header Strict-Transport-Security "max-age=31536000" always;\nserver {\n  listen 443 ssl;\n}`);
  await fix.getByRole("button", { name: "Copier l'extrait" }).click();
  expect(await readClipboard(page)).toBe(`add_header Strict-Transport-Security "max-age=31536000" always;\nserver {\n  listen 443 ssl;\n}`);
  // Une adresse qui n'est pas en https n'est jamais un lien.
  await expect(fix.getByRole("link")).toHaveCount(0);

  // Un module dont le catalogue n'a pas de conseil : le conseil de l'interface reste en repli.
  const redirect = await openFinding(page, "HTTP ne redirige pas vers HTTPS");
  await expect(redirect.fix.locator("ol")).toHaveCount(0);
  await expect(redirect.fix.locator("pre")).toHaveCount(0);
  await expect(redirect.fix.getByRole("link")).toHaveCount(0);
  await expect(redirect.fix).toContainText(/\S{4,}/);
  expect((await redirect.fix.textContent())?.length).toBeGreaterThan("Comment corriger".length + 30);
});

test("le conseil est dans la langue de l'interface (catalogue demandé en anglais)", async ({ page, request }) => {
  const id = await scanIdFor(request, "shop.example.com");
  await page.addInitScript(() => window.localStorage.setItem("domainrecon.lang", "en"));
  const catalog = page.waitForResponse((response) => response.url().includes("/api/modules") && response.url().includes("lang=en"));
  await page.goto(`/scans/${id}`);
  await catalog;
  const item = page
    .getByRole("list", { name: "To fix" })
    .getByRole("listitem")
    .filter({ hasText: /HSTS/ })
    .first();
  await item.getByRole("button", { name: /Understand and fix/ }).click();
  const fix = item.locator("dl > div").filter({ has: page.getByText("How to fix it", { exact: true }) });
  await expect(fix.locator("ol > li").first()).toBeVisible();
  await expect(fix.getByRole("tablist", { name: "Variants by platform" })).toBeVisible();
  await expect(fix.getByRole("link", { name: /Official documentation/ })).toBeVisible();
  await expect(fix.getByRole("button", { name: /^Copy .* snippet$/ })).toBeVisible();
});

test("dans une famille aussi : le conseil du catalogue est servi sous chaque constat", async ({ page, request }) => {
  const id = await scanIdFor(request, "shop.example.com");
  await page.goto(`/scans/${id}/web/security_headers`);
  const item = page.getByRole("listitem").filter({ hasText: "En-tête HSTS absent" }).first();
  await item.getByRole("button", { name: /Comprendre et corriger/ }).click();
  await expect(item.locator("ol > li").first()).toBeVisible();
  await expect(item.getByRole("tablist", { name: "Variantes par plateforme" })).toBeVisible();
});

test("téléphone (360 px) : le conseil ouvert, avec ses longues lignes de code, ne fait pas déborder la page", async ({ page, request }) => {
  await page.setViewportSize({ width: 360, height: 800 });
  const id = await scanIdFor(request, "shop.example.com");
  await page.goto(`/scans/${id}`);
  const { fix } = await openFinding(page, "En-tête HSTS absent");
  await expect(fix.getByRole("tablist")).toBeVisible();
  await expect(fix.locator("pre")).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  // Le bloc de code défile dans son cadre, au lieu d'élargir la page.
  const scrolls = await fix.locator("pre").evaluate((element) => element.scrollWidth > element.clientWidth);
  expect(scrolls).toBe(true);
  // Le bouton Copier reste dans la largeur de l'écran, atteignable.
  const copy = fix.getByRole("button", { name: /^Copier l'extrait/ });
  await copy.scrollIntoViewIfNeeded();
  const box = await copy.boundingBox();
  expect(box).not.toBeNull();
  expect(box?.x).toBeGreaterThanOrEqual(0);
  expect((box?.x ?? 0) + (box?.width ?? 0)).toBeLessThanOrEqual(360);
  await expect(copy).toBeInViewport();
});
