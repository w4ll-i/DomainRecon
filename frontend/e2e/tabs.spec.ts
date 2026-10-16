import type { Page } from "@playwright/test";
import { expect, scanIdFor, test } from "./fixtures";

// Rangée d'onglets des modules (une trentaine pour la famille Web) : aucune barre de
// défilement native, noms entiers, onglet actif visible, menu « Tous » complet ; en
// sombre et en clair, sur grand écran et sur mobile.

// Mesures de la rangée dans la vraie mise en page de Chromium.
async function measureRow(page: Page) {
  return page.getByRole("tablist", { name: "Modules de la famille Web" }).evaluate((list) => {
    const style = getComputedStyle(list);
    const row = list.getBoundingClientRect();
    const selected = list.querySelector<HTMLElement>("[aria-selected=true]");
    const box = selected?.getBoundingClientRect();
    // Tout élément de la page qui défile et garde sa barre native.
    const scrollbars = [...document.querySelectorAll<HTMLElement>("main *")].filter((element) => {
      const css = getComputedStyle(element);
      const scrollsX = /auto|scroll/.test(css.overflowX) && element.scrollWidth > element.clientWidth + 1;
      const scrollsY = /auto|scroll/.test(css.overflowY) && element.scrollHeight > element.clientHeight + 1;
      return (scrollsX || scrollsY) && css.scrollbarWidth !== "none" && element.closest("[role=tablist], nav") !== null;
    }).length;
    return {
      overflowing: list.scrollWidth > list.clientWidth,
      scrollbarWidth: style.scrollbarWidth,
      // Ni barre verticale : la rangée ne défile pas en hauteur.
      verticalScroll: list.scrollHeight - list.clientHeight,
      // Aucun onglet tronqué : chaque libellé tient dans sa boîte.
      truncated: [...list.querySelectorAll<HTMLElement>("[role=tab]")].filter((tab) => tab.scrollWidth > tab.clientWidth + 1).length,
      activeVisible: box ? box.left >= row.left - 1 && box.right <= row.right + 1 : false,
      // Pastille centrée sur la ligne du libellé (à 1 px près).
      badgeOffset: (() => {
        const label = selected?.firstElementChild;
        const badge = selected?.lastElementChild;
        if (!label || !badge || label === badge) return -1;
        const a = label.getBoundingClientRect();
        const b = badge.getBoundingClientRect();
        return Math.abs(a.top + a.height / 2 - (b.top + b.height / 2));
      })(),
      scrollbars,
      pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    };
  });
}

for (const colorScheme of ["dark", "light"] as const) {
  for (const [device, viewport] of [
    ["bureau", { width: 1366, height: 768 }],
    ["mobile", { width: 390, height: 844 }],
  ] as const) {
    test.describe(`onglets des modules, thème ${colorScheme}, ${device}`, () => {
      test.use({ colorScheme, viewport });

      test("défilement sans barre native, noms entiers, onglet actif ramené à l'écran", async ({ page, request }) => {
        await page.addInitScript((theme) => {
          try {
            window.localStorage.setItem("domainrecon.theme", theme);
          } catch {
            // Stockage indisponible : le thème suit le système.
          }
        }, colorScheme);
        const id = await scanIdFor(request, "shop.example.com");
        // Lien profond vers un onglet loin dans la rangée.
        await page.goto(`/scans/${id}/web/waf`);
        const tabs = page.getByRole("tablist", { name: "Modules de la famille Web" });
        await expect(tabs.getByRole("tab", { selected: true })).toHaveText("WAF / CDN");
        await expect
          .poll(async () => (await measureRow(page)).activeVisible, { message: "onglet actif visible" })
          .toBe(true);
        const row = await measureRow(page);
        expect(row.overflowing).toBe(true);
        expect(row.scrollbarWidth).toBe("none");
        expect(row.verticalScroll).toBeLessThanOrEqual(0);
        expect(row.truncated).toBe(0);
        expect(row.scrollbars).toBe(0);
        expect(row.pageOverflow).toBeLessThanOrEqual(0);

        // Les flèches du clavier gardent l'onglet choisi dans la partie visible.
        await tabs.getByRole("tab", { selected: true }).focus();
        await page.keyboard.press("End");
        await expect(tabs.getByRole("tab", { selected: true })).toBeFocused();
        await expect.poll(async () => (await measureRow(page)).activeVisible).toBe(true);
        await page.keyboard.press("Home");
        await expect(tabs.getByRole("tab", { selected: true })).toHaveText(/^En-têtes de sécurité/);
        await expect.poll(async () => (await measureRow(page)).activeVisible).toBe(true);
        // « En-têtes de sécurité » porte une pastille de constats (-1 : pas de pastille).
        const offset = (await measureRow(page)).badgeOffset;
        expect(offset).toBeGreaterThanOrEqual(0);
        expect(offset).toBeLessThanOrEqual(1);
      });

      test("menu « Tous » : chaque module en toutes lettres, le choix active son onglet", async ({ page, request }) => {
        const id = await scanIdFor(request, "shop.example.com");
        await page.goto(`/scans/${id}/web/cors`);
        const tabs = page.getByRole("tablist", { name: "Modules de la famille Web" });
        await expect(tabs.getByRole("tab", { selected: true })).toHaveText(/^CORS/);
        const count = await tabs.getByRole("tab").count();
        expect(count).toBeGreaterThan(20);
        const trigger = page.getByRole("button", { name: `Tous les onglets ${count}` });
        await trigger.click();
        const menu = page.getByRole("menu", { name: "Tous les onglets : Modules de la famille Web" });
        await expect(menu.getByRole("menuitemradio")).toHaveCount(count);
        await expect(menu.getByRole("menuitemradio", { checked: true })).toHaveText(/^CORS/);
        // Le menu tient dans la fenêtre, en largeur.
        const box = await menu.boundingBox();
        expect(box && box.x >= 0 && box.x + box.width <= viewport.width).toBe(true);
        await menu.getByRole("menuitemradio", { name: /^WAF \/ CDN/ }).click();
        await expect(page).toHaveURL(new RegExp(`/scans/${id}/web/waf$`));
        await expect(menu).toHaveCount(0);
        await expect(tabs.getByRole("tab", { selected: true })).toBeFocused();
        await expect.poll(async () => (await measureRow(page)).activeVisible).toBe(true);
      });
    });
  }
}

test("familles du scan : les pastilles passent à la ligne, sans barre de défilement", async ({ page, request }) => {
  const id = await scanIdFor(request, "shop.example.com");
  for (const width of [1366, 390]) {
    await page.setViewportSize({ width, height: 800 });
    await page.goto(`/scans/${id}/web`);
    const nav = page.getByRole("navigation", { name: "Familles du scan" });
    await expect(nav.getByRole("link")).toHaveCount(8);
    const scrolls = await nav.evaluate((element) => {
      const list = element.querySelector("ul") as HTMLElement;
      return [element, list].some((node) => node.scrollWidth > node.clientWidth + 1);
    });
    expect(scrolls, `à ${width} px`).toBe(false);
    // Chaque famille est visible en entier dans la fenêtre.
    for (const link of await nav.getByRole("link").all()) {
      const box = await link.boundingBox();
      expect(box && box.x >= 0 && box.x + box.width <= width).toBe(true);
    }
  }
});
