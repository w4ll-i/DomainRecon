import { expect, scanIdFor, test } from "./fixtures";

// La langue se règle à un seul endroit : l'écran Réglages.
test("changer de langue traduit l'interface, recharge les données et se mémorise", async ({ page, request }) => {
  const id = await scanIdFor(request, "shop.example.com");
  await page.goto(`/scans/${id}`);
  // Le nom du repère de navigation est traduit lui aussi (« Navigation principale » / « Main navigation »).
  const menu = page.getByRole("navigation", { name: "Navigation principale" });
  const menuEn = page.getByRole("navigation", { name: "Main navigation" });
  await expect(menu.getByRole("link", { name: "Scanner" })).toBeVisible();
  await expect(menuEn).toHaveCount(0);
  await expect(page.getByRole("button", { name: "EN", exact: true })).toHaveCount(0);

  await menu.getByRole("link", { name: "Réglages" }).click();
  const reloaded = page.waitForRequest((req) => req.url().includes("lang=en"));
  await page.getByRole("radio", { name: "English" }).check();
  await reloaded;
  await expect(menuEn.getByRole("link", { name: "Scan", exact: true })).toBeVisible();
  await expect(menuEn.getByRole("link", { name: "Settings" })).toBeVisible();
  await expect(menu).toHaveCount(0);
  await expect(page.locator("html")).toHaveAttribute("lang", "en");

  await page.goto(`/scans/${id}`);
  await expect(page.getByRole("heading", { name: "To fix" })).toBeVisible();
  await expect(page.getByRole("link", { name: /^Web:/ })).toBeVisible();
  await page.reload();
  await expect(menuEn.getByRole("link", { name: "Scan", exact: true })).toBeVisible();

  await menuEn.getByRole("link", { name: "Settings" }).click();
  await page.getByRole("radio", { name: "Français" }).check();
  await expect(menu.getByRole("link", { name: "Scanner" })).toBeVisible();
  await expect(menuEn).toHaveCount(0);
});

test("la langue choisie traduit aussi les écrans chargés à la demande et le catalogue des modules", async ({ page, request }) => {
  await page.addInitScript(() => window.localStorage.setItem("domainrecon.lang", "en"));
  const modules = page.waitForResponse((response) => response.url().includes("/api/modules") && response.url().includes("lang=en"));
  await page.goto("/monitoring");
  await expect(page.getByRole("heading", { level: 1, name: "Monitoring" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Watches" })).toBeVisible();
  type Catalog = { modules: Array<{ name: string; help: { title: string }; fix?: string; fix_ref?: string }> };
  const catalog = (await (await modules).json()) as Catalog;
  // Le catalogue arrive dans la langue demandée : titres et conseils de correction (chaque module en a un).
  const headers = catalog.modules.find((module) => module.name === "security_headers");
  expect(headers?.help.title).toBe("Security headers");
  for (const module of catalog.modules) expect(module.fix, `fix de ${module.name}`).toBeTruthy();
  // Le conseil anglais n'est pas le français servi en repli.
  const french = (await (await request.get("/api/modules?lang=fr")).json()) as Catalog;
  const headersFr = french.modules.find((module) => module.name === "security_headers");
  expect(headersFr?.fix).toBeTruthy();
  expect(headers?.fix).not.toBe(headersFr?.fix);
  expect(headers?.fix_ref).toMatch(/^https:\/\//);
});
