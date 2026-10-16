import { expect, scanIdFor, test } from "./fixtures";

test("résultat puis familles : constats, carte réseau, carte du monde embarquée, WHOIS", async ({ page, request }) => {
  const id = await scanIdFor(request, "shop.example.com");
  await page.goto(`/scans/${id}`);
  await expect(page.getByRole("heading", { level: 1, name: "shop.example.com" })).toBeVisible();
  const findings = page.getByRole("list", { name: "À corriger" });
  await expect(findings.getByRole("listitem").first()).toBeVisible();

  await page.getByRole("link", { name: /^DNS & sous-domaines :/ }).click();
  await expect(page).toHaveURL(new RegExp(`/scans/${id}/dns$`));
  await expect(page.getByRole("img", { name: /Carte réseau de shop\.example\.com/ })).toBeVisible();
  await expect(page.locator("canvas").first()).toBeVisible();

  const families = page.getByRole("navigation", { name: "Familles du scan" });
  // Le nom du lien porte l'état de la famille : « Réseau (Critique) ».
  await families.getByRole("link", { name: /^Réseau \(/ }).click();
  // Un onglet par module : la localisation (carte) ouvre la famille, les ports ont le leur.
  await expect(page.getByRole("img", { name: /^Carte de localisation/ })).toBeVisible();
  await page.getByRole("tab", { name: /^Ports ouverts/ }).click();
  await expect(page).toHaveURL(new RegExp(`/scans/${id}/network/open_ports$`));
  // Le numéro seul : le constat « Port 3306 (MySQL) exposé » contient aussi « 3306 ».
  await expect(page.getByText("3306", { exact: true })).toBeVisible();

  await families.getByRole("link", { name: /^Identité \(/ }).click();
  await expect(page.getByRole("heading", { name: "WHOIS" })).toBeVisible();
});

test("onglets d'une famille : lien profond, flèches du clavier et rechargement", async ({ page, request }) => {
  const id = await scanIdFor(request, "shop.example.com");
  await page.goto(`/scans/${id}/web/cors`);
  const tabs = page.getByRole("tablist", { name: "Modules de la famille Web" });
  await expect(tabs.getByRole("tab", { selected: true })).toContainText("CORS");
  // Un seul module à la fois.
  await expect(page.getByRole("heading", { name: "CORS" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "En-têtes de sécurité" })).toHaveCount(0);

  // Les flèches changent d'onglet et d'adresse, le focus reste sur l'onglet.
  await tabs.getByRole("tab", { selected: true }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(page).toHaveURL(new RegExp(`/scans/${id}/web/redirect_chain$`));
  await expect(page.getByRole("heading", { name: "Redirections" })).toBeVisible();
  await expect(tabs.getByRole("tab", { name: /^Redirections/ })).toBeFocused();

  await page.reload();
  await expect(tabs.getByRole("tab", { selected: true })).toContainText("Redirections");
  await expect(page.getByRole("heading", { name: "Redirections" })).toBeVisible();
});

test("identité : capture d'écran servie avec la page, tags enregistrés (un onglet chacun)", async ({ page, request }) => {
  const id = await scanIdFor(request, "example.com");
  await page.goto(`/scans/${id}/identity/screenshot`);
  await expect(page.getByRole("img", { name: "Capture d'écran de example.com" })).toBeVisible();
  // Les tags et les notes ont leur onglet ; le lien profond survit aux rechargements ci-dessous.
  await page.getByRole("tab", { name: "Notes et tags" }).click();
  await expect(page).toHaveURL(new RegExp(`/scans/${id}/identity/notes$`));
  // Tag unique et retiré en fin de test : rejouable sur un serveur réutilisé.
  const tag = `e2e-${Date.now().toString(36)}`;
  const remove = page.getByRole("button", { name: `Retirer le tag ${tag}` });
  await page.getByPlaceholder("Ajouter un tag…").fill(tag);
  await page.getByRole("button", { name: "Ajouter" }).click();
  await expect(remove).toBeVisible();
  await page.reload();
  await expect(remove).toBeVisible();
  await remove.click();
  await expect(remove).toHaveCount(0);
  await page.reload();
  await expect(page.getByRole("button", { name: "Retirer le tag prod" })).toBeVisible();
  await expect(remove).toHaveCount(0);
});

test("carte géo : carte du monde vectorielle embarquée, hors ligne, sans tuile ni requête externe", async ({ page, request }) => {
  // La garde de fixtures.ts échoue sur toute requête vers un hôte externe.
  const id = await scanIdFor(request, "shop.example.com");
  await page.goto(`/scans/${id}/network`);
  const map = page.getByRole("img", { name: /^Carte de localisation/ });
  await expect(map).toBeVisible();
  // Terres dessinées (tracé non vide) et un point à l'emplacement de la cible.
  const landLength = await map.locator("path").nth(1).evaluate((path) => path.getAttribute("d")?.length ?? 0);
  expect(landLength).toBeGreaterThan(1000);
  await expect(map.locator("circle")).toHaveCount(2);
  await expect(page.locator("img.leaflet-tile")).toHaveCount(0);
});

test("un lien profond survit au rechargement (repli SPA)", async ({ page, request }) => {
  const id = await scanIdFor(request, "example.com");
  await page.goto(`/scans/${id}/tls`);
  await page.reload();
  await expect(page.getByRole("heading", { level: 1, name: "TLS" })).toBeVisible();
  await expect(page.getByText("Certificat valide", { exact: false })).toBeVisible();
  // Un module d'adresse inconnu retombe sur le premier onglet (ici, la famille Web).
  await page.goto(`/scans/${id}/web/inconnu`);
  await expect(page.getByRole("tablist", { name: "Modules de la famille Web" }).getByRole("tab", { selected: true })).toContainText(
    "En-têtes de sécurité",
  );
});

test("un scan partiel annonce ses modules sans résultat", async ({ page, request }) => {
  const id = await scanIdFor(request, "partial.example.net");
  await page.goto(`/scans/${id}`);
  const banner = page.getByRole("status").filter({ hasText: "Analyse incomplète" });
  await expect(banner).toBeVisible();
  await expect(banner.getByRole("listitem")).toContainText(["WHOIS", "Réseau étendu (délai dépassé)"]);
});

test("scan introuvable : message et sortie", async ({ page }) => {
  await page.goto("/scans/999999");
  await expect(page.getByText("Scan introuvable")).toBeVisible();
  await page.getByRole("link", { name: "Voir l'historique" }).click();
  await expect(page).toHaveURL(/\/history$/);
});
