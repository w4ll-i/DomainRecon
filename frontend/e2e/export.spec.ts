import { readFile } from "node:fs/promises";
import type { Download, Page } from "@playwright/test";
import { expect, scanIdFor, test } from "./fixtures";

// Le menu « Exporter » de l'écran Résultat remplace les anciens boutons PDF et JSON : un seul
// bouton ouvre la liste des six formats du serveur (GET /api/scan/{id}/export).

async function openMenu(page: Page) {
  await page.getByRole("button", { name: "Exporter" }).click();
  return page.getByRole("menu", { name: "Formats d'export" });
}

// Choisit un format dans le menu et attend le téléchargement qui en découle.
async function exportAs(page: Page, format: string): Promise<Download> {
  const menu = await openMenu(page);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    // Le nom du format (PDF, JSON…) est le premier texte de l'entrée ; le reste en est l'explication.
    menu.getByRole("menuitem").filter({ has: page.getByText(format, { exact: true }) }).click(),
  ]);
  return download;
}

const textOf = async (download: Download) => readFile(await download.path(), "utf8");

test("exports PDF et JSON du scan affiché, par le menu Exporter", async ({ page, request }) => {
  const id = await scanIdFor(request, "example.com");
  await page.goto(`/scans/${id}`);
  await expect(page.getByRole("heading", { level: 1, name: "example.com" })).toBeVisible();

  // Le PDF est rendu par le Chromium de Playwright, côté serveur. Une machine qui n'en a pas reçoit
  // un 503 « PDF indisponible » : l'interface doit alors le dire, et c'est ce que ce scénario vérifie.
  const pdfAvailable = (await request.get(`/api/scan/${id}/export?format=pdf`)).status() !== 503;
  // Machine équipée (E2E_REQUIRE_PDF=1, Chromium de Playwright présent) : le repli est interdit, un PDF
  // devenu indisponible par régression ferait échouer le test au lieu de passer par la branche d'erreur.
  if (process.env.E2E_REQUIRE_PDF === "1") expect(pdfAvailable, "export PDF exigé (E2E_REQUIRE_PDF=1)").toBe(true);
  if (pdfAvailable) {
    const pdf = await exportAs(page, "PDF");
    expect(pdf.suggestedFilename()).toBe(`domainrecon-example.com-${id}.pdf`);
    const pdfBytes = await readFile(await pdf.path());
    expect(pdfBytes.subarray(0, 5).toString("latin1")).toBe("%PDF-");
    // Un PDF vide pèse moins de 2 Ko : le rapport (score, constats, familles) est bien rendu.
    expect(pdfBytes.length).toBeGreaterThan(5_000);
    expect(pdfBytes.subarray(-1024).toString("latin1")).toContain("%%EOF");
    await expect(page.getByText("Export PDF téléchargé")).toBeVisible();
  } else {
    test.info().annotations.push({ type: "pdf", description: "Chromium absent côté serveur : seul le message d'erreur est vérifié" });
    const menu = await openMenu(page);
    await menu.getByRole("menuitem").filter({ has: page.getByText("PDF", { exact: true }) }).click();
    await expect(page.getByText(/^Export PDF impossible : /)).toBeVisible();
    await expect(page.getByRole("button", { name: "Exporter" })).toBeEnabled();
  }

  const json = await exportAs(page, "JSON");
  expect(json.suggestedFilename()).toBe(`domainrecon-example.com-${id}.json`);
  // Enveloppe du rapport (générateur, version, langue, format), puis le scan complet.
  const data = JSON.parse(await textOf(json)) as {
    report: { generator: string; version: string; lang: string; format: string };
    scan: { id: number; domain: string; families: object };
  };
  expect(data.report).toMatchObject({ generator: "DomainRecon", lang: "fr", format: "json" });
  expect(data.report.version).toMatch(/^[0-9]+[.][0-9]+/);
  expect(data.scan.id).toBe(id);
  expect(data.scan.domain).toBe("example.com");
  // Une entrée par famille du catalogue des modules (huit aujourd'hui, avec « leaks ») : la liste vient
  // du serveur, un module ou une famille ajouté demain ne casse pas ce test.
  const catalog = (await (await request.get("/api/modules")).json()) as { families: string[] };
  expect(catalog.families.length).toBeGreaterThanOrEqual(7);
  expect(Object.keys(data.scan.families).sort()).toEqual([...catalog.families].sort());
  await expect(page.getByText("Export JSON téléchargé")).toBeVisible();
});

test("le menu Exporter liste les six formats, se ferme à Échap et au clic ailleurs", async ({ page, request }) => {
  const id = await scanIdFor(request, "example.com");
  await page.goto(`/scans/${id}`);
  const button = page.getByRole("button", { name: "Exporter" });
  await expect(button).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByRole("menu")).toHaveCount(0);

  const menu = await openMenu(page);
  await expect(button).toHaveAttribute("aria-expanded", "true");
  const items = menu.getByRole("menuitem");
  await expect(items).toHaveCount(6);
  // Chaque format dit à quoi il sert.
  await expect(items).toContainText([
    "PDFRapport à imprimer ou à envoyer",
    "HTMLPage autonome, lisible dans un navigateur",
    "MarkdownTexte structuré pour un ticket ou un wiki",
    "CSVTableau des constats pour un tableur",
    "JSONDonnées complètes, pour vos scripts",
    "SARIFFormat des outils d'analyse de sécurité",
  ]);

  await page.keyboard.press("Escape");
  await expect(page.getByRole("menu")).toHaveCount(0);
  await expect(button).toHaveAttribute("aria-expanded", "false");

  await openMenu(page);
  await page.getByRole("heading", { level: 1, name: "example.com" }).click();
  await expect(page.getByRole("menu")).toHaveCount(0);
});

test("HTML, Markdown, CSV et SARIF : chaque format est un vrai fichier du bon type", async ({ page, request }) => {
  const id = await scanIdFor(request, "shop.example.com");
  await page.goto(`/scans/${id}`);
  await expect(page.getByRole("heading", { level: 1, name: "shop.example.com" })).toBeVisible();

  const html = await exportAs(page, "HTML");
  expect(html.suggestedFilename()).toBe(`domainrecon-shop.example.com-${id}.html`);
  const htmlText = await textOf(html);
  expect(htmlText.trimStart().toLowerCase()).toMatch(/^<!doctype html|^<html/);
  expect(htmlText).toContain("shop.example.com");
  // Le rapport reprend le « Comment corriger » du catalogue : étapes numérotées et extrait à copier.
  const fixes = /<section id="fixes"><h2>Comment corriger<\/h2>(.*?)<\/section>/s.exec(htmlText)?.[1] ?? "";
  expect(fixes).toContain("<ol><li>");
  expect(fixes).toContain("<pre><code>");
  expect(fixes).toMatch(/Documentation officielle : https:\/\//);

  const markdown = await exportAs(page, "Markdown");
  expect(markdown.suggestedFilename()).toBe(`domainrecon-shop.example.com-${id}.md`);
  const markdownText = await textOf(markdown);
  expect(markdownText).toMatch(/^#\s.*shop\.example\.com/m);
  expect(markdownText).toMatch(/^## Comment corriger$/m);

  const csv = await exportAs(page, "CSV");
  expect(csv.suggestedFilename()).toBe(`domainrecon-shop.example.com-${id}.csv`);
  // Le CSV commence par une marque d'ordre des octets (Excel lit alors les accents) : écartée ici.
  const csvText = await textOf(csv);
  expect(csvText.charCodeAt(0)).toBe(0xfeff);
  const rows = csvText.slice(1).trim().split(/\r?\n/);
  // En-tête, puis une ligne par constat et une par module lancé.
  expect(rows[0]).toBe("type,domain,severity,family,module,status,duration_s,message");
  expect(rows.some((row) => row.startsWith("finding,shop.example.com,"))).toBe(true);
  expect(rows.some((row) => row.startsWith("module,shop.example.com,"))).toBe(true);

  const sarif = await exportAs(page, "SARIF");
  expect(sarif.suggestedFilename()).toBe(`domainrecon-shop.example.com-${id}.sarif`);
  const report = JSON.parse(await textOf(sarif)) as { version: string; runs: Array<{ results: unknown[] }> };
  expect(report.version).toBe("2.1.0");
  expect(report.runs[0].results.length).toBeGreaterThan(0);
});

test("un export en échec est annoncé, l'écran reste utilisable", async ({ page, request }) => {
  const id = await scanIdFor(request, "example.com");
  await page.goto(`/scans/${id}`);
  await page.route(`**/api/scan/${id}/export*`, (route) =>
    route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: "PDF indisponible : Chromium manque", code: "api.export_pdf_unavailable", params: {} }) }),
  );
  const menu = await openMenu(page);
  await menu.getByRole("menuitem", { name: /^PDF\b/ }).click();
  await expect(page.getByText("Export PDF impossible : PDF indisponible : Chromium manque")).toBeVisible();
  // Le bouton est de nouveau disponible : on peut choisir un autre format.
  await expect(page.getByRole("button", { name: "Exporter" })).toBeEnabled();
});
