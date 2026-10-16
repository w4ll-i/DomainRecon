import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import type { Page, TestInfo } from "@playwright/test";
import { deleteScansOf, expect, test, uniqueSuffix } from "./fixtures";

// Réglages : import d'une ancienne base par un vrai envoi de fichier (POST /api/import), contre le
// vrai serveur. Les bases d'essai sont fabriquées avec le Python du serveur de test (module sqlite3) ;
// les scans importés sont supprimés à la fin.
const PYTHON = process.env.E2E_PYTHON ?? (process.platform === "win32" ? "python" : "python3");

// Crée une base SQLite d'ancien format : table « scans », une colonne sans équivalent (legacy_flag).
function makeLegacyDatabase(info: TestInfo, name: string, rows: Array<[string, string]>): string {
  const path = info.outputPath(name);
  const code = [
    "import json, sqlite3, sys",
    "con = sqlite3.connect(sys.argv[1])",
    "con.execute('CREATE TABLE scans (id INTEGER PRIMARY KEY, domain TEXT, scan_timestamp TEXT, ip_address TEXT, legacy_flag TEXT)')",
    "con.executemany('INSERT INTO scans (domain, scan_timestamp, ip_address, legacy_flag) VALUES (?, ?, ?, ?)', [(d, t, '203.0.113.7', 'x') for d, t in json.loads(sys.argv[2])])",
    "con.commit()",
    "con.close()",
  ].join("\n");
  execFileSync(PYTHON, ["-I", "-c", code, path, JSON.stringify(rows)], { stdio: "pipe" });
  return path;
}

const importSection = (page: Page) => page.getByRole("region", { name: "Importer une ancienne base" });

async function chooseAndImport(page: Page, file: string | { name: string; mimeType: string; buffer: Buffer }) {
  const section = importSection(page);
  await section.getByLabel("Ancienne base DomainRecon (fichier .db)").setInputFiles(file);
  await section.getByRole("button", { name: "Importer", exact: true }).click();
}

test("importer une ancienne base : les six chiffres, puis le même fichier renvoyé n'ajoute rien", async ({ page, request }, info) => {
  const stamp = uniqueSuffix();
  const first = `import-a-${stamp}.example.org`;
  const second = `import-b-${stamp}.example.org`;
  const database = makeLegacyDatabase(info, "ancienne_base.db", [
    [first, "2024-03-01T10:00:00"],
    [second, "2024-03-02T10:00:00"],
    ["", "2024-03-03T10:00:00"],
    [`import-c-${stamp}.example.org`, "pas une date"],
  ]);
  try {
    await page.goto("/settings");
    const section = importSection(page);
    // Plus aucune commande à recopier : un bouton pour choisir le fichier, l'import inactif sans fichier.
    await expect(section).not.toContainText("domainrecon import");
    await expect(section.getByRole("button", { name: "Choisir un fichier" })).toBeVisible();
    await expect(section.getByRole("button", { name: "Importer", exact: true })).toBeDisabled();
    await expect(section.getByText("Aucun fichier choisi")).toBeVisible();

    const sent = page.waitForRequest((req) => req.method() === "POST" && new URL(req.url()).pathname === "/api/import");
    await chooseAndImport(page, database);
    await expect(section.getByText("ancienne_base.db")).toBeVisible();
    const request1 = await sent;
    expect(request1.headers()["content-type"]).toMatch(/^multipart\/form-data; boundary=/);

    const result = section.getByTestId("import-result");
    await expect(result).toBeVisible();
    const figure = (label: string) => result.getByText(label, { exact: true }).locator("xpath=following-sibling::dd[1]");
    await expect(figure("Scans lus")).toHaveText("4");
    await expect(figure("Ajoutés à l'historique")).toHaveText("2");
    await expect(figure("Ignorés")).toHaveText("2");
    await expect(figure("Déjà présents")).toHaveText("0");
    await expect(figure("Inutilisables (domaine ou date illisible)")).toHaveText("2");
    await expect(result).toContainText("2 scan(s) ajouté(s) à l'historique.");
    // La colonne de l'ancienne base sans équivalent est nommée.
    await expect(result.getByText("Colonnes sans équivalent, non reprises")).toBeVisible();
    await expect(result.getByText("legacy_flag", { exact: true })).toBeVisible();
    await expect(page.getByText("Import terminé : 2 scan(s) ajouté(s).")).toBeVisible();

    // Les scans importés sont dans l'historique.
    await result.getByRole("link", { name: "Voir l'historique" }).click();
    await expect(page).toHaveURL(/\/history$/);
    await page.getByRole("searchbox", { name: "Rechercher un domaine" }).fill(`import-a-${stamp}`);
    await expect(page.getByRole("link", { name: first, exact: true })).toBeVisible();

    // Même fichier une seconde fois : tout est reconnu comme déjà présent.
    await page.goto("/settings");
    await chooseAndImport(page, database);
    const again = importSection(page).getByTestId("import-result");
    await expect(again).toBeVisible();
    await expect(again.getByText("Scans lus", { exact: true }).locator("xpath=following-sibling::dd[1]")).toHaveText("4");
    await expect(again.getByText("Ajoutés à l'historique", { exact: true }).locator("xpath=following-sibling::dd[1]")).toHaveText("0");
    await expect(again.getByText("Déjà présents", { exact: true }).locator("xpath=following-sibling::dd[1]")).toHaveText("2");
    await expect(again).toContainText("Aucun nouveau scan");
    await expect(again.getByRole("link", { name: "Voir l'historique" })).toHaveCount(0);
  } finally {
    await deleteScansOf(request, first);
    await deleteScansOf(request, second);
  }
});

test("un fichier qui n'est pas une base SQLite est refusé avec un message clair, et l'import reste possible", async ({ page }) => {
  await page.goto("/settings");
  await chooseAndImport(page, { name: "notes.db", mimeType: "application/octet-stream", buffer: Buffer.from("ceci n'est pas une base de données\n") });
  const alert = importSection(page).getByRole("alert");
  await expect(alert).toBeVisible();
  await expect(alert).toContainText(/SQLite/);
  await expect(importSection(page).getByTestId("import-result")).toHaveCount(0);
  await expect(importSection(page).getByRole("button", { name: "Importer", exact: true })).toBeEnabled();
});

test("une base SQLite qui n'est pas une base DomainRecon est refusée", async ({ page }, info) => {
  const path = info.outputPath("autre_base.db");
  execFileSync(PYTHON, ["-I", "-c", "import sqlite3, sys\ncon = sqlite3.connect(sys.argv[1])\ncon.execute('CREATE TABLE notes (id INTEGER, texte TEXT)')\ncon.commit()\ncon.close()", path], { stdio: "pipe" });
  await page.goto("/settings");
  await chooseAndImport(page, path);
  const alert = importSection(page).getByRole("alert");
  await expect(alert).toBeVisible();
  await expect(alert).toContainText(/DomainRecon/);
});

test("un fichier vide est refusé, la page reste utilisable", async ({ page }, info) => {
  const empty = info.outputPath("vide.db");
  await writeFile(empty, "");
  await page.goto("/settings");
  await chooseAndImport(page, empty);
  await expect(importSection(page).getByRole("alert")).toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: "Réglages" })).toBeVisible();
});

test("une panne du serveur pendant l'envoi est dite, sans bloquer l'écran", async ({ page }, info) => {
  const database = makeLegacyDatabase(info, "ancienne_base.db", [["panne-import.example.org", "2024-03-01T10:00:00"]]);
  await page.route("**/api/import**", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "L'import a échoué. Vous pouvez le relancer : les doublons sont ignorés.", code: "api.import_failed", params: {} }),
    }),
  );
  await page.goto("/settings");
  await chooseAndImport(page, database);
  await expect(importSection(page).getByRole("alert")).toContainText("L'import a échoué. Vous pouvez le relancer");
  await expect(importSection(page).getByRole("button", { name: "Importer", exact: true })).toBeEnabled();
});

test("l'import est traduit : textes anglais et réponse du serveur en anglais", async ({ page, request }, info) => {
  const stamp = uniqueSuffix();
  const domain = `import-en-${stamp}.example.org`;
  const database = makeLegacyDatabase(info, "old_database.db", [[domain, "2024-04-01T10:00:00"]]);
  try {
    await page.addInitScript(() => window.localStorage.setItem("domainrecon.lang", "en"));
    await page.goto("/settings");
    const section = page.getByRole("region", { name: "Import an old database" });
    const sent = page.waitForRequest((req) => req.method() === "POST" && new URL(req.url()).pathname === "/api/import");
    await section.getByLabel("Old DomainRecon database (.db file)").setInputFiles(database);
    await section.getByRole("button", { name: "Import", exact: true }).click();
    expect(new URL((await sent).url()).searchParams.get("lang")).toBe("en");
    await expect(section.getByTestId("import-result")).toContainText("1 scan(s) added to the history.");
  } finally {
    await deleteScansOf(request, domain);
  }
});
