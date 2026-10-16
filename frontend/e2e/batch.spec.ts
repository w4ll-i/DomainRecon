import { readFile } from "node:fs/promises";
import { deleteScansOf, expect, test, uniqueSuffix } from "./fixtures";

// Scan en lot contre le vrai serveur (faux scanner, aucun réseau) : liste collée, profil, doublons et
// entrées refusées, avancement, résultats, export CSV. Les domaines sont neufs à chaque exécution et
// leurs scans sont supprimés à la fin.

test("une liste collée se lance en lot : avancement, résultats, ouverture d'un scan et export CSV", async ({ page, request }) => {
  const stamp = uniqueSuffix();
  const first = `lot-a-${stamp}.example.org`;
  const second = `lot-b-${stamp}.example.org`;
  try {
    await page.goto("/batch");
    await expect(page.getByRole("heading", { level: 1, name: "Scan en lot" })).toBeVisible();
    await expect(page.getByText("Aucun lot en cours")).toBeVisible();
    const start = page.getByRole("button", { name: /^Lancer le lot/ });
    await expect(start).toBeDisabled();

    // Séparateurs mêlés ; une casse différente (doublon pour le serveur) et une entrée invalide.
    await page.getByLabel("Liste de domaines").fill(`${first}, ${second.toUpperCase()}\n${second}\ninvalide_!`);
    await expect(page.getByText("4 domaine(s) détecté(s)")).toBeVisible();
    await expect(start).toHaveText("Lancer le lot (4)");

    // Profil rapide : le lot repose sur le même choix de profil que le nouveau scan.
    const profiles = page.getByRole("group", { name: "Profil du scan" });
    await profiles.getByRole("radio", { name: /^Rapide/ }).check();
    const launched = page.waitForRequest((req) => req.method() === "POST" && new URL(req.url()).pathname === "/api/batches");
    await start.click();
    const sent = (await launched).postDataJSON() as { domains: string[]; profile: string; authorized_target: boolean };
    expect(sent.profile).toBe("rapide");
    expect(sent.authorized_target).toBe(false);
    expect(sent.domains).toHaveLength(4);

    await expect(page).toHaveURL(/\/batch\?batch=[0-9a-f]+$/);
    // Le serveur dit ce qu'il a écarté : un doublon, une entrée refusée avec la raison.
    const notice = page.getByRole("status").filter({ hasText: "doublon(s) ignoré(s)" });
    await expect(notice).toContainText("1 doublon(s) ignoré(s).");
    await expect(notice).toContainText("1 entrée(s) refusée(s) :");
    await expect(notice).toContainText("invalide_!");

    // Avancement, puis les deux domaines terminés.
    await expect(page.getByRole("progressbar", { name: "Avancement du lot" })).toBeVisible();
    await expect(page.getByText("2 sur 2 terminé(s)")).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText("2 réussi(s), 0 en échec, 0 annulé(s)")).toBeVisible();
    const table = page.getByRole("table", { name: "Résultats du lot" });
    await expect(table.getByRole("columnheader")).toHaveText(["Domaine", "Statut", "Note", "Score", "Résultat"]);
    for (const domain of [first, second]) {
      const row = table.getByRole("row").filter({ hasText: domain });
      await expect(row.getByText("Terminé")).toBeVisible();
      await expect(row.getByRole("img", { name: /^Note [A-F]$/ })).toBeVisible();
    }
    // Plus de bouton d'annulation une fois le lot fini.
    await expect(page.getByRole("button", { name: "Annuler le lot" })).toHaveCount(0);

    // Export CSV du tableau.
    const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Exporter en CSV" }).click()]);
    expect(download.suggestedFilename()).toMatch(/^domainrecon_lot_[0-9a-f]{8}\.csv$/);
    const csv = (await readFile(await download.path(), "utf8")).trim().split("\n");
    expect(csv[0]).toBe("domain,status,grade,score,scan_id,error");
    expect(csv).toHaveLength(3);
    expect(csv.filter((line) => line.includes(",done,"))).toHaveLength(2);
    expect(csv.some((line) => line.startsWith(first))).toBe(true);

    // Le résultat d'un domaine du lot s'ouvre.
    await table.getByRole("row").filter({ hasText: first }).getByRole("link", { name: "Ouvrir le résultat" }).click();
    await expect(page).toHaveURL(/\/scans\/\d+$/);
    await expect(page.getByRole("heading", { level: 1, name: first })).toBeVisible();
  } finally {
    await deleteScansOf(request, first);
    await deleteScansOf(request, second);
  }
});

test("le lot propose les mêmes profils que le nouveau scan, et la case d'autorisation pour les modules actifs", async ({ page }) => {
  await page.goto("/batch");
  const profiles = page.getByRole("group", { name: "Profil du scan" });
  await expect(profiles.getByRole("radio")).toHaveCount(3);
  await expect(profiles.getByRole("radio", { name: /^Complet/ })).toBeChecked();

  await profiles.getByRole("radio", { name: /^Personnalisé/ }).check();
  await expect(page.getByRole("status").filter({ hasText: /module\(s\) choisi\(s\) sur/ })).toBeVisible();
  // Un module actif (ports ouverts) exige l'autorisation, dite au pluriel pour un lot.
  await page.locator("summary", { hasText: "Réseau" }).click();
  await page.getByRole("checkbox", { name: /Ports ouverts/ }).check();
  const consent = page.getByRole("checkbox", { name: "J'ai l'autorisation de tester ces cibles" });
  await expect(consent).toBeVisible();
  await page.getByLabel("Liste de domaines").fill("exemple-lot.example.org");
  const start = page.getByRole("button", { name: /^Lancer le lot/ });
  await expect(start).toBeDisabled();
  await consent.check();
  await expect(start).toBeEnabled();
});

test("une liste vide ou un fichier trop gros ne lance rien ; un fichier .txt remplit la liste", async ({ page }) => {
  await page.goto("/batch");
  await page.getByLabel("Fichier de domaines (.txt ou .csv)").setInputFiles({
    name: "domaines.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("un.example.org\ndeux.example.org\n"),
  });
  await expect(page.getByLabel("Liste de domaines")).toHaveValue("un.example.org\ndeux.example.org\n");
  await expect(page.getByText("2 domaine(s) détecté(s)")).toBeVisible();

  await page.getByLabel("Fichier de domaines (.txt ou .csv)").setInputFiles({
    name: "enorme.txt",
    mimeType: "text/plain",
    buffer: Buffer.alloc(600 * 1024, "a"),
  });
  await expect(page.getByText("Fichier trop volumineux (512 Ko au plus).")).toBeVisible();
  // La liste précédente n'a pas été écrasée.
  await expect(page.getByText("2 domaine(s) détecté(s)")).toBeVisible();
});
