import { readFile } from "node:fs/promises";
import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";

// Réglages : désinstallation complète contre le vrai serveur de test. Le serveur E2E
// (tests/e2e_server.py, install_uninstall_sandbox) fait opérer la désinstallation sur un bac à
// sable de son dossier de données temporaire : vraie suppression, mais jamais sur la machine ni
// sur la base des autres tests ; tâche système simulée, aucun processus lancé.
const SANDBOX = "desinstallation-test";

const dialogOf = (page: Page) => page.getByRole("alertdialog", { name: "Désinstaller complètement DomainRecon" });

async function openDialog(page: Page) {
  await page.goto("/settings");
  const zone = page.getByRole("region", { name: "Désinstaller complètement DomainRecon" });
  await expect(zone.getByText("Zone de danger")).toBeVisible();
  await zone.getByRole("button", { name: "Désinstaller complètement…" }).click();
  const dialog = dialogOf(page);
  await expect(dialog.getByTestId("uninstall-items")).toBeVisible();
  return dialog;
}

test("désinstaller complètement : liste à blanc, sauvegarde, mot de confirmation, résultat", async ({ page, request }, info) => {
  // Garde-fou : le serveur doit être celui de ce dépôt, avec son bac à sable. Sinon, aucune
  // suppression n'est demandée.
  const plan = await request.post("/api/system/uninstall", { data: { dry_run: true } });
  expect(plan.ok()).toBe(true);
  const report = (await plan.json()) as { items: Array<{ kind: string; path: string | null }> };
  const files = report.items.filter((item) => item.kind !== "system_task");
  expect(files.length).toBeGreaterThan(0);
  for (const item of files) expect(item.path).toContain(SANDBOX);

  const dialog = await openDialog(page);
  // Étape 1 : ce qui sera supprimé, d'après le serveur.
  await expect(dialog.locator('[aria-current="step"]')).toHaveText("Ce qui sera supprimé");
  const items = dialog.getByTestId("uninstall-items");
  await expect(items.getByText("Base de données (historique, surveillances, réglages, clés API chiffrées)")).toBeVisible();
  await expect(items.getByText("Clé de chiffrement des clés API")).toBeVisible();
  await expect(items.getByText("Tâche planifiée de la surveillance")).toBeVisible();
  await expect(items.getByText("Fichier temporaire")).toBeVisible();
  await expect(dialog.getByText("Installation détectée : lancement depuis les sources.")).toBeVisible();
  await dialog.screenshot({ path: info.outputPath("1-liste.png") });
  await dialog.getByRole("button", { name: "Continuer" }).click();

  // Étape 2 : sauvegarde de la vraie base du serveur de test, réimportable (fichier SQLite).
  await expect(dialog.locator('[aria-current="step"]')).toHaveText("Sauvegarde");
  const downloading = page.waitForEvent("download");
  await dialog.getByRole("button", { name: "Télécharger une sauvegarde (.db)" }).click();
  const download = await downloading;
  expect(download.suggestedFilename()).toMatch(/^domainrecon-sauvegarde-\d{8}-\d{6}\.db$/);
  const saved = info.outputPath("sauvegarde.db");
  await download.saveAs(saved);
  expect((await readFile(saved)).subarray(0, 16).toString("latin1")).toBe("SQLite format 3\u0000");
  await expect(dialog.getByText(`Sauvegarde téléchargée : ${download.suggestedFilename()}`)).toBeVisible();
  await dialog.screenshot({ path: info.outputPath("2-sauvegarde.png") });
  await dialog.getByRole("button", { name: "Continuer" }).click();

  // Étape 3 : le bouton final reste inactif tant que le mot n'est pas tapé.
  const submit = dialog.getByRole("button", { name: "Désinstaller définitivement" });
  await expect(submit).toBeDisabled();
  const field = dialog.getByRole("textbox", { name: "Tapez SUPPRIMER" });
  await expect(field).toBeFocused();
  await field.fill("SUPPRIM");
  await expect(submit).toBeDisabled();
  await field.fill("SUPPRIMER");
  await dialog.screenshot({ path: info.outputPath("3-confirmation.png") });
  const sent = page.waitForRequest((req) => req.method() === "POST" && new URL(req.url()).pathname === "/api/system/uninstall");
  await submit.click();
  expect((await sent).postDataJSON()).toEqual({ confirm: "SUPPRIMER", remove_program: false });

  // Étape 4 : résultat, étapes restantes.
  await expect(dialog.getByText("DomainRecon a été désinstallé.")).toBeVisible();
  await expect(dialog.getByText("Non supprimé")).toHaveCount(0);
  await expect(dialog.getByText("Supprimé", { exact: true }).first()).toBeVisible();
  await expect(dialog.getByTestId("uninstall-remaining")).toContainText("le dossier du projet n'est pas touché");
  await dialog.screenshot({ path: info.outputPath("4-resultat.png") });
  // Serveur de test : pas de fermeture automatique, « Terminer » referme la fenêtre.
  await dialog.getByRole("button", { name: "Terminer" }).click();
  await expect(dialogOf(page)).toHaveCount(0);

  // Le reste de l'application n'a pas été touché : historique toujours servi.
  const history = await request.get("/api/history");
  expect(history.ok()).toBe(true);
});

test("désinstaller : Annuler ou Échap ne suppriment rien, la confirmation exige le mot exact", async ({ page, request }) => {
  const before = (await (await request.post("/api/system/uninstall", { data: { dry_run: true } })).json()) as { items: unknown[] };
  const dialog = await openDialog(page);
  await page.keyboard.press("Escape");
  await expect(dialogOf(page)).toHaveCount(0);

  const again = await openDialog(page);
  await again.getByRole("button", { name: "Continuer" }).click();
  await again.getByRole("button", { name: "Continuer sans sauvegarde" }).click();
  await again.getByRole("textbox", { name: "Tapez SUPPRIMER" }).fill("OUI");
  await expect(again.getByRole("button", { name: "Désinstaller définitivement" })).toBeDisabled();
  await again.getByRole("button", { name: "Annuler" }).click();
  await expect(dialog).toHaveCount(0);

  // Refus côté serveur aussi : sans le mot, 400 et rien n'est supprimé.
  const refused = await request.post("/api/system/uninstall", { data: { confirm: "OUI" } });
  expect(refused.status()).toBe(400);
  const after = (await (await request.post("/api/system/uninstall", { data: { dry_run: true } })).json()) as { items: unknown[] };
  expect(after.items).toHaveLength(before.items.length);
});

test("désinstaller : la fenêtre en thèmes sombre et clair, et sur un écran étroit", async ({ page }, info) => {
  for (const theme of ["Sombre", "Clair"]) {
    await page.goto("/settings");
    await page.getByRole("radio", { name: theme }).check();
    const shown = await openDialog(page);
    await shown.screenshot({ path: info.outputPath(`theme-${theme.toLowerCase()}.png`) });
    await page.keyboard.press("Escape");
  }
  const dialog = await openDialog(page);
  await page.setViewportSize({ width: 390, height: 760 });
  await expect(dialog).toBeVisible();
  const box = await dialog.boundingBox();
  expect(box?.width ?? 0).toBeLessThanOrEqual(390);
  // Aucun défilement horizontal de la page.
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath("etroit.png") });
});

test("désinstaller au clavier : le focus suit chaque étape et la liste défilante est atteignable (sans rien confirmer)", async ({ page }) => {
  const dialog = await openDialog(page);
  // Étape 1 : « Annuler » d'abord, puis la tabulation passe par la liste des éléments.
  await expect(dialog.getByRole("button", { name: "Annuler" })).toBeFocused();
  const items = dialog.getByTestId("uninstall-items");
  let reached = false;
  for (let i = 0; i < 4 && !reached; i += 1) {
    await page.keyboard.press("Tab");
    reached = await items.evaluate((element) => element === document.activeElement);
  }
  expect(reached).toBe(true);
  // Étape 2 : le focus va au bouton de sauvegarde, jamais sur la page derrière la fenêtre.
  await dialog.getByRole("button", { name: "Continuer" }).press("Enter");
  await expect(dialog.getByRole("button", { name: "Télécharger une sauvegarde (.db)" })).toBeFocused();
  await dialog.getByRole("button", { name: "Continuer sans sauvegarde" }).press("Enter");
  await expect(dialog.getByRole("textbox", { name: "Tapez SUPPRIMER" })).toBeFocused();
  await dialog.getByRole("button", { name: "Retour" }).press("Enter");
  await expect(dialog.getByRole("button", { name: "Télécharger une sauvegarde (.db)" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialogOf(page)).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Désinstaller complètement…" })).toBeFocused();
});
