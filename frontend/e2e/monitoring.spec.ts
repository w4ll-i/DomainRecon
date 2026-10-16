import type { APIRequestContext, Page } from "@playwright/test";
import { deleteScansOf, expect, test, uniqueSuffix } from "./fixtures";

// Surveillance contre le vrai serveur : ajout, fréquence, pause, règles, suppression ; centre de
// notifications ; carte de la tâche système. La tâche système n'est JAMAIS installée ici (ce
// serait une vraie tâche planifiée sur la machine qui lance les tests) : on vérifie seulement
// qu'elle se présente.

// Retire les surveillances laissées par un test interrompu, et leurs scans.
async function cleanup(request: APIRequestContext, domain?: string) {
  const response = await request.get("/api/watches");
  const { watches } = (await response.json()) as { watches: Array<{ id: number; domain: string }> };
  for (const watch of watches.filter((item) => item.domain.startsWith("watch-e2e-"))) {
    await request.delete(`/api/watches/${watch.id}`);
    await deleteScansOf(request, watch.domain);
  }
  if (domain) await deleteScansOf(request, domain);
}

const rowOf = (page: Page, domain: string) =>
  page
    .getByRole("table", { name: "Domaines surveillés" })
    .getByRole("row")
    .filter({ has: page.getByRole("rowheader", { name: domain }) });

test("l'écran Surveillance : deux sections, le formulaire d'ajout et la carte de la tâche système", async ({ page, request }) => {
  await cleanup(request);
  await page.route("**/api/watches", (route) =>
    route.request().method() === "GET" ? route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ watches: [] }) }) : route.fallback(),
  );
  await page.goto("/monitoring");
  await expect(page.getByRole("heading", { level: 1, name: "Surveillance" })).toBeVisible();
  const tabs = page.getByRole("tablist", { name: "Sections de la surveillance" });
  await expect(tabs.getByRole("tab", { name: "Surveillances" })).toHaveAttribute("aria-selected", "true");
  await expect(tabs.getByRole("tab", { name: /^Notifications/ })).toHaveAttribute("aria-selected", "false");

  // Aucune surveillance : un état vide qui explique quoi faire.
  await expect(page.getByText("Aucune surveillance", { exact: true })).toBeVisible();

  // Formulaire d'ajout : domaine, fréquence, profil, règles d'alerte, canaux.
  const form = page.getByRole("form", { name: "Ajouter une surveillance" });
  await expect(form.getByLabel("Domaine à surveiller")).toBeVisible();
  await expect(form.getByLabel("Fréquence")).toHaveValue("daily");
  await expect(form.getByRole("group", { name: "Profil du scan" }).getByRole("radio")).toHaveCount(3);
  const rules = form.getByRole("group", { name: "Règles d'alerte" });
  for (const rule of ["La note baisse", "Un constat critique ou élevé apparaît", "Un nouveau port s'ouvre", "Un nouveau sous-domaine apparaît"]) {
    await expect(rules.getByRole("checkbox", { name: rule })).toBeChecked();
  }
  await expect(rules.getByLabel("Alerter quand le certificat expire dans (jours)")).toHaveValue("14");
  const channels = form.getByRole("group", { name: "Canaux d'alerte" });
  await expect(channels.getByRole("checkbox", { name: "Centre de notifications" })).toBeChecked();
  await expect(channels.getByRole("checkbox", { name: "Discord" })).not.toBeChecked();
  // Tant que le domaine est vide, rien ne s'envoie.
  await expect(form.getByRole("button", { name: "Surveiller ce domaine" })).toBeDisabled();

  // Tâche système : l'état est lu, jamais modifié.
  const task = page.getByRole("region", { name: "Tâche système" });
  await expect(task).toBeVisible();
  await expect(task).toContainText("même quand DomainRecon est fermé");
  await expect(task.getByText(/^(Installée|Non installée)$/).or(task.getByText(/ne permet pas d'installer/))).toBeVisible();
});

test("ajouter une surveillance, changer sa fréquence, la mettre en pause, modifier ses règles, la supprimer", async ({ page, request }) => {
  const domain = `watch-e2e-${uniqueSuffix()}.example.org`;
  await cleanup(request);
  try {
    await page.goto("/monitoring");
    const form = page.getByRole("form", { name: "Ajouter une surveillance" });
    await form.getByLabel("Domaine à surveiller").fill(domain);
    await form.getByLabel("Fréquence").selectOption("weekly");
    await form.getByRole("group", { name: "Profil du scan" }).getByRole("radio", { name: /^Rapide/ }).check();
    // Une règle décochée et un canal de plus : le choix part tel quel au serveur.
    await form.getByRole("checkbox", { name: "Un nouveau sous-domaine apparaît" }).uncheck();
    await form.getByRole("checkbox", { name: "Notification de bureau" }).check();
    const created = page.waitForRequest((req) => req.method() === "POST" && new URL(req.url()).pathname === "/api/watches");
    await form.getByRole("button", { name: "Surveiller ce domaine" }).click();
    const sent = (await created).postDataJSON() as Record<string, unknown>;
    expect(sent).toMatchObject({
      domain,
      frequency: "weekly",
      profile: "rapide",
      lang: "fr",
      channels: ["center", "desktop"],
      rules: { grade_drop: true, new_findings: true, new_port: true, new_subdomain: false, cert_expiry_days: 14 },
    });
    await expect(page.getByText(`${domain} est maintenant surveillé`)).toBeVisible();
    await expect(form.getByLabel("Domaine à surveiller")).toHaveValue("");

    const row = rowOf(page, domain);
    await expect(row).toBeVisible();
    await expect(row.getByLabel(`Fréquence de ${domain}`)).toHaveValue("weekly");
    await expect(row.getByRole("checkbox", { name: "Active" })).toBeChecked();

    // Un même domaine ne peut pas être surveillé deux fois : le serveur refuse, le message s'affiche.
    await form.getByLabel("Domaine à surveiller").fill(domain);
    await form.getByRole("button", { name: "Surveiller ce domaine" }).click();
    await expect(page.getByText("Ce domaine est déjà surveillé.")).toBeVisible();

    // Fréquence : changée dans la ligne, retenue par le serveur.
    await row.getByLabel(`Fréquence de ${domain}`).selectOption("monthly");
    await expect.poll(async () => {
      const { watches } = (await (await request.get("/api/watches")).json()) as { watches: Array<{ domain: string; frequency: string }> };
      return watches.find((watch) => watch.domain === domain)?.frequency;
    }).toBe("monthly");

    // Pause : l'état le dit, la prochaine exécution disparaît, « Lancer maintenant » n'est plus possible.
    await row.getByRole("checkbox", { name: "Active" }).click();
    await expect(row.getByRole("checkbox", { name: "En pause" })).not.toBeChecked();
    await expect(row.getByRole("button", { name: "Lancer maintenant" })).toBeDisabled();
    await row.getByRole("checkbox", { name: "En pause" }).click();
    await expect(row.getByRole("checkbox", { name: "Active" })).toBeChecked();
    await expect(row.getByRole("button", { name: "Lancer maintenant" })).toBeEnabled();

    // Règles et canaux d'une surveillance existante.
    await row.getByRole("button", { name: "Modifier" }).click();
    const editor = page.getByRole("table", { name: "Domaines surveillés" }).getByRole("group", { name: "Règles d'alerte" });
    await expect(editor.getByRole("checkbox", { name: "Un nouveau sous-domaine apparaît" })).not.toBeChecked();
    await editor.getByRole("checkbox", { name: "Un nouveau sous-domaine apparaît" }).check();
    await page.getByRole("table", { name: "Domaines surveillés" }).getByRole("button", { name: "Enregistrer" }).click();
    await expect(page.getByText("Surveillance enregistrée")).toBeVisible();
    await expect.poll(async () => {
      const { watches } = (await (await request.get("/api/watches")).json()) as {
        watches: Array<{ domain: string; rules: { new_subdomain: boolean } }>;
      };
      return watches.find((watch) => watch.domain === domain)?.rules.new_subdomain;
    }).toBe(true);

    // Les réglages survivent au rechargement.
    await page.reload();
    await expect(rowOf(page, domain).getByLabel(`Fréquence de ${domain}`)).toHaveValue("monthly");

    // Suppression après confirmation.
    await page.getByRole("button", { name: `Supprimer la surveillance de ${domain}` }).click();
    const dialog = page.getByRole("alertdialog", { name: "Supprimer la surveillance ?" });
    await expect(dialog).toContainText(`${domain} ne sera plus scanné automatiquement`);
    await dialog.getByRole("button", { name: "Annuler" }).click();
    await expect(rowOf(page, domain)).toBeVisible();
    await page.getByRole("button", { name: `Supprimer la surveillance de ${domain}` }).click();
    await page.getByRole("alertdialog").getByRole("button", { name: "Supprimer" }).click();
    await expect(rowOf(page, domain)).toHaveCount(0);
  } finally {
    await cleanup(request, domain);
  }
});

test("« Lancer maintenant » planifie le scan tout de suite et le dit", async ({ page, request }) => {
  const domain = `watch-e2e-${uniqueSuffix()}.example.org`;
  await cleanup(request);
  try {
    const created = await request.post("/api/watches", { data: { domain, frequency: "monthly", profile: "rapide", enabled: true, next_run_at: "2999-01-01T00:00:00Z" } });
    expect(created.status()).toBe(201);
    await page.goto("/monitoring");
    const row = rowOf(page, domain);
    await expect(row).toBeVisible();
    await expect(row.getByText("Jamais exécutée")).toBeVisible();
    const run = page.waitForRequest((req) => req.method() === "POST" && /\/api\/watches\/\d+\/run$/.test(new URL(req.url()).pathname));
    await row.getByRole("button", { name: "Lancer maintenant" }).click();
    expect((await run).postData()).toBe("{}");
    await expect(page.getByText(`Scan de ${domain} planifié`)).toBeVisible();
  } finally {
    await cleanup(request, domain);
  }
});

test("centre de notifications : non lues, marquer comme lue, supprimer, vider", async ({ page }) => {
  let items = [
    { id: 1, created_at: "2026-10-14T08:00:00Z", domain: "alpha.example.org", scan_id: 37, watch_id: 1, rule: "grade_drop", severity: "high", message: "La note passe de B à D", is_read: false, delivery: {} },
    { id: 2, created_at: "2026-10-13T08:00:00Z", domain: "beta.example.org", scan_id: null, watch_id: 2, rule: "new_port", severity: "medium", message: "Nouveau port ouvert : 3306", is_read: false, delivery: {} },
    { id: 3, created_at: "2026-10-12T08:00:00Z", domain: "gamma.example.org", scan_id: null, watch_id: 3, rule: "cert_expiry", severity: "low", message: "Le certificat expire dans 12 jours", is_read: true, delivery: {} },
  ];
  const json = (body: unknown) => ({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  await page.route("**/api/notifications**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === "GET") {
      return route.fulfill(json({ total: items.length, unread: items.filter((item) => !item.is_read).length, items }));
    }
    if (request.method() === "POST" && url.pathname === "/api/notifications/read") {
      const ids = (request.postDataJSON() as { ids?: number[] }).ids;
      items = items.map((item) => (!ids || ids.includes(item.id) ? { ...item, is_read: true } : item));
      return route.fulfill(json({ updated: 1 }));
    }
    if (request.method() === "DELETE" && url.searchParams.get("all") === "true") {
      const deleted = items.length;
      items = [];
      return route.fulfill(json({ deleted }));
    }
    if (request.method() === "DELETE") {
      const id = Number(url.pathname.split("/").pop());
      items = items.filter((item) => item.id !== id);
      return route.fulfill(json({ id }));
    }
    return route.fallback();
  });

  await page.goto("/monitoring");
  // Le nombre d'alertes non lues est sur l'onglet.
  const tab = page.getByRole("tab", { name: /^Notifications/ });
  await expect(tab).toContainText("2");
  await tab.click();
  await expect(page).toHaveURL(/\/monitoring\?tab=notifications$/);
  await expect(page.getByText("2 non lue(s)")).toBeVisible();
  const list = page.getByRole("list", { name: "Notifications" });
  await expect(list.getByRole("listitem")).toHaveCount(3);
  await expect(list.getByRole("listitem").nth(0)).toContainText("alpha.example.org");
  await expect(list.getByRole("listitem").nth(0)).toContainText("Nouveau");
  await expect(list.getByRole("listitem").nth(0)).toContainText("Élevée");
  await expect(list.getByRole("listitem").nth(2)).not.toContainText("Nouveau");
  await expect(list.getByRole("link", { name: "Voir le scan" })).toHaveAttribute("href", "/scans/37");

  await page.getByRole("button", { name: "Marquer comme lue l'alerte de alpha.example.org" }).click();
  await expect(page.getByText("1 non lue(s)")).toBeVisible();
  await page.getByRole("button", { name: "Tout marquer comme lu" }).click();
  await expect(page.getByText("0 non lue(s)")).toBeVisible();
  await expect(page.getByRole("button", { name: "Tout marquer comme lu" })).toBeDisabled();

  await page.getByRole("button", { name: "Supprimer l'alerte de beta.example.org" }).click();
  await expect(list.getByRole("listitem")).toHaveCount(2);
  await page.getByRole("button", { name: "Vider" }).click();
  await expect(page.getByText("Aucune notification")).toBeVisible();
});

test("l'onglet Notifications est un lien profond qui survit au rechargement", async ({ page }) => {
  await page.goto("/monitoring?tab=notifications");
  await expect(page.getByRole("tab", { name: /^Notifications/ })).toHaveAttribute("aria-selected", "true");
  await page.reload();
  await expect(page.getByRole("tab", { name: /^Notifications/ })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Surveillances" }).click();
  await expect(page).toHaveURL(/\/monitoring$/);
});
