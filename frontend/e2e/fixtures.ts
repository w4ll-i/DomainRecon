import { type APIRequestContext, expect, test as base } from "@playwright/test";

// Clé de localStorage qui retient que la visite guidée du premier lancement a été faite ou écartée
// (src/lib/storage.ts).
export const ONBOARDING_KEY = "domainrecon.onboarded";

// Bruit réseau voulu par les scénarios (400/404 attendus) : Chromium le journalise en
// console.error sans que ce soit une erreur de l'application.
const NETWORK_NOISE = /^Failed to load resource/;

// Chaque test échoue sur une violation de la CSP stricte, une erreur
// JavaScript non attrapée, un console.error applicatif (une erreur de rendu
// attrapée par l'errorElement du routeur ne produit que celui-ci) ou une
// requête vers un hôte externe : l'application fonctionne hors ligne (polices et
// carte du monde embarquées).
//
// L'accueil du premier lancement (fenêtre modale qui propose la visite guidée) recouvre l'écran et capte le
// focus : sans choix mémorisé, aucun clic des autres scénarios n'atteindrait l'interface. Par
// défaut, chaque test part donc d'un navigateur qui l'a déjà vu ; onboarding.spec.ts, lui, part
// d'un premier lancement (`test.use({ onboarding: "first-run" })`).
export const test = base.extend<{ guard: void; onboarding: "seen" | "first-run"; onboardingSeen: void }>({
  onboarding: ["seen", { option: true }],
  onboardingSeen: [
    async ({ page, onboarding }, use) => {
      if (onboarding === "seen") {
        await page.addInitScript((key) => {
          try {
            window.localStorage.setItem(key, "1");
          } catch {
            // Stockage indisponible (page vierge) : l'accueil s'affichera, le test le dira.
          }
        }, ONBOARDING_KEY);
      }
      await use();
    },
    { auto: true },
  ],
  guard: [
    async ({ page }, use) => {
      const problems: string[] = [];
      page.on("console", (message) => {
        const text = message.text();
        if (/Content[- ]Security[- ]Policy/i.test(text)) problems.push(text);
        else if (message.type() === "error" && !NETWORK_NOISE.test(text)) problems.push(`console.error : ${text}`);
      });
      page.on("pageerror", (error) => problems.push(`Erreur JavaScript : ${error.message}`));
      await page.route(
        (url) => !["127.0.0.1", "localhost"].includes(url.hostname) && url.protocol.startsWith("http"),
        (route) => {
          problems.push(`Requête externe : ${route.request().url()}`);
          return route.abort();
        },
      );
      await use();
      expect(problems, "violations CSP, erreurs JavaScript ou console.error").toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

// Identifiant du scan le plus récent d'un domaine (correspondance exacte).
export async function scanIdFor(request: APIRequestContext, domain: string): Promise<number> {
  const response = await request.get(`/api/history?domain=${encodeURIComponent(domain)}&limit=200`);
  expect(response.ok()).toBeTruthy();
  const body = (await response.json()) as { scans: Array<{ id: number; domain: string }> };
  const scan = body.scans.find((item) => item.domain === domain);
  if (!scan) throw new Error(`Aucun scan seedé pour ${domain}`);
  return scan.id;
}

// Lance un scan (faux scanner) par l'API et attend son enregistrement ; renvoie
// l'identifiant du scan. Sert aux tests qui détruisent ce qu'ils ont créé.
export async function createScan(request: APIRequestContext, domain: string): Promise<number> {
  const started = await request.post("/api/scans", { data: { domain } });
  expect(started.status()).toBe(202);
  const { id } = (await started.json()) as { id: string };
  const job = async () =>
    (await (await request.get(`/api/scans/${id}`)).json()) as { status: string; scan_id: number | null };
  await expect.poll(async () => (await job()).status, { timeout: 20_000 }).toBe("done");
  const scanId = (await job()).scan_id;
  if (scanId === null) throw new Error(`Tâche ${id} terminée sans scan enregistré`);
  return scanId;
}

// Supprime tous les scans d'un domaine (correspondance exacte) : les scénarios qui créent des
// scans rangent derrière eux, la base du serveur de test reste celle du départ.
export async function deleteScansOf(request: APIRequestContext, domain: string): Promise<number> {
  const response = await request.get(`/api/history?domain=${encodeURIComponent(domain)}&limit=200`);
  expect(response.ok()).toBeTruthy();
  const body = (await response.json()) as { scans: Array<{ id: number; domain: string }> };
  const own = body.scans.filter((scan) => scan.domain === domain);
  for (const scan of own) {
    const deleted = await request.delete(`/api/scan/${scan.id}`);
    expect(deleted.ok()).toBeTruthy();
  }
  return own.length;
}

// Suffixe court et unique : des noms de domaine neufs à chaque exécution, sur un serveur réutilisé.
export const uniqueSuffix = (): string => `${Date.now().toString(36)}${Math.floor(Math.random() * 1296).toString(36)}`;
