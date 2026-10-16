import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// Découpage du build par écran (router.tsx : React.lazy). Comme csp.test.ts, ces contrôles lisent
// le dernier build de domainrecon/web (généré, non versionné) et sont ignorés sans build :
// ils ne s'exécutent que si `npm run build` a eu lieu avant `npm run test`.
const BUILD_DIR = join(import.meta.dirname, "..", "..", "domainrecon", "web");
const hasBuild = existsSync(join(BUILD_DIR, "index.html"));

// Le build annonce ses tailles en kB de 1000 octets.
const KB = 1000;

function builtScripts(): string[] {
  return readdirSync(join(BUILD_DIR, "assets")).filter((name) => name.endsWith(".js"));
}

const size = (name: string) => statSync(join(BUILD_DIR, "assets", name)).size;

// Scripts que index.html charge d'emblée : le point d'entrée et ses dépendances préchargées.
function initialScripts(html: string): { entry: string; preloaded: string[] } {
  const entry = /<script[^>]*\btype="module"[^>]*\bsrc="\/assets\/([^"]+\.js)"/.exec(html)?.[1] ?? "";
  const preloaded = [...html.matchAll(/<link[^>]*\brel="modulepreload"[^>]*\bhref="\/assets\/([^"]+\.js)"/g)].map((m) => m[1]);
  return { entry, preloaded };
}

describe.skipIf(!hasBuild)("découpage du build par écran", () => {
  const html = hasBuild ? readFileSync(join(BUILD_DIR, "index.html"), "utf8") : "";

  it("le fichier JS principal reste nettement sous 600 Ko", () => {
    const { entry } = initialScripts(html);
    expect(entry).not.toBe("");
    expect(size(entry)).toBeLessThan(600 * KB);
  });

  it("chaque écran lourd est un fichier à part, absent du chargement initial", () => {
    const { entry, preloaded } = initialScripts(html);
    const loaded = [entry, ...preloaded];
    const scripts = builtScripts();
    for (const screen of ["FamilyPage", "TimelinePage", "SettingsPage", "HistoryPage", "MonitoringPage", "NetworkGraph", "GeoMap"]) {
      const chunk = scripts.find((name) => name.startsWith(`${screen}-`));
      expect(chunk, `fichier ${screen}-*.js`).toBeDefined();
      expect(loaded).not.toContain(chunk);
    }
  });

  it("l'écran d'une famille garde ses blocs les plus lourds (graphe réseau, carte) à part", () => {
    const family = builtScripts().find((name) => name.startsWith("FamilyPage-"));
    expect(family).toBeDefined();
    expect(size(family ?? "")).toBeLessThan(300 * KB);
  });

  it("le chargement initial (entrée et dépendances préchargées) pèse moins de 700 Ko", () => {
    const { entry, preloaded } = initialScripts(html);
    const total = [entry, ...preloaded].reduce((sum, name) => sum + size(name), 0);
    expect(total).toBeLessThan(700 * KB);
  });

  it("aucun fichier JS ne dépasse 600 Ko", () => {
    const tooBig = builtScripts().filter((name) => size(name) >= 600 * KB);
    expect(tooBig).toEqual([]);
  });
});
