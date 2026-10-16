import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import indexHtml from "../index.html?raw";

// Toutes les sources de l'application (hors tests) : la CSP stricte servie par
// FastAPI refuse styles et scripts en ligne, et l'interface n'injecte jamais
// de HTML brut.
const sources = import.meta.glob(["./**/*.ts", "./**/*.tsx", "!./**/*.test.ts", "!./**/*.test.tsx"], {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

const FORBIDDEN: Array<[string, RegExp]> = [
  ["attribut style", /\sstyle=\{/],
  ["style posé par script", /setAttribute\(\s*["'`]style["'`]|createElement\(\s*["'`]style["'`]/],
  ["HTML brut", /dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML/],
  // Gestionnaires HTML en ligne (onclick="…", setAttribute("onerror", …)) ; les props React (onClick={…}) restent permises.
  ["gestionnaire d'événement en ligne", /\son[a-z]+\s*=\s*["'`]|setAttribute\(\s*["'`]on[a-z]+["'`]/],
  ["évaluation de code", /\beval\(|new Function\(/],
  // Anciennes origines de l'interface (CDN, polices, logo) : tout est désormais dans le bundle.
  ["ressource externe", /cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|fonts\.googleapis\.com|fonts\.gstatic\.com|i\.ibb\.co/],
];

// Page HTML sans script ni style en ligne, sans gestionnaire d'événement ni ressource externe.
function expectNoInlineCode(html: string): void {
  expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/);
  expect(html).not.toMatch(/<style/);
  expect(html).not.toMatch(/\sstyle=/);
  expect(html).not.toMatch(/\son[a-z]+\s*=/);
  expect(html).not.toMatch(/(?:src|href)="https?:/);
}

describe("compatibilité avec la CSP stricte", () => {
  it("parcourt bien les sources de l'application", () => {
    // Un glob qui ne trouverait rien rendrait tous les contrôles ci-dessous vacuement verts.
    expect(Object.keys(sources)).toContain("./app/AppShell.tsx");
  });

  it.each(FORBIDDEN)("aucune source n'utilise : %s", (_label, pattern) => {
    const offenders = Object.entries(sources)
      .filter(([, code]) => pattern.test(code))
      .map(([file]) => file);
    expect(offenders).toEqual([]);
  });

  it("index.html ne contient ni script ni style en ligne ni ressource externe", () => {
    expectNoInlineCode(indexHtml);
  });

  it("index.html déclare un color-scheme neutre (clair et sombre), pas figé sur le sombre", () => {
    // Avant le CSS, un color-scheme figé sur « dark » peint un fond sombre : flash en thème clair.
    // tokens.css fixe ensuite color-scheme selon le thème appliqué.
    expect(indexHtml).toMatch(/<meta\s+name="color-scheme"\s+content="light dark"/);
    expect(indexHtml).not.toMatch(/name="color-scheme"\s+content="dark"/);
  });
});

// Le BUILD produit (domainrecon/web, servi par FastAPI) : c'est lui que la CSP juge.
// Un bundleur peut y réintroduire ce que les sources n'ont pas (police ou style
// intégrés en data:, balise en ligne, ressource externe).
//
// LIMITE : domainrecon/web est généré (non versionné) et ces tests ne lancent pas le
// build. Sans build présent, les contrôles ci-dessous sont ignorés ; ils ne
// s'exécutent que si `npm run build` a eu lieu avant `npm run test` (et vérifient
// alors le dernier build en date, pas forcément celui des sources actuelles). Dans la
// CI, `npm run test` précède `npm run build` : y ajouter ce contrôle exige de les inverser.
const BUILD_DIR = join(import.meta.dirname, "..", "..", "domainrecon", "web");
const hasBuild = existsSync(join(BUILD_DIR, "index.html"));

function buildFiles(extension: string): string[] {
  const found: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.name.endsWith(extension)) found.push(path);
    }
  };
  walk(join(BUILD_DIR, "assets"));
  return found;
}

// Police intégrée en data: : refusée par font-src 'self' (les polices sont des fichiers de /assets).
const DATA_FONT = /data:(?:font\/|application\/(?:x-)?font|application\/vnd\.ms-fontobject)/i;

describe.skipIf(!hasBuild)("compatibilité du build avec la CSP stricte", () => {
  it("index.html construit : ni script ni style en ligne ni ressource externe", () => {
    const html = readFileSync(join(BUILD_DIR, "index.html"), "utf8");
    // Le point d'entrée est bien un script externe (la garde ne tourne pas à vide).
    expect(html).toMatch(/<script[^>]*\bsrc="\/assets\//);
    expectNoInlineCode(html);
  });

  it("les feuilles de style construites n'intègrent aucune police en data: ni ressource externe", () => {
    const sheets = buildFiles(".css");
    expect(sheets.length).toBeGreaterThan(0);
    let fontFaces = 0;
    for (const file of sheets) {
      const css = readFileSync(file, "utf8");
      const blocks = css.match(/@font-face\s*\{[^}]*\}/g) ?? [];
      fontFaces += blocks.length;
      // Une police par fichier : aucune @font-face ne porte une source en data:.
      expect(blocks.filter((block) => /data:/i.test(block))).toEqual([]);
      expect(css).not.toMatch(DATA_FONT);
      expect(css).not.toMatch(/url\(\s*["']?https?:|@import\s+(?:url\(\s*)?["']?https?:/i);
    }
    expect(fontFaces).toBeGreaterThan(0);
  });

  it("les scripts construits n'intègrent aucune police en data:", () => {
    const scripts = buildFiles(".js");
    expect(scripts.length).toBeGreaterThan(0);
    const offenders = scripts.filter((file) => DATA_FONT.test(readFileSync(file, "utf8")));
    expect(offenders).toEqual([]);
  });
});
