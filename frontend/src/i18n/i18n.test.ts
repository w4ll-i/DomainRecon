import { describe, expect, it } from "vitest";
import en from "./en.json";
import fr from "./fr.json";
import i18n, { currentLang, detectLang, setLang } from "./index";

type Catalog = { [key: string]: string | Catalog };

function flatten(catalog: Catalog, prefix = ""): Record<string, string> {
  const flat: Record<string, string> = {};
  for (const [key, value] of Object.entries(catalog)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (typeof value === "string") flat[path] = value;
    else Object.assign(flat, flatten(value, path));
  }
  return flat;
}

const placeholders = (text: string) => [...text.matchAll(/{{\s*([\w.]+)\s*}}/g)].map((m) => m[1]).sort();

const flatFr = flatten(fr as Catalog);
const flatEn = flatten(en as Catalog);

// Tout littéral "espace.clé" des sources (hors tests) doit exister : les clés
// construites dynamiquement sont vérifiées par lib/families.test.ts.
const NAMESPACES =
  "common|nav|shell|server|lang|errors|token|toast|grade|scanStatus|moduleStatus|familyState|severity|confidence|families|modules|unavailable|newScan|live|result|findings|score|radar|metrics|family|headerStatus|verdict|web|tls|email|dns|network|identity|history|timeline|settings|notFound|generic|palette|category|scanProfile|export|understand|fix|dashboard|compare|batch|monitoring|notifications|glossary|help|onboarding|uninstall|tabsNav";
const KEY_LITERAL = new RegExp(`"((?:${NAMESPACES})\\.[A-Za-z0-9_.-]+)"`, "g");
const sources = import.meta.glob(["../**/*.ts", "../**/*.tsx", "!../**/*.test.ts", "!../**/*.test.tsx"], {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

describe("catalogues de l'interface", () => {
  it("FR et EN ont exactement les mêmes clés", () => {
    expect(Object.keys(flatEn).sort()).toEqual(Object.keys(flatFr).sort());
  });

  it("chaque clé a les mêmes paramètres en FR et en EN", () => {
    for (const key of Object.keys(flatFr)) {
      expect([key, placeholders(flatEn[key] ?? "")]).toEqual([key, placeholders(flatFr[key])]);
    }
  });

  it("aucune traduction n'est vide", () => {
    expect(Object.entries(flatFr).filter(([, v]) => !v.trim())).toEqual([]);
    expect(Object.entries(flatEn).filter(([, v]) => !v.trim())).toEqual([]);
  });

  it("toute clé écrite en toutes lettres dans le code existe", () => {
    const missing: string[] = [];
    for (const [file, code] of Object.entries(sources)) {
      for (const match of code.matchAll(KEY_LITERAL)) {
        if (!(match[1] in flatFr)) missing.push(`${file} : ${match[1]}`);
      }
    }
    expect(missing).toEqual([]);
  });
});

describe("langue de l'interface", () => {
  it("détecte la langue : choix mémorisé, sinon navigateur (fr* → fr, sinon en)", () => {
    expect(detectLang(null, "fr-FR")).toBe("fr");
    expect(detectLang(null, "fr")).toBe("fr");
    expect(detectLang(null, "en-US")).toBe("en");
    expect(detectLang(null, "de-DE")).toBe("en");
    expect(detectLang(null, undefined)).toBe("en");
    expect(detectLang("en", "fr-FR")).toBe("en");
    expect(detectLang("xx", "fr-FR")).toBe("fr");
  });

  it("change de langue, la mémorise et met à jour <html lang>", async () => {
    await setLang("en");
    expect(currentLang()).toBe("en");
    expect(i18n.t("nav.newScan")).toBe("New scan");
    expect(window.localStorage.getItem("domainrecon.lang")).toBe("en");
    expect(document.documentElement.lang).toBe("en");
    await setLang("fr");
    expect(i18n.t("nav.newScan")).toBe("Nouveau scan");
  });
});
