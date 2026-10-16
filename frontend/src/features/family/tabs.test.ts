import { describe, expect, it, vi } from "vitest";
import type { Finding } from "../../api/types";
import en from "../../i18n/en.json";
import fr from "../../i18n/fr.json";
import { FAMILY_KEYS, FAMILY_MODULES } from "../../lib/families";
import { activeFamilyTab, FAMILY_TABS, tabFindings } from "./tabs";

// Le registre importe les composants de module, qui chargent Cytoscape et Leaflet
// (inutiles ici : on n'en rend aucun).
vi.mock("cytoscape", () => ({ default: vi.fn() }));
vi.mock("leaflet", () => ({}));
vi.mock("leaflet/dist/leaflet.css", () => ({}));

type Catalog = { [key: string]: string | Catalog };
const lookup = (catalog: Catalog, key: string): unknown => key.split(".").reduce<unknown>((node, part) => (node as Catalog | undefined)?.[part], catalog);

const finding = (severity: Finding["severity"], module: Finding["module"] = "security_headers"): Finding => ({
  severity,
  family: "web",
  module,
  message: "constat",
});

describe("registre des onglets de famille", () => {
  it("chaque module de chaque famille a un onglet et un seul, dans la bonne famille", () => {
    for (const family of FAMILY_KEYS) {
      const modules = FAMILY_TABS[family].flatMap((tab) => (tab.module ? [tab.module] : []));
      expect([...modules].sort(), family).toEqual([...FAMILY_MODULES[family]].sort());
    }
  });

  it("les clés d'onglet sont uniques dans une famille et sûres dans une adresse", () => {
    for (const family of FAMILY_KEYS) {
      const keys = FAMILY_TABS[family].map((tab) => tab.key);
      expect(new Set(keys).size, family).toBe(keys.length);
      for (const key of keys) expect(key).toMatch(/^[a-z_]+$/);
    }
  });

  it("les seuls onglets sans module sont la carte réseau (DNS) et les notes (identité)", () => {
    const own = FAMILY_KEYS.flatMap((family) => FAMILY_TABS[family].filter((tab) => !tab.module).map((tab) => `${family}/${tab.key}`));
    expect(own).toEqual(["dns/graph", "identity/notes"]);
    // La carte réseau ouvre la famille DNS, comme avant (page longue).
    expect(FAMILY_TABS.dns[0].key).toBe("graph");
    // La localisation ouvre la famille Réseau (la carte géographique).
    expect(FAMILY_TABS.network[0].key).toBe("geo_data");
  });

  it("chaque libellé d'onglet existe en français et en anglais", () => {
    for (const family of FAMILY_KEYS) {
      for (const tab of FAMILY_TABS[family]) {
        expect(lookup(fr as Catalog, tab.labelKey), `${tab.labelKey} (fr)`).toEqual(expect.any(String));
        expect(lookup(en as Catalog, tab.labelKey), `${tab.labelKey} (en)`).toEqual(expect.any(String));
      }
    }
  });

  it("la réputation n'a pas d'onglet tant qu'elle n'a pas de module", () => {
    expect(FAMILY_TABS.reputation).toEqual([]);
    expect(activeFamilyTab("reputation", undefined)).toBeUndefined();
    expect(activeFamilyTab("reputation", "waf")).toBeUndefined();
  });
});

describe("onglet actif", () => {
  it("celui de l'adresse, sinon le premier", () => {
    expect(activeFamilyTab("web", "cors")?.key).toBe("cors");
    expect(activeFamilyTab("web", undefined)?.key).toBe("security_headers");
    expect(activeFamilyTab("web", "inconnu")?.key).toBe("security_headers");
    // Un module d'une autre famille n'existe pas dans celle-ci.
    expect(activeFamilyTab("web", "open_ports")?.key).toBe("security_headers");
    expect(activeFamilyTab("dns", "graph")?.key).toBe("graph");
    expect(activeFamilyTab("identity", "notes")?.key).toBe("notes");
  });
});

describe("pastille de constats d'un onglet", () => {
  const [headers, cookies] = FAMILY_TABS.web;
  const notes = FAMILY_TABS.identity[2];

  it("compte les constats du module et prend le ton du plus grave", () => {
    expect(tabFindings([finding("low")], headers)).toEqual({ count: 1, tone: "neutral" });
    expect(tabFindings([finding("medium")], headers)).toEqual({ count: 1, tone: "warning" });
    expect(tabFindings([finding("low"), finding("medium")], headers)).toEqual({ count: 2, tone: "warning" });
    expect(tabFindings([finding("high")], headers)).toEqual({ count: 1, tone: "critical" });
    expect(tabFindings([finding("medium"), finding("critical"), finding("low")], headers)).toEqual({ count: 3, tone: "critical" });
  });

  it("ne compte que les constats du module de l'onglet", () => {
    expect(tabFindings([finding("high", "cookie_security"), finding("low")], headers)).toEqual({ count: 1, tone: "neutral" });
    expect(tabFindings([finding("high", "cookie_security")], cookies)).toEqual({ count: 1, tone: "critical" });
  });

  it("aucune pastille sans constat, sans liste ou pour un onglet qui n'est pas un module", () => {
    expect(tabFindings([], headers)).toBeNull();
    expect(tabFindings([finding("high", "cors")], headers)).toBeNull();
    expect(tabFindings(null, headers)).toBeNull();
    expect(tabFindings(undefined, headers)).toBeNull();
    expect(tabFindings([finding("high")], notes)).toBeNull();
  });
});
