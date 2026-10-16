import { describe, expect, it } from "vitest";
import type { ModulesResponse } from "../api/types";
import { makeScan } from "../test/fixtures";
import { buildCatalog, humanizeKey, moduleLabel, STATIC_CATALOG } from "./catalog";
import { MODULE_NAMES } from "./families";
import { failedModules, moduleState, scanModuleState } from "./moduleState";

const help = { title: "Fuites HIBP", checks: "Comptes du domaine dans des fuites", why: "Mots de passe réutilisés" };
const response: ModulesResponse = {
  families: ["web", "tls", "email", "dns", "network", "identity", "reputation", "leaks"],
  modules: [
    { name: "security_headers", family: "web", category: "passif", requires_authorization: false, help: { title: "En-têtes", checks: "", why: "" } },
    { name: "hibp", family: "leaks", category: "cle_api", requires_authorization: false, criteria: [{ criterion: "hibp", weight: 5 }], help },
    { name: "dnsbl", family: "reputation", category: "passif", requires_authorization: false, help: { title: "DNSBL", checks: "", why: "" } },
    { name: "inconnue", family: "famille_future", category: "passif", requires_authorization: false, help: { title: "", checks: "", why: "" } },
  ],
};

describe("catalogue des modules", () => {
  it("repli statique : les 18 modules historiques, dans l'ordre d'exécution", () => {
    expect(STATIC_CATALOG.live).toBe(false);
    expect(STATIC_CATALOG.moduleNames).toEqual(MODULE_NAMES);
    expect(STATIC_CATALOG.total).toBe(18);
    expect(STATIC_CATALOG.modules("dns")).toEqual(["dns_records", "subdomains", "subdomain_takeover", "reverse_dns"]);
    expect(STATIC_CATALOG.modules("leaks")).toEqual([]);
    expect(buildCatalog(undefined)).toBe(STATIC_CATALOG);
    expect(buildCatalog({ modules: [], families: [] })).toBe(STATIC_CATALOG);
  });

  it("construit familles, modules, titres et critères depuis la réponse du serveur", () => {
    const catalog = buildCatalog(response);
    expect(catalog.live).toBe(true);
    expect(catalog.families).toContain("leaks");
    expect(catalog.modules("leaks")).toEqual(["hibp"]);
    expect(catalog.modules("reputation")).toEqual(["dnsbl"]);
    expect(catalog.familyOf("hibp")).toBe("leaks");
    expect(catalog.title("hibp")).toBe("Fuites HIBP");
    // Une famille inconnue de l'interface est écartée, pas affichée.
    expect(catalog.moduleNames).not.toContain("inconnue");
    // Critères du barème : historiques + ceux déclarés par les modules.
    expect(catalog.criteria("leaks")).toEqual(["hibp"]);
    expect(catalog.criteria("tls")).toEqual(["tls"]);
  });

  it("libellé : traduction de l'interface, sinon titre du catalogue, sinon clé lisible", () => {
    const catalog = buildCatalog(response);
    const t = (key: string, options?: Record<string, unknown>) => (key === "modules.waf" ? "WAF / CDN" : String(options?.defaultValue ?? key));
    expect(moduleLabel(t, catalog, "waf")).toBe("WAF / CDN");
    expect(moduleLabel(t, catalog, "hibp")).toBe("Fuites HIBP");
    expect(moduleLabel(t, catalog, "tls_deep")).toBe("Tls deep");
    expect(humanizeKey("github_leaks")).toBe("Github leaks");
  });
});

describe("statut d'un module du registre", () => {
  const scan = makeScan({
    modules: {
      hibp: { status: "ok", data: { measured: true, error: null, accounts: 2 }, duration: 1.2, error: null },
      dnsbl: { status: "failed", data: { measured: false, error: "Service indisponible" }, duration: 0.5, error: "Service indisponible" },
      wayback: { status: "ok", data: { measured: false, skipped: true, error: "Adresse IP" }, duration: 0, error: null },
    },
    modules_launched: ["hibp", "dnsbl", "wayback"],
  });

  it("lit le résultat dans scan.modules, sans jamais lire un échec comme « rien trouvé »", () => {
    expect(scanModuleState(scan, "hibp")).toEqual({ status: "ok", error: null });
    expect(scanModuleState(scan, "dnsbl")).toEqual({ status: "failed", error: "Service indisponible" });
    expect(scanModuleState(scan, "wayback")).toEqual({ status: "skipped", error: "Adresse IP" });
  });

  it("module absent du scan : non lancé (jamais mesuré)", () => {
    expect(scanModuleState(scan, "leakix")).toEqual({ status: "not_launched", error: null });
  });

  it("module historique hors de la liste des modules lancés : non lancé", () => {
    const quick = makeScan({ modules_launched: ["dns_records"], module_status: {} });
    expect(moduleState(quick, "cors")).toEqual({ status: "not_launched", error: null });
    expect(scanModuleState(makeScan(), "cors").status).toBe("ok");
  });

  it("liste les modules du registre en échec avec les historiques", () => {
    expect(failedModules(scan).map((m) => m.name)).toEqual(["dnsbl"]);
  });
});
