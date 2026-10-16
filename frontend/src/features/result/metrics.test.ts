import { describe, expect, it } from "vitest";
import { allOk, makeLegacyScan, makeScan } from "../../test/fixtures";
import { familyModuleCount, moduleCount, scanAsn } from "./metrics";

describe("numéro d'AS du bandeau", () => {
  it("lit l'AS du module réseau étendu, avec ou sans le préfixe « AS »", () => {
    expect(scanAsn(makeScan())).toBe("AS15133");
    const bare = makeScan();
    bare.network_extended = { asn_info: { asn: "15133" } };
    expect(scanAsn(bare)).toBe("AS15133");
    const lower = makeScan();
    lower.network_extended = { asn_info: { asn: " as64500 Example " } };
    expect(scanAsn(lower)).toBe("AS64500");
  });

  it("se rabat sur la ligne d'AS de la géolocalisation, sinon null", () => {
    const geo = makeScan();
    geo.network_extended = {};
    expect(scanAsn(geo)).toBe("AS15133");
    const none = makeScan();
    none.network_extended = {};
    none.geo_data = { as_info: "Edgecast Inc." };
    expect(scanAsn(none)).toBeNull();
    expect(scanAsn(makeLegacyScan())).toBeNull();
  });
});

describe("compte des sous-domaines et des ports", () => {
  it("compte la liste d'un module mesuré", () => {
    const scan = makeScan();
    expect(moduleCount(scan, "subdomains")).toBe(3);
    expect(moduleCount(scan, "open_ports")).toBe(3);
  });

  it("préfère le total trouvé quand la liste des sous-domaines a été plafonnée", () => {
    const scan = makeScan({
      module_status: { ...allOk(), subdomains: { status: "ok", error: null, total_found: 1200 } },
    });
    expect(moduleCount(scan, "subdomains")).toBe(1200);
    // Un total plus petit que la liste ne la réduit jamais.
    const small = makeScan({ module_status: { ...allOk(), subdomains: { status: "ok", error: null, total_found: 1 } } });
    expect(moduleCount(small, "subdomains")).toBe(3);
  });

  it("n'invente jamais un zéro : échec, délai dépassé et sans objet valent null", () => {
    for (const status of ["failed", "timeout", "skipped"] as const) {
      const scan = makeScan({
        subdomains: [],
        open_ports: [],
        module_status: { ...allOk(), subdomains: { status, error: "x" }, open_ports: { status, error: "x" } },
      });
      expect(moduleCount(scan, "subdomains"), status).toBeNull();
      expect(moduleCount(scan, "open_ports"), status).toBeNull();
    }
  });

  it("un module mesuré qui n'a rien trouvé vaut bien 0", () => {
    const scan = makeScan({ subdomains: [], open_ports: [] });
    expect(moduleCount(scan, "subdomains")).toBe(0);
    expect(moduleCount(scan, "open_ports")).toBe(0);
  });
});

describe("modules mesurés d'une famille", () => {
  it("compte les modules qui ont rendu un résultat sur ceux de la famille", () => {
    const scan = makeScan();
    expect(familyModuleCount(scan, "web")).toEqual({ measured: 7, total: 7 });
    // Capture d'écran sans objet : un module sur deux.
    expect(familyModuleCount(scan, "identity")).toEqual({ measured: 1, total: 2 });
    expect(familyModuleCount(scan, "reputation")).toEqual({ measured: 0, total: 0 });
  });

  it("un module en échec ou hors délai n'est pas compté", () => {
    const scan = makeScan({
      module_status: { ...allOk(), waf: { status: "timeout", error: "x" }, cors: { status: "failed", error: "x" } },
    });
    expect(familyModuleCount(scan, "web")).toEqual({ measured: 5, total: 7 });
  });
});
