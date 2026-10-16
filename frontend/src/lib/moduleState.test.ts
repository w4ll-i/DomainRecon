import { describe, expect, it } from "vitest";
import type { ScanResponse } from "../api/types";
import i18n from "../i18n";
import { failedModules, moduleState, scanModuleState, unavailableText } from "./moduleState";

const withStatus = (module_status: ScanResponse["module_status"]) => ({ module_status });

describe("statut honnête d'un module", () => {
  it("un module « ok » est mesuré", () => {
    expect(moduleState(withStatus({ cors: { status: "ok", error: null } }), "cors")).toEqual({ status: "ok", error: null });
  });

  it.each(["failed", "timeout", "skipped"] as const)("reprend le statut « %s » et sa raison", (status) => {
    const scan = withStatus({ whois_data: { status, error: "raison" } });
    expect(moduleState(scan, "whois_data")).toEqual({ status, error: "raison" });
  });

  it("scan antérieur à module_status : measured=false vaut échec, ou sans objet si skipped", () => {
    expect(moduleState(withStatus({}), "waf", { measured: false, error: "HTTP injoignable" })).toEqual({
      status: "failed",
      error: "HTTP injoignable",
    });
    expect(moduleState(withStatus({}), "email_security", { measured: false, skipped: true, error: null })).toEqual({
      status: "skipped",
      error: null,
    });
    expect(moduleState(withStatus({}), "waf", { detected: false })).toEqual({ status: "ok", error: null });
  });

  it("scan antérieur : un objet vide (colonne par défaut) est « non mesuré », comme dans le score", () => {
    const scan = withStatus({ cors: { status: "ok", error: null } });
    expect(moduleState(scan, "cors", {})).toEqual({ status: "failed", error: null });
    expect(moduleState(withStatus({}), "security_headers", {})).toEqual({ status: "failed", error: null });
    // Une liste vide reste « rien trouvé » ; un objet renseigné reste mesuré.
    expect(moduleState(withStatus({}), "technologies", [])).toEqual({ status: "ok", error: null });
    expect(moduleState(withStatus({}), "waf", { detected: false })).toEqual({ status: "ok", error: null });
    // Sans valeur fournie : seul module_status fait foi.
    expect(moduleState(scan, "cors")).toEqual({ status: "ok", error: null });
  });

  it("ancien takeover « sans objet » faute d'énumération : non vérifié (échec)", () => {
    const scan = withStatus({
      subdomain_takeover: { status: "skipped", error: "Énumération des sous-domaines en échec (crt.sh)" },
    });
    expect(moduleState(scan, "subdomain_takeover").status).toBe("failed");
  });

  it("scan sans module_status : un takeover vide n'est mesuré que si le score l'a mesuré", () => {
    // Colonne ajoutée à NULL aux anciens scans : une liste vide ne prouve rien.
    expect(moduleState(withStatus({}), "subdomain_takeover", [])).toEqual({ status: "failed", error: null });
    const measured = { security_score: { breakdown: { takeover: { score: 5, max: 5, measured: true } } } };
    expect(moduleState({ module_status: {}, ...measured }, "subdomain_takeover", [])).toEqual({ status: "ok", error: null });
    const unmeasured = { security_score: { breakdown: { takeover: { score: 0, max: 5, measured: false } } } };
    expect(moduleState({ module_status: {}, ...unmeasured }, "subdomain_takeover", [])).toEqual({ status: "failed", error: null });
    // Des entrées enregistrées, ou un module_status, font foi.
    expect(moduleState(withStatus({}), "subdomain_takeover", [{ subdomain: "a.example.com" }])).toEqual({ status: "ok", error: null });
    expect(moduleState(withStatus({ subdomain_takeover: { status: "ok", error: null } }), "subdomain_takeover", [])).toEqual({
      status: "ok",
      error: null,
    });
  });

  it("la capture se lit sur screenshot_path", () => {
    const scan = { module_status: {}, screenshot_path: null } as unknown as ScanResponse;
    expect(scanModuleState(scan, "screenshot")).toEqual({ status: "ok", error: null });
  });

  it("liste les modules sans résultat (échec ou délai dépassé) dans l'ordre", () => {
    const scan = withStatus({
      whois_data: { status: "failed", error: "WHOIS injoignable" },
      screenshot: { status: "skipped", error: "Chromium absent" },
      network_extended: { status: "timeout", error: "Délai dépassé (60 s)" },
    });
    expect(failedModules(scan)).toEqual([
      { name: "whois_data", status: "failed", error: "WHOIS injoignable" },
      { name: "network_extended", status: "timeout", error: "Délai dépassé (60 s)" },
    ]);
  });

  it("met en texte un statut et sa raison", () => {
    expect(unavailableText({ status: "timeout", error: "Délai dépassé (60 s)" }, i18n.t)).toBe(
      "Non mesuré (délai dépassé) : Délai dépassé (60 s)",
    );
    expect(unavailableText({ status: "skipped", error: null }, i18n.t)).toBe("Sans objet");
  });
});
