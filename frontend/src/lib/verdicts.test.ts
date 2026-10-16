import { describe, expect, it } from "vitest";
import type { ScanResponse } from "../api/types";
import {
  dnsValueText,
  emailWithoutMail,
  headerChecks,
  isNullMx,
  neighborsCount,
  sharedCdnIp,
  subdomainCount,
  subdomainResolution,
  takeoverConfirmed,
  takeoverTested,
  takeoverVerdict,
  tlsVerdict,
  whoisOtherDomain,
  whoisStatuses,
} from "./verdicts";

// Scan minimal : chaque test n'y met que ce qu'il vérifie.
const scan = (overrides: Partial<ScanResponse>) =>
  ({ domain: "example.com", module_status: {}, subdomains: [], subdomain_takeover: [], ...overrides }) as ScanResponse;

describe("verdict TLS", () => {
  it("certificat valide : jours restants et niveau", () => {
    expect(tlsVerdict(scan({ tls_certificate: { valid: true, days_remaining: 90 } }))).toMatchObject({
      level: "ok",
      label: "verdict.tls.validDays",
      params: { days: 90 },
    });
    expect(tlsVerdict(scan({ tls_certificate: { valid: true, days_remaining: 20 } })).level).toBe("warning");
    expect(tlsVerdict(scan({ tls_certificate: { valid: true, days_remaining: 3 } })).level).toBe("critical");
  });

  it("pas de HTTPS et certificat invalide sont des constats, pas des mesures manquées", () => {
    expect(tlsVerdict(scan({ tls_certificate: { measured: true, https: false, verify_error: "port 443 fermé" } }))).toEqual({
      level: "critical",
      label: "verdict.tls.noHttps",
      detail: "port 443 fermé",
    });
    expect(tlsVerdict(scan({ tls_certificate: { measured: true, https: true, valid: false, verify_error: "expiré" } })).label).toBe(
      "verdict.tls.invalid",
    );
    // Ancien scan : l'échec de vérification était rangé en erreur.
    expect(tlsVerdict(scan({ tls_certificate: { error: "certificate verify failed: self signed" } })).label).toBe(
      "verdict.tls.invalid",
    );
  });

  it("module en échec : non mesuré avec sa raison", () => {
    const verdict = tlsVerdict(
      scan({
        tls_certificate: { measured: false, error: "Hôte injoignable" },
        module_status: { tls_certificate: { status: "failed", error: "Hôte injoignable" } },
      }),
    );
    expect(verdict).toEqual({ level: "na", label: "moduleStatus.failed", detail: "Hôte injoignable" });
  });
});

describe("takeover", () => {
  it("confirmé : champ confirmed, ou ancienne règle risque élevé + empreinte", () => {
    expect(takeoverConfirmed({ subdomain: "a", confirmed: true })).toBe(true);
    expect(takeoverConfirmed({ subdomain: "a", confirmed: false, risk: "high" })).toBe(false);
    expect(takeoverConfirmed({ subdomain: "a", risk: "high" })).toBe(true);
    expect(takeoverConfirmed({ subdomain: "a", risk: "medium" })).toBe(false);
  });

  it("compte les sous-domaines testés (noms distincts, 15 au plus)", () => {
    const subs = Array.from({ length: 20 }, (_, i) => ({ subdomain: `s${i}.example.com` }));
    expect(takeoverTested(scan({ subdomains: subs, module_status: { subdomain_takeover: { status: "ok", error: null } } }))).toBe(15);
    expect(takeoverTested(scan({ subdomains: subs }))).toBeNull();
  });

  it("n'annonce jamais « aucun takeover » pour un module non vérifié", () => {
    const failed = scan({ module_status: { subdomain_takeover: { status: "failed", error: "Non vérifié" } } });
    expect(takeoverVerdict(failed)).toEqual({ level: "warning", label: "verdict.takeover.notChecked", detail: "Non vérifié" });
    const found = scan({ subdomain_takeover: [{ subdomain: "a", confirmed: true }, { subdomain: "b", confirmed: false }] });
    expect(takeoverVerdict(found)).toEqual({
      level: "critical",
      label: "verdict.takeover.found",
      params: { confirmed: 1, toCheck: 1 },
    });
  });

  it("scan sans module_status : « aucun takeover » seulement si le score l'a mesuré", () => {
    // Colonne ajoutée à NULL aux anciens scans : liste vide indiscernable d'un « rien trouvé ».
    expect(takeoverVerdict(scan({}))).toEqual({ level: "warning", label: "verdict.takeover.notChecked", detail: null });
    const unmeasured = { takeover: { score: 0, max: 5, measured: false } };
    expect(takeoverVerdict(scan({ security_score: { breakdown: unmeasured } })).label).toBe("verdict.takeover.notChecked");
    const measured = { takeover: { score: 5, max: 5, measured: true } };
    expect(takeoverVerdict(scan({ security_score: { breakdown: measured } })).label).toBe("verdict.takeover.none");
    // Avec module_status, c'est lui qui fait foi (scan récent).
    const ok = scan({ module_status: { subdomain_takeover: { status: "ok", error: null } } });
    expect(takeoverVerdict(ok).label).toBe("verdict.takeover.none");
  });

  it("n'affiche jamais un compteur à zéro (« 0 confirmé(s) »)", () => {
    const onlyConfirmed = scan({ subdomain_takeover: [{ subdomain: "a", confirmed: true }, { subdomain: "b", confirmed: true }] });
    expect(takeoverVerdict(onlyConfirmed)).toEqual({
      level: "critical",
      label: "verdict.takeover.confirmedOnly",
      params: { count: 2 },
    });
    const onlyToCheck = scan({ subdomain_takeover: [{ subdomain: "a", confirmed: false }] });
    expect(takeoverVerdict(onlyToCheck)).toEqual({
      level: "warning",
      label: "verdict.takeover.toCheckOnly",
      params: { count: 1 },
    });
  });
});

describe("sous-domaines et DNS", () => {
  it("prend le total trouvé quand la liste enregistrée est plafonnée", () => {
    const subs = [{ subdomain: "a.example.com" }, { subdomain: "b.example.com" }];
    expect(subdomainCount(scan({ subdomains: subs }))).toEqual({ shown: 2, total: 2 });
    expect(
      subdomainCount(scan({ subdomains: subs, module_status: { subdomains: { status: "ok", error: null, total_found: 250 } } })),
    ).toEqual({ shown: 2, total: 250 });
  });

  it("qualifie la résolution d'un sous-domaine", () => {
    expect(subdomainResolution({ subdomain: "a", ip: "1.2.3.4", wildcard: true })).toEqual({ kind: "wildcard", ip: "1.2.3.4" });
    expect(subdomainResolution({ subdomain: "a", ip: "1.2.3.4" })).toEqual({ kind: "resolved", ip: "1.2.3.4" });
    expect(subdomainResolution({ subdomain: "a", resolution: "not_tested" })).toEqual({ kind: "untested", ip: null });
    expect(subdomainResolution({ subdomain: "a" })).toEqual({ kind: "unresolved", ip: null });
  });

  it("reconnaît le MX nul et met en texte les enregistrements", () => {
    expect(isNullMx({ priority: 0, value: ".", null_mx: true })).toBe(true);
    expect(isNullMx({ priority: 0, value: "" })).toBe(true);
    expect(isNullMx({ priority: 10, value: "mx.example.com" })).toBe(false);
    expect(dnsValueText({ priority: 10, value: "mx.example.com" }, "(MX nul)")).toBe("10 mx.example.com");
    expect(dnsValueText({ priority: 0, value: ".", null_mx: true }, "(MX nul)")).toBe("0 . (MX nul)");
    expect(dnsValueText({ mname: "ns1", rname: "hostmaster", serial: 3 }, "")).toBe("ns1 hostmaster");
    expect(dnsValueText("93.184.216.34", "")).toBe("93.184.216.34");
  });
});

describe("WHOIS, CDN, e-mail, en-têtes, voisins", () => {
  it("signale un WHOIS fait sur un autre domaine et nettoie les statuts EPP", () => {
    expect(whoisOtherDomain(scan({ domain: "alice.github.io", whois_data: { queried_domain: "github.io" } }))).toBe("github.io");
    expect(whoisOtherDomain(scan({ whois_data: { queried_domain: "EXAMPLE.com" } }))).toBe("");
    expect(
      whoisStatuses(["clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited", "clientdeleteprohibited", ""]),
    ).toEqual(["clientDeleteProhibited"]);
  });

  it("repère une IP mutualisée de CDN", () => {
    expect(sharedCdnIp(scan({ waf: { cdn_detected: true } }))).toBe(true);
    expect(sharedCdnIp(scan({ geo_data: { anycast: true } }))).toBe(true);
    expect(sharedCdnIp(scan({ waf: {}, geo_data: {} }))).toBe(false);
  });

  it("reconnaît un domaine sans messagerie (MX nul, SPF A, DMARC A)", () => {
    expect(emailWithoutMail({ null_mx: true, spf: { grade: "A" }, dmarc: { grade: "A" } })).toBe(true);
    expect(emailWithoutMail({ null_mx: false, spf: { grade: "A" }, dmarc: { grade: "A" } })).toBe(false);
  });

  it("lit les verdicts du serveur, ou la simple présence pour un ancien scan", () => {
    expect(headerChecks({ checks: { "X-Frame-Options": { value: "DENY", status: "ok", detail: "Conforme" } } })).toEqual([
      { name: "X-Frame-Options", value: "DENY", status: "ok", detail: "Conforme", legacy: false },
    ]);
    expect(headerChecks({ checks: { "X-Test": { status: "bizarre" } } })[0].status).toBe("missing");
    const legacy = headerChecks({ headers_found: { "X-Frame-Options": "DENY" } });
    expect(legacy).toHaveLength(6);
    expect(legacy.find((row) => row.name === "X-Frame-Options")).toMatchObject({ status: "ok", legacy: true });
    expect(legacy.find((row) => row.name === "Content-Security-Policy")).toMatchObject({ status: "missing", legacy: true });
  });

  it("compte les voisins reverse-IP (liste plafonnée par le serveur)", () => {
    expect(neighborsCount({ reverse_ip_neighbors: ["a", "b"], neighbors_total: 40 })).toEqual({ shown: 2, total: 40 });
    expect(neighborsCount({ reverse_ip_neighbors: ["a"] })).toEqual({ shown: 1, total: 1 });
  });
});
