import { describe, expect, it } from "vitest";
import en from "../i18n/en.json";
import fr from "../i18n/fr.json";
import {
  FAMILY_KEYS,
  FAMILY_MODULES,
  MODULE_FAMILY,
  MODULE_NAMES,
  TOTAL_MODULES,
  isFamilyKey,
  isModuleName,
} from "./families";
import { FAMILY_CRITERIA } from "./familyScore";
import { FAMILY_ICONS } from "./icons";

type Catalog = { [key: string]: string | Catalog };

function has(catalog: Catalog, key: string): boolean {
  let node: string | Catalog | undefined = catalog;
  for (const part of key.split(".")) {
    if (!node || typeof node === "string") return false;
    node = node[part];
  }
  return typeof node === "string" && node.trim() !== "";
}

// Clés construites dynamiquement dans le code (`t(\`modules.${name}\`)`…).
const DYNAMIC_KEYS = [
  ...FAMILY_KEYS.flatMap((f) => [`families.${f}.name`, `families.${f}.description`]),
  ...MODULE_NAMES.map((m) => `modules.${m}`),
  ...["ok", "warning", "critical", "unmeasured", "skipped", "info"].map((s) => `familyState.${s}`),
  ...["critical", "high", "medium", "low"].map((s) => `severity.${s}`),
  ...["ok", "failed", "timeout", "skipped", "pending", "running"].map((s) => `moduleStatus.${s}`),
  ...["success", "partial", "error", "unknown"].map((s) => `scanStatus.${s}`),
  ...["high", "medium", "low"].map((s) => `confidence.${s}`),
  ...["ok", "weak", "invalid", "missing", "info"].map((s) => `headerStatus.${s}`),
  ...["headers", "tls", "email", "waf", "cookies", "cors", "https_redirect", "takeover"].map((c) => `score.criteria.${c}`),
  ...["notApplicable", "notMeasured", "bonus"].map((k) => `score.kind.${k}`),
  ...["A", "B", "C", "D", "F"].map((g) => `email.level.${g}`),
  ...["found", "absent", "unverified"].map((s) => `web.files.${s}`),
  ...["high", "medium", "low"].map((r) => `dns.takeover.risk.${r}`),
  ...["proofNx", "proofFingerprint", "proofNoHttp"].map((p) => `dns.takeover.${p}`),
  ...["pending", "running", "done", "partial", "skipped"].map((s) => `live.tile.${s}`),
  ...["online", "degraded", "offline", "checking"].map((s) => `server.${s}`),
  ...["fr", "en"].map((l) => `lang.${l}`),
  ...[400, 401, 403, 404, 413, 415, 422, 429, 500, 502, 503, 504].map((c) => `errors.http.${c}`),
];

describe("familles et modules", () => {
  it("répartit les 18 modules, chacun dans une seule famille", () => {
    expect(TOTAL_MODULES).toBe(18);
    const all = FAMILY_KEYS.flatMap((family) => FAMILY_MODULES[family]);
    expect(new Set(all).size).toBe(18);
    expect([...all].sort()).toEqual([...MODULE_NAMES].sort());
    expect(MODULE_FAMILY).toMatchObject({
      security_headers: "web",
      waf: "web",
      tls_certificate: "tls",
      email_security: "email",
      reverse_dns: "dns",
      subdomain_takeover: "dns",
      geo_data: "network",
      whois_data: "identity",
      screenshot: "identity",
    });
  });

  it("compte huit familles ; réputation et fuites n'ont pas de module historique", () => {
    expect(FAMILY_KEYS).toEqual(["web", "tls", "email", "dns", "network", "identity", "reputation", "leaks"]);
    expect(FAMILY_MODULES.reputation).toEqual([]);
    expect(FAMILY_MODULES.leaks).toEqual([]);
    // Chaque famille a son icône et ses critères de barème (la réputation n'en a pas encore).
    for (const family of FAMILY_KEYS) {
      expect(FAMILY_ICONS[family]).toBeDefined();
      expect(FAMILY_CRITERIA[family]).toBeDefined();
    }
    expect(FAMILY_CRITERIA.reputation).toEqual([]);
  });

  it("reconnaît les familles et les modules", () => {
    expect(isFamilyKey("dns")).toBe(true);
    expect(isFamilyKey("reputation")).toBe(true);
    expect(isFamilyKey("foo")).toBe(false);
    expect(isFamilyKey(undefined)).toBe(false);
    expect(isModuleName("cors")).toBe(true);
    expect(isModuleName("score")).toBe(false);
  });

  it.each(["fr", "en"] as const)("chaque clé dynamique existe (%s)", (lang) => {
    const catalog = (lang === "fr" ? fr : en) as Catalog;
    expect(DYNAMIC_KEYS.filter((key) => !has(catalog, key))).toEqual([]);
  });
});
