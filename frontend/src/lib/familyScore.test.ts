import { describe, expect, it } from "vitest";
import type { CriterionScore } from "../api/types";
import { makeScan } from "../test/fixtures";
import { FAMILY_KEYS } from "./families";
import { FAMILY_CRITERIA, familyPercent } from "./familyScore";

const breakdown = makeScan().security_score.breakdown as Record<string, CriterionScore>;
const criterion = (score: number, max: number, extra: Partial<CriterionScore> = {}): CriterionScore => ({
  score,
  max,
  measured: true,
  counted: true,
  applicable: true,
  ...extra,
});

describe("part du barème d'une famille", () => {
  it("somme les critères comptés de la famille, en pourcentage arrondi", () => {
    // Web : en-têtes 19/25, cookies 4/10, CORS 10/10, redirection 5/5 ; le bonus WAF non obtenu n'est pas compté.
    expect(familyPercent("web", breakdown)).toBe(76);
    expect(familyPercent("tls", breakdown)).toBe(100);
    expect(familyPercent("email", breakdown)).toBe(80);
  });

  it("compte le bonus WAF quand il est obtenu", () => {
    const withWaf = { ...breakdown, waf: criterion(10, 10) };
    expect(familyPercent("web", withWaf)).toBe(Math.round((48 * 100) / 60));
  });

  it("rend null, jamais 0, sans critère compté : non mesuré, sans objet ou hors barème", () => {
    expect(familyPercent("dns", breakdown)).toBeNull();
    expect(familyPercent("network", breakdown)).toBeNull();
    expect(familyPercent("identity", breakdown)).toBeNull();
    expect(familyPercent("email", { email: criterion(0, 15, { measured: false, counted: false, applicable: false }) })).toBeNull();
    expect(familyPercent("web", {})).toBeNull();
    expect(familyPercent("web", undefined)).toBeNull();
  });

  it("un vrai zéro mesuré reste 0", () => {
    expect(familyPercent("tls", { tls: criterion(0, 20) })).toBe(0);
  });

  it("lit un ancien barème sans « counted » : un critère mesuré est compté", () => {
    expect(familyPercent("tls", { tls: { score: 10, max: 20 } })).toBe(50);
    expect(familyPercent("tls", { tls: { score: 0, max: 20, measured: false } })).toBeNull();
  });

  it("ignore les entrées illisibles", () => {
    const hostile = {
      tls: { score: "20", max: 20 },
      email: null,
      headers: criterion(10, 0),
      cookies: criterion(Number.NaN, 10),
      cors: criterion(5, 10),
    } as unknown as Record<string, CriterionScore>;
    expect(familyPercent("tls", hostile)).toBeNull();
    expect(familyPercent("email", hostile)).toBeNull();
    expect(familyPercent("web", hostile)).toBe(50);
  });

  it("chaque famille a sa liste de critères, sans critère en double", () => {
    expect(Object.keys(FAMILY_CRITERIA).sort()).toEqual([...FAMILY_KEYS].sort());
    const all = FAMILY_KEYS.flatMap((family) => FAMILY_CRITERIA[family]);
    expect(new Set(all).size).toBe(all.length);
    // Les huit critères du barème v3 sont tous rattachés à une famille.
    expect([...all].sort()).toEqual(Object.keys(breakdown).sort());
  });
});
