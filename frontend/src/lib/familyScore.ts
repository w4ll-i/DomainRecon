import type { CriterionScore, FamilyKey } from "../api/types";

// Critères du barème (clés de security_score.breakdown) de chaque famille : copie de
// FAMILY_CRITERIA de domainrecon/scanner/families.py. Réseau, identité et réputation
// n'ont pas de critère dans le barème actuel (les 15 points de la réputation ne sont
// pas encore attribués) : leur part du barème n'est pas mesurable.
export const FAMILY_CRITERIA: Readonly<Record<FamilyKey, readonly string[]>> = {
  web: ["headers", "cookies", "cors", "https_redirect", "waf"],
  tls: ["tls"],
  email: ["email"],
  dns: ["takeover"],
  network: [],
  identity: [],
  reputation: [],
  leaks: [],
};

const isNumber = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);

// Part du barème obtenue par une famille, de 0 à 100 : points obtenus sur points
// possibles de ses critères comptés (même règle que family_grade côté serveur :
// un ancien barème sans « counted » compte le critère s'il est mesuré). null quand
// aucun de ses critères n'est compté (non mesuré, sans objet ou hors barème) :
// jamais 0, qui se lirait comme le pire résultat.
export function familyPercent(
  family: FamilyKey,
  breakdown: Record<string, CriterionScore> | null | undefined,
  // Critères de la famille tels que le catalogue du serveur les déclare (lib/catalog.ts) ;
  // par défaut, ceux des 18 modules historiques.
  criteria: readonly string[] = FAMILY_CRITERIA[family],
): number | null {
  let obtained = 0;
  let maximum = 0;
  for (const key of criteria) {
    const item = breakdown?.[key];
    if (!item || typeof item !== "object") continue;
    const counted = item.counted ?? item.measured ?? true;
    if (!counted || !isNumber(item.score) || !isNumber(item.max) || item.max <= 0) continue;
    obtained += item.score;
    maximum += item.max;
  }
  return maximum > 0 ? Math.round((obtained * 100) / maximum) : null;
}
