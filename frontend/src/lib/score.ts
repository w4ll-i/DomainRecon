import type { CriterionScore, ScanResponse, SecurityScore, TimelineEntry } from "../api/types";

// Couverture minimale (% du barème applicable) pour qu'un score porte une note
// (MIN_GRADED_COVERAGE de domainrecon/scanner/score.py), appliquée aussi aux
// scans notés avant cette règle.
export const MIN_GRADED_COVERAGE = 50;

export function lowCoverage(ss?: SecurityScore | null): boolean {
  return typeof ss?.coverage === "number" && ss.coverage < MIN_GRADED_COVERAGE;
}

// Nombre fini seulement (JSON brut : chaîne, booléen) ; même règle que
// _number côté serveur (history._timeline_entry).
function isNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

// Score sans note (N/A) : rien de mesurable, score non numérique, ou
// couverture insuffisante ; jamais présenté comme une note, ni comme un 0/100.
export function scoreUnavailable(ss?: SecurityScore | null): boolean {
  return !ss || typeof ss !== "object" || !isNumber(ss.score) || ss.grade === "N/A" || ss.coverage === 0 || lowCoverage(ss);
}

export function displayGrade(ss?: SecurityScore | null): string {
  if (!ss?.grade) return "N/A";
  return scoreUnavailable(ss) ? "N/A" : ss.grade;
}

// Score calculé sur une couverture insuffisante : indicatif seulement ; null
// s'il n'y a aucun score.
export function scoreIndicative(ss?: SecurityScore | null): number | null {
  if (!scoreUnavailable(ss) || !isNumber(ss?.score)) return null;
  return isNumber(ss.measured_max) && ss.measured_max > 0 && ss.coverage !== 0 ? ss.score : null;
}

// Règle unique d'affichage du score (Résultat, Historique, Timeline) : le score
// seul quand la note existe, « indicatif » quand la couverture est insuffisante,
// rien (N/A) quand rien n'est mesurable.
export interface ScoreView {
  kind: "score" | "indicative" | "none";
  value: number | null;
}

export function scoreView(ss?: SecurityScore | null): ScoreView {
  if (!scoreUnavailable(ss)) return { kind: "score", value: Number(ss?.score) };
  const indicative = scoreIndicative(ss);
  return indicative === null ? { kind: "none", value: null } : { kind: "indicative", value: indicative };
}

// Relevé de la timeline : exactement la règle de l'Historique. Le serveur
// (history._timeline_entry) ne retire le score que là où l'Historique n'en
// montre aucun (couverture nulle, ou note N/A sans critère compté) et transmet
// measured_max (null pour un ancien scan qui n'en a pas).
export function timelineScoreView(
  entry: Pick<TimelineEntry, "security_score" | "grade" | "coverage" | "measured_max">,
): ScoreView {
  return scoreView({
    score: entry.security_score,
    grade: entry.grade ?? undefined,
    coverage: entry.coverage,
    measured_max: entry.measured_max ?? undefined,
  });
}

export type CriterionKind = "points" | "bonus" | "notMeasured" | "notApplicable";

// Sans objet (applicable === false) ≠ non mesuré ; scan antérieur à
// `applicable` : le détail le disait (texte d'origine).
export function criterionNotApplicable(item: CriterionScore): boolean {
  if (typeof item.applicable === "boolean") return !item.applicable;
  return /^Non applicable/.test(String(item.detail ?? ""));
}

export function criterionKind(item: CriterionScore): CriterionKind {
  if (item.measured === false) return criterionNotApplicable(item) ? "notApplicable" : "notMeasured";
  if (item.counted === false) return "bonus";
  return "points";
}

export function penaltyTotal(ss?: SecurityScore | null): number {
  return (ss?.penalties ?? []).reduce((sum, penalty) => sum + (Number(penalty?.points) || 0), 0);
}

// Liste « À corriger » vide : un scan en échec ou trop peu mesuré n'est pas
// un scan « propre ».
export function findingsEmptyKey(
  scan: Pick<ScanResponse, "status" | "security_score">,
): "findings.noneError" | "findings.noneLowCoverage" | "findings.none" {
  if (scan.status === "error") return "findings.noneError";
  if (scoreUnavailable(scan.security_score)) return "findings.noneLowCoverage";
  return "findings.none";
}

// Le détail du score a-t-il quelque chose à montrer (un critère, une pénalité, un plafond de
// grade) ? Sinon l'écran Résultat ne propose pas l'onglet « Détail du score ».
export function scoreHasDetails(ss?: SecurityScore | null): boolean {
  if (!ss || typeof ss !== "object") return false;
  const hasCriterion = Object.values(ss.breakdown ?? {}).some((item) => Boolean(item) && typeof item === "object");
  const hasPenalty = (ss.penalties ?? []).some((penalty) => penalty && typeof penalty === "object");
  return hasCriterion || hasPenalty || (ss.grade_cap_reasons ?? []).length > 0 || Boolean(ss.grade_cap);
}
