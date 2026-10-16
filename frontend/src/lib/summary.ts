import type { ScanResponse } from "../api/types";
import { displayGrade, scoreUnavailable } from "./score";

// Phrase de résumé de l'écran Résultat, en langage clair : une clé de traduction et ses
// paramètres. La posture vient de la note (A et B : bonne, C : moyenne, D et F : fragile),
// les problèmes des constats de l'API (« sérieux » : gravité critique ou élevée).
export interface ScanSummaryText {
  key: string;
  params: { count: number };
}

export type Posture = "good" | "fair" | "poor";

export function postureOf(grade: string): Posture {
  if (grade === "A" || grade === "B") return "good";
  if (grade === "C") return "fair";
  return "poor";
}

export function scanSummary(scan: Pick<ScanResponse, "status" | "findings" | "security_score">): ScanSummaryText {
  const findings = scan.findings ?? [];
  // Un scan en échec ne conclut rien ; sans note (couverture insuffisante), la phrase le dit.
  if (scan.status === "error") return { key: "result.summary.error", params: { count: 0 } };
  if (scoreUnavailable(scan.security_score)) {
    return { key: "result.summary.noGrade", params: { count: findings.length } };
  }
  const severe = findings.filter((item) => item.severity === "critical" || item.severity === "high").length;
  const posture = postureOf(displayGrade(scan.security_score));
  if (severe > 0) return { key: `result.summary.${posture}.severe`, params: { count: severe } };
  if (findings.length > 0) return { key: `result.summary.${posture}.minor`, params: { count: findings.length } };
  return { key: `result.summary.${posture}.clean`, params: { count: 0 } };
}
