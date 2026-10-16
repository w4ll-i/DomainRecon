import { useTranslation } from "react-i18next";
import { gradeToken } from "../lib/colors";
import styles from "./ScoreGauge.module.css";

interface ScoreGaugeProps {
  // Note affichée (« A » à « F »), ou null / « N/A » quand aucune note n'est attribuée.
  grade: string | null;
  // Score de 0 à 100 ; null quand rien n'est mesurable.
  score: number | null;
  // Part du barème mesurée (0 à 100) ; décrite aux lecteurs d'écran seulement.
  coverage: number | null;
  // Score calculé sur une couverture insuffisante : indicatif, sans note.
  indicative: boolean;
}

type GaugeKind = "score" | "indicative" | "na";

// Note en grand : une lettre typographique (48 px) suivie du score sur 100. Pas
// d'anneau ni de dessin : la lettre et le chiffre disent tout. Le nom accessible
// reprend la note, le score et la couverture.
export function ScoreGauge({ grade, score, coverage, indicative }: ScoreGaugeProps) {
  const { t } = useTranslation();
  const token = gradeToken(grade);
  const value = typeof score === "number" && Number.isFinite(score) ? Math.min(100, Math.max(0, score)) : null;
  // Sans score : N/A. Score indicatif : jamais de note, quelle que soit celle reçue.
  // Score sans note valide : N/A aussi (un score seul ne se présente pas comme une note).
  const kind: GaugeKind = value === null ? "na" : indicative ? "indicative" : token === "NA" ? "na" : "score";
  // Seule une vraie note donne sa lettre et sa couleur ; sinon « N/A » et le gris des jetons.
  const graded = kind === "score";
  const letter = graded ? token : t("common.na");
  const colorToken = graded ? token : "NA";

  const parts =
    kind === "score"
      ? [t("grade.aria", { grade: token }), t("grade.gaugeScore", { score: value })]
      : kind === "indicative"
        ? [t("grade.gaugeIndicative", { score: value })]
        : [t("grade.aria", { grade: t("common.na") })];
  if (typeof coverage === "number" && Number.isFinite(coverage)) parts.push(t("grade.gaugeCoverage", { coverage }));

  return (
    <div className={styles.gauge} data-state={kind} data-grade={colorToken} role="img" aria-label={parts.join(", ")}>
      <span className={styles.letter}>{letter}</span>
      {value !== null && kind !== "na" && <span className={styles.score}>{t("result.score", { score: value })}</span>}
      {kind === "indicative" && <span className={styles.hint}>{t("grade.indicative")}</span>}
    </div>
  );
}
