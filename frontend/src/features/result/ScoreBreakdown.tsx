import { useTranslation } from "react-i18next";
import type { SecurityScore } from "../../api/types";
import { ScoreBars } from "../../components/ScoreBars";
import { penaltyTotal, scoreHasDetails, scoreUnavailable } from "../../lib/score";
import styles from "./result.module.css";

// Détail du score : une barre par critère (ScoreBars, valeur en attribut HTML, aucun
// style en ligne), le calcul, les pénalités hors barème et le plafond de grade.
export function ScoreBreakdown({ score }: { score: SecurityScore }) {
  const { t } = useTranslation();
  const penalties = (score.penalties ?? []).filter((penalty) => penalty && typeof penalty === "object");
  const reasons = score.grade_cap_reasons ?? [];
  if (!scoreHasDetails(score)) return null;

  const measuredMax = Number(score.measured_max);
  const hasTotals = Number.isFinite(Number(score.measured_points)) && measuredMax > 0;
  const adjusted = penalties.length > 0 || Boolean(score.grade_cap);
  const raw = hasTotals
    ? adjusted || typeof score.score !== "number"
      ? Math.round((Number(score.measured_points) * 100) / measuredMax)
      : score.score
    : null;

  return (
    <div className={styles.scoreDetails}>
      <ScoreBars breakdown={score.breakdown ?? {}} showDetails />
      {raw !== null && (
        <p className={styles.note}>
          {t(adjusted ? "score.measuredAdjusted" : "score.measured", {
            points: score.measured_points,
            max: score.measured_max,
            raw,
          })}
          {scoreUnavailable(score) ? ` ${t("common.indicative")}` : ""}
        </p>
      )}
      {penalties.length > 0 && (
        <div className={styles.penalties}>
          <p className={styles.penaltyTitle}>{t("score.penalties", { total: penaltyTotal(score) })}</p>
          <ul>
            {penalties.map((penalty, index) => (
              <li key={penalty.key ?? index}>
                <span>{penalty.label}</span>
                <span className="mono">−{penalty.points}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {(score.grade_cap || reasons.length > 0) && (
        <div className={styles.penalties}>
          <p className={styles.penaltyTitle}>
            {score.grade_cap ? t("score.cap", { grade: score.grade_cap }) : t("score.capUnknown")}
          </p>
          <ul>
            {reasons.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
