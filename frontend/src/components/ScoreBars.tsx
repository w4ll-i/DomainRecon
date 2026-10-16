import { useId } from "react";
import { useTranslation } from "react-i18next";
import type { CriterionScore } from "../api/types";
import { criterionKind } from "../lib/score";
import styles from "./ScoreBars.module.css";

interface ScoreBarsProps {
  breakdown: Record<string, CriterionScore>;
  // Affiche sous chaque barre l'explication du critère (champ detail du serveur).
  showDetails?: boolean;
}

const isNumber = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);

// Décomposition du score : une barre par critère. Mesuré : accent ; bonus (hors barème
// tant qu'il n'est pas obtenu) : cyan ; non mesuré : pointillé gris ; sans objet :
// rayé. La valeur de chaque <progress> est un attribut HTML (jamais de style en
// ligne) ; l'entrée glisse de 0 à la valeur par une transition CSS.
export function ScoreBars({ breakdown, showDetails = false }: ScoreBarsProps) {
  const { t } = useTranslation();
  const prefix = useId();
  const criteria = Object.entries(breakdown ?? {}).filter(
    (entry): entry is [string, CriterionScore] => Boolean(entry[1]) && typeof entry[1] === "object",
  );
  if (!criteria.length) return null;

  return (
    <ul className={styles.list} aria-label={t("score.title")}>
      {criteria.map(([key, item], index) => {
        const kind = criterionKind(item);
        // Rang et non clé : la clé vient de l'API, un identifiant ne doit pas la contenir.
        const labelId = `${prefix}-${index}`;
        const max = isNumber(item.max) && item.max > 0 ? item.max : 1;
        const score = Math.min(max, Math.max(0, isNumber(item.score) ? item.score : 0));
        const points = t("score.points", { score, max });
        // Critère non mesuré ou sans objet : une barre à zéro se lirait comme « 0 point ».
        const filled = kind === "points" || kind === "bonus";
        return (
          <li key={key} className={styles.row} data-kind={kind}>
            <span id={labelId} className={styles.label}>
              {t(`score.criteria.${key}`, { defaultValue: key })}
            </span>
            <progress
              className={styles.bar}
              max={max}
              value={filled ? score : 0}
              {...(kind === "points"
                ? { "aria-labelledby": labelId, "aria-valuetext": points }
                : { "aria-hidden": true })}
            />
            <span className={styles.value}>{kind === "points" ? points : t(`score.kind.${kind}`)}</span>
            {showDetails && typeof item.detail === "string" && item.detail && (
              <span className={styles.detail}>
                {kind === "bonus" ? t("score.bonusDetail", { detail: item.detail }) : item.detail}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}
