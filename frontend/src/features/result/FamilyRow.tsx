import { ChevronRight } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import type { FamilyKey, ScanResponse } from "../../api/types";
import { GradeBadge } from "../../components/GradeBadge";
import { FAMILY_ICONS, STATE_ICONS } from "../../lib/icons";
import styles from "./result.module.css";

// Famille en ligne simple : icône, nom, note, état (icône et texte) et nombre de
// problèmes. Le lien porte un nom accessible complet (état, note, résumé).
export function FamilyRow({ scan, family }: { scan: ScanResponse; family: FamilyKey }) {
  const { t } = useTranslation();
  const summary = scan.families?.[family];
  const state = summary?.state ?? "unmeasured";
  const Icon = FAMILY_ICONS[family];
  const StateIcon = STATE_ICONS[state];
  const name = t(`families.${family}.name`);
  const stateLabel = t(`familyState.${state}`);
  const issues = (scan.findings ?? []).filter((finding) => finding.family === family).length;
  const aria = t("result.tileAria", {
    family: name,
    state: stateLabel,
    grade: summary?.grade ?? t("common.na"),
    summary: summary?.summary ?? "",
  }).trim();
  return (
    <Link to={`/scans/${scan.id}/${family}`} className={styles.row} data-state={state} data-family={family} aria-label={aria}>
      <Icon aria-hidden className={styles.rowIcon} />
      <span className={styles.rowName}>{name}</span>
      <span className={styles.rowGrade}>{summary?.grade && <GradeBadge grade={summary.grade} size="sm" />}</span>
      <span className={styles.rowState}>
        <StateIcon aria-hidden />
        {stateLabel}
      </span>
      <span className={styles.rowIssues}>{issues > 0 ? t("result.row.issues", { count: issues }) : t("result.row.none")}</span>
      <ChevronRight aria-hidden className={styles.rowChevron} />
    </Link>
  );
}
