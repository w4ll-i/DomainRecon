import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import styles from "./KvList.module.css";

export interface KvRow {
  label: string;
  value: ReactNode;
  mono?: boolean;
}

// Absence de valeur : N/A. Un booléen est une mesure : « Oui » ou « Non »
// (un `false` mesuré n'est pas une donnée manquante).
const isEmpty = (value: ReactNode) => value === null || value === undefined || value === "";

// Données de scan : du TEXTE rendu par React, jamais du HTML.
export function KvList({ rows }: { rows: KvRow[] }) {
  const { t } = useTranslation();
  const text = (value: ReactNode): ReactNode => {
    if (typeof value === "boolean") return t(value ? "common.yes" : "common.no");
    return isEmpty(value) ? t("common.na") : value;
  };
  return (
    <dl className={styles.list}>
      {rows.map((row) => (
        <div key={row.label} className={styles.row}>
          <dt className={styles.label}>{row.label}</dt>
          <dd className={row.mono ? `${styles.value} mono` : styles.value}>{text(row.value)}</dd>
        </div>
      ))}
    </dl>
  );
}
