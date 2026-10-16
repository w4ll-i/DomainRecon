import { type KeyboardEvent, type ReactNode, useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { type GlossaryKey, splitGlossary } from "../lib/glossary";
import styles from "./Term.module.css";

// Terme technique avec son infobulle : s'ouvre au survol et au focus clavier, Échap la
// ferme. Le texte vient du glossaire (« glossary.<clé>.def »).
export function Term({ k, children }: { k: GlossaryKey; children?: ReactNode }) {
  const { t } = useTranslation();
  const id = useId();
  const [dismissed, setDismissed] = useState(false);
  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === "Escape") setDismissed(true);
  };
  return (
    <span
      className={styles.term}
      tabIndex={0}
      aria-describedby={id}
      data-dismissed={dismissed ? "true" : undefined}
      onKeyDown={onKeyDown}
      onMouseEnter={() => setDismissed(false)}
      onFocus={() => setDismissed(false)}
    >
      {children ?? t(`glossary.${k}.name`)}
      <span role="tooltip" id={id} className={styles.tip}>
        <strong>{t(`glossary.${k}.name`)}</strong> {t(`glossary.${k}.def`)}
      </span>
    </span>
  );
}

// Texte courant dont les sigles connus (SPF, DMARC, HSTS…) reçoivent leur infobulle.
export function GlossaryText({ text }: { text: string }) {
  return (
    <>
      {splitGlossary(text).map((segment, index) =>
        segment.term ? (
          <Term key={index} k={segment.term}>
            {segment.text}
          </Term>
        ) : (
          <span key={index}>{segment.text}</span>
        ),
      )}
    </>
  );
}
