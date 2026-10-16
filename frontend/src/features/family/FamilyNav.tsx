import { useTranslation } from "react-i18next";
import { NavLink } from "react-router";
import type { ScanResponse } from "../../api/types";
import { FAMILY_KEYS } from "../../lib/families";
import { FAMILY_ICONS, STATE_ICONS } from "../../lib/icons";
import styles from "./family.module.css";

// Navigation entre les familles du scan : une pastille par famille, avec son icône
// (neutre) et l'icône de son état. L'état se dit
// aussi en toutes lettres pour les lecteurs d'écran : la couleur n'est jamais seule.
export function FamilyNav({ scanId, families }: { scanId: number; families: ScanResponse["families"] }) {
  const { t } = useTranslation();
  return (
    <nav className={styles.nav} aria-label={t("family.nav")}>
      <ul className={styles.navList}>
        {FAMILY_KEYS.map((key) => {
          const Icon = FAMILY_ICONS[key];
          const state = families?.[key]?.state ?? "unmeasured";
          const StateIcon = STATE_ICONS[state];
          return (
            <li key={key}>
              <NavLink
                to={`/scans/${scanId}/${key}`}
                className={({ isActive }) => (isActive ? `${styles.navLink} ${styles.navActive}` : styles.navLink)}
                data-state={state}
                data-family={key}
              >
                <span className={styles.navIcon} aria-hidden="true">
                  <Icon />
                </span>
                {t(`families.${key}.name`)}
                {/* L'état ne tient pas qu'à la couleur : icône, et texte pour les lecteurs d'écran. */}
                <StateIcon aria-hidden className={styles.navState} />{" "}
                <span className="visually-hidden">({t(`familyState.${state}`)})</span>
              </NavLink>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
