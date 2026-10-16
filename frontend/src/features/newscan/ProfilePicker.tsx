import { useId } from "react";
import { useTranslation } from "react-i18next";
import type { ScanProfile } from "../../api/types";
import type { Catalog } from "../../lib/catalog";
import { moduleLabel } from "../../lib/catalog";
import { CategoryBadge } from "../../components/CategoryBadge";
import { GlossaryText } from "../../components/Term";
import { passiveModules, PROFILES, type ScanOptions } from "./scanOptions";
import styles from "./ProfilePicker.module.css";

interface Props {
  catalog: Catalog;
  value: ScanOptions;
  onChange: (value: ScanOptions) => void;
  needsAuth: boolean;
  // Cible(s) à nommer dans la déclaration (« cette cible », « ces cibles »).
  plural?: boolean;
}

// Choix du profil de scan (rapide, complet, personnalisé), sélection des modules par famille
// pour le profil personnalisé, et déclaration d'autorisation exigée par les modules actifs
// et sensibles.
export function ProfilePicker({ catalog, value, onChange, needsAuth, plural = false }: Props) {
  const { t } = useTranslation();
  const name = useId();
  const quickCount = catalog.moduleNames.filter((module) => catalog.info(module)?.quick).length;
  const selected = new Set(value.selected);

  const setProfile = (profile: ScanProfile) => {
    const initial = profile === "personnalise" && value.selected.length === 0 ? passiveModules(catalog) : value.selected;
    onChange({ ...value, profile, selected: initial });
  };
  const toggle = (module: string) => {
    const next = new Set(selected);
    if (next.has(module)) next.delete(module);
    else next.add(module);
    onChange({ ...value, selected: catalog.moduleNames.filter((item) => next.has(item)) });
  };
  const setFamily = (family: string, on: boolean) => {
    const members = catalog.modules(family as never);
    const next = new Set(selected);
    for (const module of members) {
      if (on) next.add(module);
      else next.delete(module);
    }
    onChange({ ...value, selected: catalog.moduleNames.filter((item) => next.has(item)) });
  };

  return (
    <div className={styles.picker} data-tour="profiles">
      <fieldset className={styles.profiles}>
        <legend className={styles.legend}>{t("scanProfile.legend")}</legend>
        {PROFILES.map((profile) => (
          <label key={profile} className={styles.profile}>
            <input
              type="radio"
              name={name}
              value={profile}
              checked={value.profile === profile}
              onChange={() => setProfile(profile)}
            />
            <span className={styles.profileText}>
              <span className={styles.profileName}>{t(`scanProfile.${profile}.name`)}</span>
              <span className={styles.profileDesc}>
                {/* Tant que le catalogue du serveur n'est pas arrivé, le nombre de modules rapides est inconnu : pas de « 0 ». */}
                {profile === "rapide" && !catalog.live
                  ? t("scanProfile.rapide.descPending")
                  : t(`scanProfile.${profile}.desc`, { count: quickCount })}
              </span>
            </span>
          </label>
        ))}
      </fieldset>

      {value.profile === "personnalise" && (
        <div className={styles.modules}>
          <p className={styles.count} role="status">
            {t("scanProfile.selectedCount", { count: value.selected.length, total: catalog.total })}
          </p>
          {catalog.families.map((family) => {
            const members = catalog.modules(family);
            if (members.length === 0) return null;
            const chosen = members.filter((module) => selected.has(module)).length;
            return (
              <details key={family} className={styles.family}>
                <summary className={styles.summary}>
                  <span>{t(`families.${family}.name`)}</span>
                  <span className={styles.familyCount}>
                    {chosen}/{members.length}
                  </span>
                </summary>
                <div className={styles.familyActions}>
                  <button type="button" className="btn" data-variant="ghost" onClick={() => setFamily(family, true)}>
                    {t("scanProfile.selectFamily", { family: t(`families.${family}.name`) })}
                  </button>
                  <button type="button" className="btn" data-variant="ghost" onClick={() => setFamily(family, false)}>
                    {t("scanProfile.clearFamily", { family: t(`families.${family}.name`) })}
                  </button>
                </div>
                <ul className={styles.list}>
                  {members.map((module) => {
                    const info = catalog.info(module);
                    const missingKey = info?.keys?.some((key) => key.required && !key.configured) ?? false;
                    return (
                      <li key={module} className={styles.item}>
                        <label className={styles.moduleLabel}>
                          <input type="checkbox" checked={selected.has(module)} onChange={() => toggle(module)} />
                          <span className={styles.moduleName}>{moduleLabel(t, catalog, module)}</span>
                          {info && <CategoryBadge category={info.category} />}
                        </label>
                        {info?.help.checks && (
                          <p className={styles.help}>
                            <GlossaryText text={info.help.checks} />
                          </p>
                        )}
                        {missingKey && <p className={styles.warn}>{t("scanProfile.keyMissing")}</p>}
                      </li>
                    );
                  })}
                </ul>
              </details>
            );
          })}
          {value.selected.length === 0 && <p className={styles.warn}>{t("scanProfile.noneSelected")}</p>}
        </div>
      )}

      {needsAuth && (
        <div className={styles.auth}>
          <label className={styles.authLabel}>
            <input
              type="checkbox"
              checked={value.authorized}
              onChange={(event) => onChange({ ...value, authorized: event.target.checked })}
            />
            <span>{t(plural ? "scanProfile.authorizedPlural" : "scanProfile.authorized")}</span>
          </label>
          <p className={styles.help}>{t("scanProfile.authorizedHint")}</p>
        </div>
      )}
    </div>
  );
}
