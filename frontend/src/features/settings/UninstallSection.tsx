import { Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { SectionTitle } from "../../components/SectionTitle";
import styles from "./settings.module.css";
import { UninstallDialog } from "./UninstallDialog";
import danger from "./uninstall.module.css";

// Zone de danger des Réglages : désinstallation complète, en quatre étapes (UninstallDialog).
export function UninstallSection() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <section className={`${styles.card} ${danger.danger}`} aria-labelledby="settings-uninstall">
      <SectionTitle level={2} label={t("uninstall.kicker")} title={t("uninstall.title")} id="settings-uninstall" />
      <p className={styles.muted}>{t("uninstall.text")}</p>
      <div>
        <button type="button" className="btn" onClick={() => setOpen(true)}>
          <Trash2 aria-hidden />
          {t("uninstall.open")}
        </button>
      </div>
      {open && <UninstallDialog open onClose={() => setOpen(false)} />}
    </section>
  );
}
