import { CircleCheck, CircleDashed, CircleMinus, CircleX, LoaderCircle, type LucideIcon, TriangleAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useCatalog } from "../../api/queries";
import type { FamilyKey } from "../../api/types";
import { useLang } from "../../i18n";
import { useModuleLabel } from "../../lib/useModuleLabel";
import { familyModules, familyProgress, type LiveState } from "./liveReducer";
import styles from "./LiveScanPage.module.css";
import { formatModuleDuration } from "./liveView";

// Une icône par statut de module ; le texte du statut est toujours écrit à côté
// (la couleur n'est jamais le seul indice).
const STATUS_ICONS: Record<string, LucideIcon> = {
  ok: CircleCheck,
  failed: CircleX,
  timeout: TriangleAlert,
  skipped: CircleMinus,
  pending: CircleDashed,
  running: LoaderCircle,
};

// Une famille : son nom, son avancement (« 2/4 modules ») puis ses modules en lignes
// simples (nom, statut, durée). Pas de carte : un titre et une liste à filets.
export function LiveTile({ family, state }: { family: FamilyKey; state: LiveState }) {
  const { t } = useTranslation();
  const lang = useLang();
  const catalog = useCatalog();
  const moduleLabel = useModuleLabel();
  const progress = familyProgress(state, family, catalog);
  const label =
    progress.state === "running"
      ? t("live.tile.running", { done: progress.done, total: progress.total })
      : progress.state === "partial"
        ? t("live.tile.partial", { count: progress.unmeasured })
        : t(`live.tile.${progress.state}`);
  const name = t(`families.${family}.name`);
  return (
    <div
      className={styles.family}
      data-state={progress.state}
      data-family={family}
      role="group"
      aria-label={t("live.tileAria", { family: name, state: label })}
    >
      <div className={styles.familyHead}>
        <h3 className={styles.familyName}>{name}</h3>
        <p className={styles.familyState}>{label}</p>
      </div>
      <ul className={styles.modules}>
        {familyModules(state, family, catalog).map((module) => {
          const result = state.modules[module];
          const status = result ? result.status : state.phase === "running" ? "running" : "pending";
          const Icon = STATUS_ICONS[status] ?? CircleMinus;
          return (
            <li key={module} className={styles.module} data-status={status}>
              <Icon aria-hidden className={status === "running" ? `${styles.moduleIcon} spin` : styles.moduleIcon} />
              <span className={styles.moduleName}>{moduleLabel(module)}</span>
              <span className={styles.moduleStatus}>{t(`moduleStatus.${status}`)}</span>
              <span className={`${styles.moduleDuration} mono`}>{result ? formatModuleDuration(result.duration, lang) : ""}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
