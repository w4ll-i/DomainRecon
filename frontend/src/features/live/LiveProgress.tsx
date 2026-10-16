import { useTranslation } from "react-i18next";
import { useCatalog } from "../../api/queries";
import { useModuleLabel } from "../../lib/useModuleLabel";
import type { LiveState } from "./liveReducer";
import styles from "./LiveScanPage.module.css";
import { currentModule, formatClock, isoDuration } from "./liveView";

interface LiveProgressProps {
  live: LiveState;
  // Secondes écoulées (chronomètre).
  elapsed: number;
}

// Suivi en direct : une seule barre de progression, « n modules sur N », le module en
// cours et le chronomètre. Le texte porte l'information ; la barre ne fait que la montrer.
export function LiveProgress({ live, elapsed }: LiveProgressProps) {
  const { t } = useTranslation();
  const catalog = useCatalog();
  const label = useModuleLabel();
  const current = currentModule(live, catalog);
  const text = t("live.progressText", { done: live.done, total: live.total });
  return (
    <div className={styles.progressBlock} data-phase={live.phase}>
      <div className={styles.progressHead}>
        <p className={styles.progressText}>{text}</p>
        <time className={`${styles.clock} mono`} dateTime={isoDuration(elapsed)}>
          {formatClock(elapsed)}
        </time>
      </div>
      <progress
        id="live-progress"
        className={styles.progress}
        max={live.total}
        value={live.done}
        aria-label={t("live.progressLabel")}
        aria-valuetext={text}
      />
      <p className={styles.current} data-kind={current.kind}>
        {current.kind === "running" && (
          <>
            <span className={styles.currentLabel}>{t("live.currentLabel")}</span>
            <span className={styles.currentName}>{label(current.name)}</span>
            {current.more > 0 && <span className={`${styles.currentMore} mono`}>+{current.more}</span>}
          </>
        )}
        {current.kind === "waiting" && t("live.waitingFirst")}
        {current.kind === "finalizing" && t("live.finalizing")}
      </p>
    </div>
  );
}
