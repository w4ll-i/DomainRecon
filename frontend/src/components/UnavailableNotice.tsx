import { CircleMinus, CircleQuestionMark } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { ModuleAvailability } from "../lib/moduleState";
import styles from "./UnavailableNotice.module.css";

// Module sans résultat : jamais un « rien trouvé ».
export function UnavailableNotice({ state }: { state: ModuleAvailability }) {
  const { t } = useTranslation();
  const skipped = state.status === "skipped" || state.status === "not_launched";
  const Icon = skipped ? CircleMinus : CircleQuestionMark;
  return (
    <div className={styles.notice} data-kind={skipped ? "skipped" : "unmeasured"} role="note">
      <Icon aria-hidden className={styles.icon} />
      <div className={styles.body}>
        <p className={styles.title}>{t(`moduleStatus.${state.status}`)}</p>
        {state.error && <p className={styles.reason}>{state.error}</p>}
        <p className={styles.hint}>{t(state.status === "not_launched" ? "unavailable.notLaunchedHint" : skipped ? "unavailable.skippedHint" : "unavailable.unmeasuredHint")}</p>
      </div>
    </div>
  );
}
