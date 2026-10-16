import { useState } from "react";
import { useTranslation } from "react-i18next";
import { errorDetail, isLocalOnly } from "../../api/client";
import { useSetSystemTask, useSystemTask } from "../../api/opsQueries";
import { Loading } from "../../components/PageState";
import { Pill } from "../../components/Pills";
import { useToast } from "../../components/Toasts";
import styles from "../../styles/ops.module.css";

// Tâche système : exécute « domainrecon monitor run-due » même quand l'application est fermée
// (Planificateur de tâches sous Windows, minuteur systemd utilisateur sous Linux).
export function TaskCard() {
  const { t } = useTranslation();
  const toast = useToast();
  const task = useSystemTask();
  const set = useSetSystemTask();
  // Refus « réservé à cette machine » : une règle, pas une panne (avertissement, pas erreur).
  const [restriction, setRestriction] = useState<string | null>(null);

  const toggle = (install: boolean) => {
    setRestriction(null);
    set.mutate(install, {
      onSuccess: () => toast.show(t(install ? "monitoring.task.installed" : "monitoring.task.removed"), "success"),
      onError: (error) => {
        if (isLocalOnly(error)) {
          setRestriction(errorDetail(error));
          toast.show(errorDetail(error), "warning");
        } else {
          toast.show(errorDetail(error), "error");
        }
      },
    });
  };

  return (
    <section className={styles.card} aria-labelledby="monitoring-task">
      <h2 id="monitoring-task" className={styles.emptyTitle}>
        {t("monitoring.task.title")}
      </h2>
      <p className={styles.muted}>{t("monitoring.task.hint")}</p>
      {task.isPending ? (
        <Loading />
      ) : task.isError ? (
        <p className={styles.error}>{errorDetail(task.error)}</p>
      ) : !task.data.supported ? (
        <p className={styles.muted}>{t("monitoring.task.unsupported")}</p>
      ) : (
        <>
          <div className={styles.row}>
            <Pill tone={task.data.installed ? "ok" : "neutral"}>
              {t(task.data.installed ? "monitoring.task.stateOn" : "monitoring.task.stateOff")}
            </Pill>
            {task.data.installed ? (
              <button type="button" className="btn" disabled={set.isPending} onClick={() => toggle(false)}>
                {t("monitoring.task.uninstall")}
              </button>
            ) : (
              <button type="button" className="btn" data-variant="primary" disabled={set.isPending} onClick={() => toggle(true)}>
                {t("monitoring.task.install")}
              </button>
            )}
          </div>
          {restriction && (
            <p className={styles.muted} role="status">
              {restriction}
            </p>
          )}
          {task.data.command && <code className={styles.mono}>{task.data.command}</code>}
        </>
      )}
    </section>
  );
}
