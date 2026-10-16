import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";
import { useNotifications } from "../../api/opsQueries";
import { SectionTitle } from "../../components/SectionTitle";
import { Tabs } from "../../components/Tabs";
import { tabId, tabPanelId } from "../../lib/tabs";
import { useDocumentTitle } from "../../lib/useDocumentTitle";
import styles from "../../styles/ops.module.css";
import { NotificationCenter } from "./NotificationCenter";
import { TaskCard } from "./TaskCard";
import { WatchForm } from "./WatchForm";
import { WatchList } from "./WatchList";

const PREFIX = "monitoring";

// Surveillance : domaines scannés à intervalle régulier et comparés au scan précédent, règles
// d'alerte, canaux, tâche système et centre de notifications.
export function MonitoringPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const active = params.get("tab") === "notifications" ? "notifications" : "watches";
  const notifications = useNotifications();
  useDocumentTitle(t("monitoring.title"));

  return (
    <div className={styles.page}>
      <SectionTitle level={1} size="page" label={t("monitoring.kicker")} title={t("monitoring.title")} />
      <p className={styles.lead}>{t("monitoring.lead")}</p>
      <Tabs
        tabs={[
          { key: "watches", label: t("monitoring.tabs.watches") },
          {
            key: "notifications",
            label: t("monitoring.tabs.notifications"),
            count: notifications.data?.unread || undefined,
            tone: "warning",
          },
        ]}
        activeKey={active}
        onChange={(key) => setParams(key === "watches" ? {} : { tab: key })}
        label={t("monitoring.tabs.label")}
        idPrefix={PREFIX}
      />
      <div role="tabpanel" id={tabPanelId(PREFIX)} aria-labelledby={tabId(PREFIX, active)} className={styles.stack}>
        {active === "watches" ? (
          <>
            <WatchList />
            <WatchForm />
            <TaskCard />
          </>
        ) : (
          <NotificationCenter />
        )}
      </div>
    </div>
  );
}
