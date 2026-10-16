import { Bell, Check, Trash2 } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { errorDetail } from "../../api/client";
import { useNotificationActions, useNotifications } from "../../api/opsQueries";
import { EmptyHint } from "../../components/EmptyHint";
import { ErrorState, Loading } from "../../components/PageState";
import { Pill } from "../../components/Pills";
import { useToast } from "../../components/Toasts";
import { useLang } from "../../i18n";
import { formatDate } from "../../lib/format";
import type { Tone } from "../../lib/tones";
import styles from "../../styles/ops.module.css";

const SEVERITY_TONES: Record<string, Tone> = { critical: "critical", high: "critical", medium: "warning", low: "info" };

// Centre de notifications : alertes de la surveillance, de la plus récente à la plus ancienne.
export function NotificationCenter() {
  const { t } = useTranslation();
  const lang = useLang();
  const toast = useToast();
  const notifications = useNotifications();
  const { markRead, remove, clear } = useNotificationActions();
  const fail = (error: unknown) => toast.show(errorDetail(error), "error");

  if (notifications.isPending) return <Loading />;
  if (notifications.isError) {
    return <ErrorState detail={errorDetail(notifications.error)} onRetry={() => void notifications.refetch()} />;
  }
  const { items, unread } = notifications.data;
  if (items.length === 0) {
    return <EmptyHint icon={Bell} title={t("notifications.emptyTitle")} text={t("notifications.emptyText")} />;
  }
  return (
    <div className={styles.card}>
      <div className={`${styles.row} ${styles.between}`}>
        <p role="status">{t("notifications.unread", { count: unread })}</p>
        <div className={styles.row}>
          <button type="button" className="btn" disabled={unread === 0 || markRead.isPending} onClick={() => markRead.mutate(undefined, { onError: fail })}>
            <Check aria-hidden />
            {t("notifications.markAll")}
          </button>
          <button type="button" className="btn" disabled={clear.isPending} onClick={() => clear.mutate(undefined, { onError: fail })}>
            <Trash2 aria-hidden />
            {t("notifications.clear")}
          </button>
        </div>
      </div>
      <ul className={styles.diffList} aria-label={t("notifications.title")}>
        {items.map((item) => (
          <li key={item.id} data-read={item.is_read ? "true" : "false"}>
            <Pill tone={SEVERITY_TONES[item.severity] ?? "neutral"}>{t(`severity.${item.severity}`, { defaultValue: item.severity })}</Pill>
            <span>
              {!item.is_read && <strong>{t("notifications.new")} </strong>}
              <span className={styles.mono}>{item.domain}</span> · {item.message}
              <span className={styles.muted}> · {formatDate(item.created_at, lang)}</span>
              {item.scan_id !== null && (
                <>
                  {" "}
                  <Link to={`/scans/${item.scan_id}`}>{t("notifications.open")}</Link>
                </>
              )}
            </span>
            {!item.is_read && (
              <button type="button" className="btn" data-variant="ghost" aria-label={t("notifications.markOne", { domain: item.domain })} onClick={() => markRead.mutate([item.id], { onError: fail })}>
                <Check aria-hidden />
              </button>
            )}
            <button type="button" className="btn" data-variant="ghost" aria-label={t("notifications.removeOne", { domain: item.domain })} onClick={() => remove.mutate(item.id, { onError: fail })}>
              <Trash2 aria-hidden />
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
