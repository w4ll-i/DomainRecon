import { Eye, Pencil, Play, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { errorDetail } from "../../api/client";
import type { Frequency, Watch } from "../../api/ops";
import { useDeleteWatch, useRunWatch, useUpdateWatch, useWatches } from "../../api/opsQueries";
import { useConfirm } from "../../components/ConfirmDialog";
import { EmptyHint } from "../../components/EmptyHint";
import { ErrorState, Loading } from "../../components/PageState";
import { Pill } from "../../components/Pills";
import { useToast } from "../../components/Toasts";
import { useLang } from "../../i18n";
import { formatDate } from "../../lib/format";
import styles from "../../styles/ops.module.css";
import { FREQUENCIES } from "./watchConfig";
import { ChannelFields, RulesFields } from "./WatchForm";

// Modification des règles d'alerte et des canaux d'une surveillance existante.
function WatchEditor({ watch }: { watch: Watch }) {
  const { t } = useTranslation();
  const toast = useToast();
  const update = useUpdateWatch();
  const [rules, setRules] = useState(watch.rules);
  const [channels, setChannels] = useState(watch.channels);
  const save = () =>
    update.mutate(
      { id: watch.id, patch: { rules, channels } },
      {
        onSuccess: () => toast.show(t("monitoring.saved"), "success"),
        onError: (error) => toast.show(errorDetail(error), "error"),
      },
    );
  return (
    <div className={styles.stack}>
      <RulesFields rules={rules} onChange={setRules} idPrefix={`watch-${watch.id}`} />
      <ChannelFields channels={channels} onChange={setChannels} />
      <div>
        <button type="button" className="btn" data-variant="primary" disabled={update.isPending} onClick={save}>
          {t("monitoring.save")}
        </button>
      </div>
    </div>
  );
}

function WatchRow({ watch }: { watch: Watch }) {
  const { t } = useTranslation();
  const lang = useLang();
  const toast = useToast();
  const confirm = useConfirm();
  const update = useUpdateWatch();
  const remove = useDeleteWatch();
  const run = useRunWatch();
  const [editing, setEditing] = useState(false);
  const fail = (error: unknown) => toast.show(errorDetail(error), "error");

  const askDelete = async () => {
    const ok = await confirm({
      title: t("monitoring.deleteTitle"),
      message: t("monitoring.deleteMessage", { domain: watch.domain }),
      confirmLabel: t("common.delete"),
      danger: true,
    });
    if (ok) remove.mutate(watch.id, { onError: fail });
  };

  return (
    <>
      <tr>
        <th scope="row">
          <span className={styles.mono}>{watch.domain}</span>
        </th>
        <td>
          <select
            aria-label={t("monitoring.frequencyOf", { domain: watch.domain })}
            value={watch.frequency}
            onChange={(event) =>
              update.mutate({ id: watch.id, patch: { frequency: event.target.value as Frequency } }, { onError: fail })
            }
          >
            {FREQUENCIES.map((value) => (
              <option key={value} value={value}>
                {t(`monitoring.frequency.${value}`)}
              </option>
            ))}
          </select>
        </td>
        <td>
          <label className={styles.check}>
            <input
              type="checkbox"
              checked={watch.enabled}
              onChange={(event) => update.mutate({ id: watch.id, patch: { enabled: event.target.checked } }, { onError: fail })}
            />
            <span>{t(watch.enabled ? "monitoring.active" : "monitoring.paused")}</span>
          </label>
        </td>
        <td className={styles.muted}>
          {watch.last_run_at ? formatDate(watch.last_run_at, lang) : t("monitoring.neverRun")}
          {watch.last_status && watch.last_status !== "ok" && <Pill tone="warning">{watch.last_status}</Pill>}
          {watch.last_scan_id !== null && (
            <>
              {" "}
              <Link to={`/scans/${watch.last_scan_id}`}>{t("monitoring.lastScan")}</Link>
            </>
          )}
        </td>
        <td className={styles.muted}>{watch.enabled ? formatDate(watch.next_run_at, lang) : "—"}</td>
        <td>
          <div className={styles.row}>
            <button
              type="button"
              className="btn"
              data-variant="ghost"
              disabled={run.isPending || !watch.enabled}
              onClick={() =>
                run.mutate(watch.id, {
                  onSuccess: () => toast.show(t("monitoring.runQueued", { domain: watch.domain }), "info"),
                  onError: fail,
                })
              }
            >
              <Play aria-hidden />
              {t("monitoring.run")}
            </button>
            <button type="button" className="btn" data-variant="ghost" aria-expanded={editing} onClick={() => setEditing((value) => !value)}>
              <Pencil aria-hidden />
              {t("monitoring.edit")}
            </button>
            <button type="button" className="btn" data-variant="ghost" aria-label={t("monitoring.deleteLabel", { domain: watch.domain })} onClick={() => void askDelete()}>
              <Trash2 aria-hidden />
            </button>
          </div>
        </td>
      </tr>
      {editing && (
        <tr>
          <td colSpan={6}>
            <WatchEditor watch={watch} />
          </td>
        </tr>
      )}
    </>
  );
}

export function WatchList() {
  const { t } = useTranslation();
  const watches = useWatches();
  if (watches.isPending) return <Loading />;
  if (watches.isError) return <ErrorState detail={errorDetail(watches.error)} onRetry={() => void watches.refetch()} />;
  if (watches.data.watches.length === 0) {
    return <EmptyHint icon={Eye} title={t("monitoring.emptyTitle")} text={t("monitoring.emptyText")} />;
  }
  return (
    <div className={styles.card}>
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <caption className="visually-hidden">{t("monitoring.tableCaption")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("monitoring.col.domain")}</th>
              <th scope="col">{t("monitoring.col.frequency")}</th>
              <th scope="col">{t("monitoring.col.state")}</th>
              <th scope="col">{t("monitoring.col.last")}</th>
              <th scope="col">{t("monitoring.col.next")}</th>
              <th scope="col">
                <span className="visually-hidden">{t("monitoring.col.actions")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {watches.data.watches.map((watch) => (
              <WatchRow key={watch.id} watch={watch} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
