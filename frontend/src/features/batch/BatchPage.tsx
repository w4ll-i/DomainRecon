import { Download, Files, Upload } from "lucide-react";
import { type ChangeEvent, type FormEvent, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";
import { errorDetail } from "../../api/client";
import type { BatchItemStatus, BatchView } from "../../api/ops";
import { useBatch, useCancelBatch, useStartBatch } from "../../api/opsQueries";
import { EmptyHint } from "../../components/EmptyHint";
import { GradeBadge } from "../../components/GradeBadge";
import { ErrorState, Loading } from "../../components/PageState";
import { Pill } from "../../components/Pills";
import { SectionTitle } from "../../components/SectionTitle";
import { useToast } from "../../components/Toasts";
import { downloadBlob } from "../../lib/download";
import type { Tone } from "../../lib/tones";
import { useDocumentTitle } from "../../lib/useDocumentTitle";
import styles from "../../styles/ops.module.css";
import { batchCsv, parseDomainList } from "./batchList";
import { ProfilePicker } from "../newscan/ProfilePicker";
import { useScanOptions } from "../newscan/scanOptions";

// Taille maximale d'un fichier de liste importé (le serveur plafonne à 100 domaines).
const MAX_FILE_BYTES = 512 * 1024;

const STATUS_TONES: Record<BatchItemStatus, Tone> = {
  queued: "neutral",
  running: "accent",
  done: "ok",
  failed: "critical",
  cancelled: "na",
};

function Progress({ batch }: { batch: BatchView }) {
  const { t } = useTranslation();
  const cancel = useCancelBatch();
  const toast = useToast();
  const running = batch.status === "running" || batch.status === "queued";
  return (
    <div className={styles.card}>
      <div className={`${styles.row} ${styles.between}`}>
        <p role="status">{t("batch.progress", { done: batch.finished, total: batch.total })}</p>
        <div className={styles.row}>
          {running && (
            <button
              type="button"
              className="btn"
              data-variant="danger"
              disabled={cancel.isPending}
              onClick={() =>
                cancel.mutate(batch.id, { onError: (error) => toast.show(errorDetail(error), "error") })
              }
            >
              {t("batch.cancel")}
            </button>
          )}
          {batch.items && batch.items.length > 0 && (
            <button
              type="button"
              className="btn"
              onClick={() =>
                downloadBlob(new Blob([batchCsv(batch.items ?? [])], { type: "text/csv;charset=utf-8" }), `domainrecon_lot_${batch.id.slice(0, 8)}.csv`)
              }
            >
              <Download aria-hidden />
              {t("batch.exportCsv")}
            </button>
          )}
        </div>
      </div>
      <progress className={styles.progress} max={batch.total} value={batch.finished} aria-label={t("batch.progressLabel")} />
      <p className={styles.muted}>
        {t("batch.counts", {
          done: batch.counts.done,
          failed: batch.counts.failed,
          cancelled: batch.counts.cancelled,
        })}
      </p>
      {(batch.items?.length ?? 0) > 0 && (
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <caption className="visually-hidden">{t("batch.tableCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("batch.col.domain")}</th>
                <th scope="col">{t("batch.col.status")}</th>
                <th scope="col">{t("batch.col.grade")}</th>
                <th scope="col">{t("batch.col.score")}</th>
                <th scope="col">{t("batch.col.result")}</th>
              </tr>
            </thead>
            <tbody>
              {batch.items?.map((item) => (
                <tr key={item.domain}>
                  <th scope="row" className={styles.mono}>
                    {item.domain}
                  </th>
                  <td>
                    <Pill tone={STATUS_TONES[item.status]}>{t(`batch.status.${item.status}`)}</Pill>
                  </td>
                  <td>{item.grade ? <GradeBadge grade={item.grade} size="sm" /> : "—"}</td>
                  <td className={styles.mono}>{item.score ?? "—"}</td>
                  <td>
                    {item.scan_id !== null ? (
                      <Link to={`/scans/${item.scan_id}`}>{t("batch.open")}</Link>
                    ) : item.error ? (
                      <span className={styles.error}>{item.error}</span>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// Lot : coller une liste (ou importer un .txt/.csv), choisir le profil, suivre l'avancement,
// ouvrir chaque résultat et exporter le tableau en CSV.
export function BatchPage() {
  const { t } = useTranslation();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const batchId = params.get("batch");
  const [text, setText] = useState("");
  const [warning, setWarning] = useState<{ rejected: BatchView["rejected"]; duplicates: number } | null>(null);
  const scan = useScanOptions();
  const start = useStartBatch();
  const batch = useBatch(batchId);
  const file = useRef<HTMLInputElement>(null);
  useDocumentTitle(t("batch.title"));

  const domains = parseDomainList(text);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (domains.length === 0) return;
    start.mutate(
      { domains, authorized_target: false, ...scan.payload(), profile: scan.options.profile },
      {
        onSuccess: (view) => {
          setWarning({ rejected: view.rejected ?? [], duplicates: view.duplicates ?? 0 });
          setParams({ batch: view.id });
        },
        onError: (error) => toast.show(errorDetail(error), "error"),
      },
    );
  };

  const importFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const chosen = event.target.files?.[0];
    event.target.value = "";
    if (!chosen) return;
    if (chosen.size > MAX_FILE_BYTES) {
      toast.show(t("batch.fileTooBig"), "warning");
      return;
    }
    try {
      const content = await chosen.text();
      setText((current) => (current.trim() ? `${current.trim()}\n${content}` : content));
    } catch {
      toast.show(t("batch.fileError"), "error");
    }
  };

  return (
    <div className={styles.page}>
      <SectionTitle level={1} size="page" label={t("batch.kicker")} title={t("batch.title")} />
      <p className={styles.lead}>{t("batch.lead")}</p>

      <form className={styles.card} onSubmit={submit}>
        <div className={styles.field}>
          <label htmlFor="batch-list">{t("batch.listLabel")}</label>
          <textarea
            id="batch-list"
            className={styles.textarea}
            value={text}
            onChange={(event) => setText(event.target.value)}
            placeholder={t("batch.listPlaceholder")}
            spellCheck={false}
          />
        </div>
        <div className={styles.row}>
          <input
            ref={file}
            type="file"
            accept=".txt,.csv,text/plain,text/csv"
            className="visually-hidden"
            aria-label={t("batch.importLabel")}
            onChange={(event) => void importFile(event)}
          />
          <button type="button" className="btn" onClick={() => file.current?.click()}>
            <Upload aria-hidden />
            {t("batch.import")}
          </button>
          <span className={styles.muted} role="status">
            {t("batch.detected", { count: domains.length })}
          </span>
        </div>
        <ProfilePicker
          catalog={scan.catalog}
          value={scan.options}
          onChange={scan.setOptions}
          needsAuth={scan.needsAuth}
          plural
        />
        <div>
          <button type="submit" className="btn" data-variant="primary" disabled={start.isPending || domains.length === 0 || !scan.valid}>
            <Files aria-hidden />
            {t("batch.start", { count: domains.length })}
          </button>
        </div>
      </form>

      {warning && ((warning.rejected?.length ?? 0) > 0 || warning.duplicates > 0) && (
        <div className={styles.card} role="status">
          {warning.duplicates > 0 && <p className={styles.muted}>{t("batch.duplicates", { count: warning.duplicates })}</p>}
          {(warning.rejected?.length ?? 0) > 0 && (
            <>
              <p className={styles.error}>{t("batch.rejected", { count: warning.rejected?.length ?? 0 })}</p>
              <ul className={styles.diffList}>
                {warning.rejected?.map((entry) => (
                  <li key={entry.input}>
                    <span className={styles.mono}>{entry.input}</span>
                    <span className={styles.muted}>{entry.reason}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}

      {batchId === null ? (
        <EmptyHint icon={Files} title={t("batch.emptyTitle")} text={t("batch.emptyText")} />
      ) : batch.isPending ? (
        <Loading />
      ) : batch.isError ? (
        <ErrorState detail={errorDetail(batch.error)} onRetry={() => void batch.refetch()} />
      ) : (
        <Progress batch={batch.data} />
      )}
    </div>
  );
}
