import { FileUp, LoaderCircle, X } from "lucide-react";
import { type ChangeEvent, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { errorDetail } from "../../api/client";
import type { ImportResult } from "../../api/ops";
import { useImportDatabase } from "../../api/opsQueries";
import { MAX_IMPORT_MIB, type UploadProgress } from "../../api/upload";
import { SectionTitle } from "../../components/SectionTitle";
import { useToast } from "../../components/Toasts";
import { useLang } from "../../i18n";
import { formatBytes, formatNumber } from "../../lib/format";
import styles from "./settings.module.css";

const MAX_IMPORT_BYTES = MAX_IMPORT_MIB * 1024 * 1024;

function isAbort(error: unknown): boolean {
  return (error as { name?: unknown } | null)?.name === "AbortError";
}

// Les six chiffres du serveur, puis les colonnes de l'ancienne base qui n'ont pas d'équivalent.
function Result({ result }: { result: ImportResult }) {
  const { t } = useTranslation();
  const lang = useLang();
  const rows: Array<[string, number, boolean]> = [
    ["read", result.read, false],
    ["imported", result.imported, false],
    ["ignored", result.ignored, false],
    ["duplicates", result.duplicates, true],
    ["unusable", result.unusable, true],
  ];
  const summary =
    result.imported > 0
      ? t("settings.import.summary", { count: result.imported })
      : result.read === 0
        ? t("settings.import.nothingToImport")
        : t("settings.import.nothingNew");
  return (
    <div className={styles.importResult} role="status" aria-label={t("settings.import.result.title")} data-testid="import-result">
      <h3 className={styles.importResultTitle}>{t("settings.import.result.title")}</h3>
      <p>{summary}</p>
      <dl className={styles.importCounts}>
        {rows.map(([key, value, nested]) => (
          <div key={key} className={nested ? styles.importNested : undefined}>
            <dt>{t(`settings.import.result.${key}`)}</dt>
            <dd className="mono">{formatNumber(value, lang)}</dd>
          </div>
        ))}
      </dl>
      {result.unknown_columns.length > 0 && (
        <div>
          <p className={styles.muted}>{t("settings.import.result.unknownColumns")}</p>
          <ul className={styles.importColumns}>
            {result.unknown_columns.map((name) => (
              <li key={name} className="mono">
                {name}
              </li>
            ))}
          </ul>
        </div>
      )}
      {result.imported > 0 && (
        <p>
          <Link to="/history">{t("settings.import.history")}</Link>
        </p>
      )}
    </div>
  );
}

// Import d'une ancienne base : le fichier .db part vers le serveur (POST /api/import) avec
// l'avancement de l'envoi, puis le résultat ou l'erreur (texte du serveur, déjà traduit).
export function ImportSection() {
  const { t } = useTranslation();
  const lang = useLang();
  const toast = useToast();
  const run = useImportDatabase();
  const input = useRef<HTMLInputElement>(null);
  const controller = useRef<AbortController | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<UploadProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cancelled, setCancelled] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);

  const tooBig = file !== null && file.size > MAX_IMPORT_BYTES;
  const pending = run.isPending;
  // Octets tous envoyés : le serveur lit la base, sans avancement mesurable.
  const received = progress !== null && progress.total > 0 && progress.loaded >= progress.total;
  const percent = progress && progress.total > 0 ? Math.min(100, Math.floor((progress.loaded / progress.total) * 100)) : 0;

  const choose = (event: ChangeEvent<HTMLInputElement>) => {
    const chosen = event.target.files?.[0] ?? null;
    // Le même fichier peut être rechoisi (après une erreur) : le champ repart vide.
    event.target.value = "";
    if (!chosen) return;
    setFile(chosen);
    setResult(null);
    setError(null);
    setCancelled(false);
    setProgress(null);
  };

  const start = () => {
    if (!file || pending || tooBig) return;
    const abort = new AbortController();
    controller.current = abort;
    setResult(null);
    setError(null);
    setCancelled(false);
    setProgress({ loaded: 0, total: file.size });
    run.mutate(
      { file, onProgress: setProgress, signal: abort.signal },
      {
        onSuccess: (data) => {
          setResult(data);
          if (data.imported > 0) toast.show(t("settings.import.done", { count: data.imported }), "success");
        },
        onError: (failure) => {
          if (isAbort(failure)) setCancelled(true);
          else setError(errorDetail(failure));
        },
        onSettled: () => {
          controller.current = null;
          setProgress(null);
        },
      },
    );
  };

  return (
    <section className={styles.card} aria-labelledby="settings-import">
      <SectionTitle level={2} label={t("settings.import.kicker")} title={t("settings.import.title")} id="settings-import" />
      <p className={styles.muted}>{t("settings.import.text")}</p>
      <input
        ref={input}
        type="file"
        accept=".db,.sqlite,.sqlite3,.db3"
        className="visually-hidden"
        aria-label={t("settings.import.fileLabel")}
        tabIndex={-1}
        onChange={choose}
      />
      <div className={styles.importFile}>
        <button type="button" className="btn" disabled={pending} onClick={() => input.current?.click()}>
          <FileUp aria-hidden />
          {t(file ? "settings.import.change" : "settings.import.choose")}
        </button>
        {file ? (
          <p className={styles.importName}>
            <span className="mono">{file.name}</span>
            <span className={styles.muted}> · {formatBytes(file.size, lang)}</span>
          </p>
        ) : (
          <p className={styles.muted}>{t("settings.import.noFile")}</p>
        )}
      </div>
      {tooBig && file && (
        <p className={styles.error} role="alert">
          {t("settings.import.tooBig", { size: formatBytes(file.size, lang), max: formatBytes(MAX_IMPORT_BYTES, lang) })}
        </p>
      )}
      <div className={styles.actions}>
        <button type="button" className="btn" data-variant="primary" disabled={!file || tooBig || pending} onClick={start}>
          {pending ? <LoaderCircle aria-hidden className="spin" /> : null}
          {t("settings.import.start")}
        </button>
        {pending && (
          <button type="button" className="btn" data-variant="ghost" onClick={() => controller.current?.abort()}>
            <X aria-hidden />
            {t("settings.import.cancel")}
          </button>
        )}
      </div>
      {pending && (
        <div className={styles.importProgress}>
          {/* Sans valeur, la barre est indéterminée : le serveur lit la base, le temps n'est pas mesurable. */}
          <progress
            className={styles.progress}
            max={100}
            {...(received ? {} : { value: percent })}
            aria-label={t("settings.import.title")}
          />
          <p className={styles.muted} role="status">
            {received ? t("settings.import.processing") : t("settings.import.uploading", { percent })}
          </p>
        </div>
      )}
      {error && (
        <p className={styles.error} role="alert">
          {error}
        </p>
      )}
      {cancelled && (
        <p className={styles.muted} role="status">
          {t("settings.import.cancelled")}
        </p>
      )}
      {result && <Result result={result} />}
      <p className={styles.muted}>{t("settings.import.hint")}</p>
    </section>
  );
}
