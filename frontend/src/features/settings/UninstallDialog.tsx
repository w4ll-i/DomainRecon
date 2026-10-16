import { Check, Copy, Download, LoaderCircle, TriangleAlert } from "lucide-react";
import { useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorDetail } from "../../api/client";
import {
  CONFIRM_WORD,
  fetchBackup,
  type UninstallItem,
  type UninstallReport,
  type UninstallStep,
  useFinishUninstall,
  useUninstall,
  useUninstallPlan,
} from "../../api/uninstall";
import { Modal } from "../../components/Modal";
import { useLang } from "../../i18n";
import { copyText } from "../../lib/clipboard";
import { downloadBlob } from "../../lib/download";
import { formatBytes, formatNumber } from "../../lib/format";
import styles from "./uninstall.module.css";

const STEPS = ["plan", "backup", "confirm", "result"] as const;
type Step = (typeof STEPS)[number];

// Sortes connues (uninstall.kind.*) ; une sorte inconnue d'un serveur plus récent s'affiche telle quelle.
const KINDS = new Set([
  "database",
  "screenshots",
  "logs",
  "webview",
  "settings_file",
  "secret_key",
  "other_data",
  "data_dir",
  "cache",
  "temp",
  "system_task",
]);

const PORTABLE = new Set(["portable_onefile", "portable_folder"]);

function Steps({ current }: { current: Step }) {
  const { t } = useTranslation();
  const index = STEPS.indexOf(current);
  return (
    <ol className={styles.steps} aria-label={t("uninstall.steps.label")}>
      {STEPS.map((step, i) => (
        <li
          key={step}
          className={i < index ? `${styles.step} ${styles.stepDone}` : styles.step}
          aria-current={i === index ? "step" : undefined}
        >
          {t(`uninstall.steps.${step}`)}
        </li>
      ))}
    </ol>
  );
}

function ItemList({ items, showStatus }: { items: UninstallItem[]; showStatus: boolean }) {
  const { t } = useTranslation();
  const lang = useLang();
  return (
    // tabIndex : la liste défile en hauteur ; sans arrêt de tabulation, le clavier ne pourrait pas la faire défiler.
    <ul className={styles.list} data-testid="uninstall-items" tabIndex={0}>
      {items.map((item, i) => (
        <li key={`${item.kind}-${item.path ?? i}`} className={styles.row}>
          <span>{KINDS.has(item.kind) ? t(`uninstall.kind.${item.kind}`) : item.kind}</span>
          {showStatus ? (
            <span className={item.status === "failed" || item.status === "skipped" ? styles.statusFailed : styles.statusOk}>
              {t(`uninstall.status.${item.status}`)}
            </span>
          ) : (
            <span className={`${styles.size} mono`}>{item.size ? formatBytes(item.size, lang) : ""}</span>
          )}
          {item.path && <span className={`${styles.path} mono`}>{item.path}</span>}
        </li>
      ))}
    </ul>
  );
}

function StepNote({ step }: { step: UninstallStep }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const code = step.code === "external_database" && step.path === "database_url" ? "external_database_url" : step.code;
  const text = t(`uninstall.remaining.${code}`, { path: step.path ?? "", defaultValue: step.code });
  return (
    <li>
      {text}
      {step.command && (
        <span className={styles.command}>
          <code className="mono">{step.command}</code>
          <button
            type="button"
            className="btn"
            data-variant="ghost"
            onClick={() => void copyText(step.command ?? "").then((ok) => setCopied(ok))}
          >
            {copied ? <Check aria-hidden /> : <Copy aria-hidden />}
            {t(copied ? "uninstall.result.copied" : "uninstall.result.copy")}
          </button>
        </span>
      )}
    </li>
  );
}

// Étapes restantes annoncées par le serveur ; pour une version portable, la case
// « supprimer aussi le programme » change l'annonce avant la désinstallation.
function notes(report: UninstallReport, removeProgram: boolean): UninstallStep[] {
  if (!report.dry_run || !removeProgram) return report.remaining;
  return report.remaining.map((step) => (step.code === "delete_program" ? { ...step, code: "program_scheduled" } : step));
}

// Désinstallation complète en quatre étapes : ce qui sera supprimé (inventaire à blanc du
// serveur), sauvegarde proposée, confirmation en tapant le mot demandé, résultat et suite.
export function UninstallDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const lang = useLang();
  const titleId = useId();
  const [step, setStep] = useState<Step>("plan");
  const [removeProgram, setRemoveProgram] = useState(false);
  const [typed, setTyped] = useState("");
  const [backup, setBackup] = useState<{ state: "idle" | "running" | "done" | "error"; detail?: string }>({ state: "idle" });
  const [closing, setClosing] = useState<"no" | "yes" | "manual">("no");
  const plan = useUninstallPlan(open && step !== "result");
  const run = useUninstall();
  const finish = useFinishUninstall();
  const input = useRef<HTMLInputElement>(null);
  // Focus de chaque étape : le bouton qui avait le focus disparaît au changement d'étape ;
  // sans cible, le focus tomberait sur la page, hors de la fenêtre (Modal refocalise à chaque
  // changement de initialFocus).
  const planFocus = useRef<HTMLButtonElement>(null);
  const backupFocus = useRef<HTMLButtonElement>(null);
  const resultFocus = useRef<HTMLButtonElement>(null);
  const stepFocus = { plan: planFocus, backup: backupFocus, confirm: input, result: resultFocus }[step];
  const word = CONFIRM_WORD[lang];
  const result = run.data;
  const done = result !== undefined;

  const reset = () => {
    setStep("plan");
    setRemoveProgram(false);
    setTyped("");
    setBackup({ state: "idle" });
    setClosing("no");
    run.reset();
  };

  const cancel = () => {
    // Pendant la suppression, ou une fois DomainRecon désinstallé, la fenêtre ne se ferme plus
    // d'un Échap : il ne reste qu'à fermer l'application.
    if (run.isPending || (done && result.can_exit)) return;
    reset();
    onClose();
  };

  const download = async () => {
    setBackup({ state: "running" });
    try {
      const { blob, filename } = await fetchBackup(lang);
      downloadBlob(blob, filename);
      setBackup({ state: "done", detail: filename });
    } catch (error) {
      setBackup({ state: "error", detail: errorDetail(error) });
    }
  };

  const confirm = () => {
    if (typed.trim().toUpperCase() !== word || run.isPending) return;
    run.mutate({ confirm: word, remove_program: removeProgram }, { onSuccess: () => setStep("result") });
  };

  const close = () =>
    finish.mutate(undefined, {
      onSuccess: (data) => setClosing(data.exiting ? "yes" : "manual"),
      onError: () => setClosing("manual"),
    });

  const report = plan.data;
  const canRemoveProgram = report !== undefined && PORTABLE.has(report.mode) && report.program_removal.available;

  return (
    <Modal open={open} role="alertdialog" labelledBy={titleId} onCancel={cancel} initialFocus={stepFocus}>
      <div className={styles.body} data-testid="uninstall-dialog">
        <h2 id={titleId} className={styles.heading}>
          <TriangleAlert aria-hidden />
          {t("uninstall.dialogTitle")}
        </h2>
        <Steps current={step} />

        {step === "plan" && (
          <>
            {plan.isPending ? (
              <p className={styles.muted} role="status">
                <LoaderCircle aria-hidden className="spin" /> {t("uninstall.plan.loading")}
              </p>
            ) : plan.isError ? (
              <p className={styles.error} role="alert">
                {t("uninstall.plan.error", { detail: errorDetail(plan.error) })}
              </p>
            ) : (
              <>
                <p className={styles.muted}>{t("uninstall.plan.mode", { mode: t(`uninstall.mode.${plan.data.mode}`) })}</p>
                {plan.data.items.length > 0 ? (
                  <>
                    <p>{t("uninstall.plan.intro")}</p>
                    <ItemList items={plan.data.items} showStatus={false} />
                    <p className={styles.muted}>{t("uninstall.plan.total", { size: formatBytes(plan.data.total_size, lang) })}</p>
                  </>
                ) : (
                  <p>{t("uninstall.plan.empty")}</p>
                )}
                {canRemoveProgram && (
                  <label className={styles.check}>
                    <input type="checkbox" checked={removeProgram} onChange={(event) => setRemoveProgram(event.target.checked)} />
                    <span>
                      {t("uninstall.plan.removeProgram")}
                      <br />
                      <span className={styles.muted}>{t("uninstall.plan.removeProgramHint")}</span>
                    </span>
                  </label>
                )}
                <p>{t("uninstall.plan.after")}</p>
                <ul className={styles.notes}>
                  {notes(plan.data, removeProgram).map((note) => (
                    <StepNote key={note.code} step={note} />
                  ))}
                </ul>
              </>
            )}
            <div className={styles.actions}>
              <button ref={planFocus} type="button" className="btn" onClick={cancel}>
                {t("common.cancel")}
              </button>
              <button type="button" className="btn" data-variant="primary" disabled={!plan.isSuccess} onClick={() => setStep("backup")}>
                {t("uninstall.next")}
              </button>
            </div>
          </>
        )}

        {step === "backup" && (
          <>
            <p>{t("uninstall.backup.intro")}</p>
            <div>
              <button ref={backupFocus} type="button" className="btn" disabled={backup.state === "running"} onClick={() => void download()}>
                {backup.state === "running" ? <LoaderCircle aria-hidden className="spin" /> : <Download aria-hidden />}
                {t("uninstall.backup.download")}
              </button>
            </div>
            {backup.state === "done" && (
              <p className={styles.muted} role="status">
                {t("uninstall.backup.done", { name: backup.detail })}
              </p>
            )}
            {backup.state === "error" && (
              <p className={styles.error} role="alert">
                {t("uninstall.backup.error", { detail: backup.detail })}
              </p>
            )}
            <div className={styles.actions}>
              <button type="button" className="btn" data-variant="ghost" onClick={() => setStep("plan")}>
                {t("uninstall.back")}
              </button>
              <span className={styles.spacer} />
              <button type="button" className="btn" onClick={cancel}>
                {t("common.cancel")}
              </button>
              <button type="button" className="btn" data-variant="primary" onClick={() => setStep("confirm")}>
                {t(backup.state === "done" ? "uninstall.next" : "uninstall.backup.skip")}
              </button>
            </div>
          </>
        )}

        {step === "confirm" && (
          <form
            className={styles.body}
            onSubmit={(event) => {
              event.preventDefault();
              confirm();
            }}
          >
            <p>{t("uninstall.confirm.intro", { word })}</p>
            <label className={styles.body}>
              <span className={styles.muted}>{t("uninstall.confirm.label", { word })}</span>
              <input
                ref={input}
                className={styles.input}
                value={typed}
                autoComplete="off"
                spellCheck={false}
                disabled={run.isPending}
                onChange={(event) => setTyped(event.target.value)}
              />
            </label>
            {run.isError && (
              <p className={styles.error} role="alert">
                {t("uninstall.confirm.error", { detail: errorDetail(run.error) })}
              </p>
            )}
            <div className={styles.actions}>
              <button type="button" className="btn" data-variant="ghost" disabled={run.isPending} onClick={() => setStep("backup")}>
                {t("uninstall.back")}
              </button>
              <span className={styles.spacer} />
              <button type="button" className="btn" disabled={run.isPending} onClick={cancel}>
                {t("common.cancel")}
              </button>
              <button type="submit" className="btn" data-variant="danger" disabled={typed.trim().toUpperCase() !== word || run.isPending}>
                {run.isPending && <LoaderCircle aria-hidden className="spin" />}
                {t(run.isPending ? "uninstall.confirm.running" : "uninstall.confirm.submit")}
              </button>
            </div>
          </form>
        )}

        {step === "result" && result && (
          <>
            <p role="status">
              <strong>{t("uninstall.result.done")}</strong>{" "}
              {t("uninstall.result.deleted", {
                count: formatNumber(result.items.filter((item) => item.status === "deleted").length, lang),
              })}
            </p>
            <ItemList items={result.items} showStatus />
            {result.items.some((item) => item.status === "failed") && <p className={styles.error}>{t("uninstall.result.failed")}</p>}
            <p>{t("uninstall.result.remaining")}</p>
            <ul className={styles.notes} data-testid="uninstall-remaining">
              {result.remaining.map((note) => (
                <StepNote key={note.code} step={note} />
              ))}
            </ul>
            {closing === "yes" && (
              <p className={styles.muted} role="status">
                {t("uninstall.result.closing")}
              </p>
            )}
            {closing === "manual" && (
              <p className={styles.muted} role="status">
                {t("uninstall.result.closeManually")}
              </p>
            )}
            <div className={styles.actions}>
              {result.can_exit ? (
                <button
                  ref={resultFocus}
                  type="button"
                  className="btn"
                  data-variant="primary"
                  disabled={finish.isPending || closing === "yes"}
                  onClick={close}
                >
                  {t("uninstall.result.close")}
                </button>
              ) : (
                <button ref={resultFocus} type="button" className="btn" data-variant="primary" onClick={cancel}>
                  {t("uninstall.result.dismiss")}
                </button>
              )}
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
