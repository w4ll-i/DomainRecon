import { useTranslation } from "react-i18next";
import { useCatalog } from "../../api/queries";
import type { ScanResponse } from "../../api/types";
import { Pill, ScanStatusPill } from "../../components/Pills";
import { ScoreGauge } from "../../components/ScoreGauge";
import { useLang } from "../../i18n";
import { formatDate, formatDuration } from "../../lib/format";
import { failedModules } from "../../lib/moduleState";
import { displayGrade, scoreUnavailable, scoreView } from "../../lib/score";
import { scanSummary } from "../../lib/summary";
import { useModuleLabel } from "../../lib/useModuleLabel";
import { familyModuleCount } from "./metrics";
import { ResultActions } from "./ResultActions";
import styles from "./result.module.css";

// En-tête du résultat : le domaine, la note en grand, le score sur 100, une phrase de
// résumé en langage clair, puis la méta (statut, date, durée, modules mesurés sur lancés).
export function ResultHeader({ scan, stale = false }: { scan: ScanResponse; stale?: boolean }) {
  const { t } = useTranslation();
  const lang = useLang();
  const catalog = useCatalog();
  const label = useModuleLabel();
  const ss = scan.security_score ?? {};
  const grade = displayGrade(ss);
  const unavailable = scoreUnavailable(ss);
  const view = scoreView(ss);
  const failed = failedModules(scan);
  const isError = scan.status === "error";
  // Un scan en erreur ou partiel est toujours signalé, même sans message ni
  // module en échec : la note seule ne dit pas qu'il est incomplet.
  const showBanner = Boolean(scan.error_message) || failed.length > 0 || isError || scan.status === "partial";
  const summary = scanSummary(scan);
  const modules = catalog.families.reduce(
    (sum, family) => {
      const count = familyModuleCount(scan, family, catalog);
      return { measured: sum.measured + count.measured, total: sum.total + count.total };
    },
    { measured: 0, total: 0 },
  );

  return (
    <header className={styles.hero}>
      <div className={styles.heroTop}>
        <h1 className={`${styles.domain} mono`}>{scan.domain}</h1>
        <ResultActions scan={scan} stale={stale} />
      </div>
      {/* Note, score et couverture : un seul bloc, cible de la visite guidée (étape « Note »). */}
      <div className={styles.scoreBlock} data-tour="result-score">
        <div className={styles.verdict}>
          <ScoreGauge
            grade={grade}
            score={view.value}
            coverage={typeof ss.coverage === "number" ? ss.coverage : null}
            indicative={view.kind === "indicative"}
          />
          <p className={styles.summary}>{t(summary.key, summary.params)}</p>
        </div>
        {/* Le score en chiffres est dans la note ; seuls « indicatif » et « pas de note » se disent ici. */}
        {view.kind !== "score" && (
          <p className={styles.scoreNote}>
            {view.kind === "indicative" ? t("result.indicative", { score: view.value }) : t("result.scoreNA")}
          </p>
        )}
        {unavailable && ss.grade_reason && <p className={styles.reason}>{ss.grade_reason}</p>}
        <dl className={styles.meta}>
          <div>
            <dt>{t("result.status")}</dt>
            <dd>
              <ScanStatusPill status={scan.status} />
            </dd>
          </div>
          <div>
            <dt>{t("result.date")}</dt>
            <dd>{formatDate(scan.scan_timestamp, lang)}</dd>
          </div>
          <div>
            <dt>{t("result.duration")}</dt>
            <dd>{formatDuration(scan.scan_duration, lang)}</dd>
          </div>
          <div>
            <dt>{t("result.modulesLabel")}</dt>
            <dd>{t("result.modulesCount", { measured: modules.measured, total: modules.total })}</dd>
          </div>
          {typeof ss.coverage === "number" && (
            <div>
              <dt>{t("result.coverageLabel")}</dt>
              <dd>
                {t("result.coverage", { coverage: ss.coverage })}
                {ss.confidence ? ` · ${t("result.confidence", { level: t(`confidence.${ss.confidence}`) })}` : ""}
              </dd>
            </div>
          )}
        </dl>
      </div>
      {showBanner && (
        <div className={styles.banner} data-tone={isError ? "critical" : "warning"} role={isError ? "alert" : "status"}>
          <p className={styles.bannerTitle}>{t(isError ? "result.errorTitle" : "result.partialTitle")}</p>
          {scan.error_message && <p className={styles.bannerText}>{scan.error_message}</p>}
          {!scan.error_message && failed.length === 0 && <p className={styles.bannerText}>{t("result.noDetail")}</p>}
          {failed.length > 0 && (
            <>
              <p className={styles.bannerHint}>{t("result.failedModules", { count: failed.length })}</p>
              <ul className={styles.failedList}>
                {failed.map((module) => (
                  <li key={module.name} className={styles.failedItem}>
                    {/* Ton neutral : le texte secondaire ne se pose pas sur le fond teinté du bandeau. */}
                    <Pill tone="neutral">
                      {label(module.name)}
                      {module.status === "timeout" ? ` ${t("result.timeoutSuffix")}` : ""}
                    </Pill>
                    {module.error && <span className={styles.failedReason}>{module.error}</span>}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </header>
  );
}
