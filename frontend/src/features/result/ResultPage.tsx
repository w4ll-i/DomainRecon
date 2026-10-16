import { useTranslation } from "react-i18next";
import { useParams, useSearchParams } from "react-router";
import { useCatalog, useScan } from "../../api/queries";
import { CountBadge } from "../../components/CountBadge";
import { ErrorState, Loading } from "../../components/PageState";
import { SectionTitle } from "../../components/SectionTitle";
import { Tabs } from "../../components/Tabs";
import { parseId } from "../../lib/format";
import { scoreHasDetails } from "../../lib/score";
import { tabId, tabPanelId } from "../../lib/tabs";
import type { Tone } from "../../lib/tones";
import { useDocumentTitle } from "../../lib/useDocumentTitle";
import { useRememberLastScan } from "../../lib/useLastScan";
import { FamilyRow } from "./FamilyRow";
import { FindingsList } from "./FindingsList";
import { ResultHeader } from "./ResultHeader";
import styles from "./result.module.css";
import { ScanError } from "./ScanError";
import { ScoreBreakdown } from "./ScoreBreakdown";

const TAB_PREFIX = "result";
// « À corriger » : les cinq actions les plus prioritaires d'emblée ; le reste se déplie.
const PRIORITY_LIMIT = 5;
type ResultTab = "overview" | "score";

export function ResultPage() {
  const { t } = useTranslation();
  const params = useParams();
  const [search, setSearch] = useSearchParams();
  const id = parseId(params.id);
  const query = useScan(id);
  const catalog = useCatalog();
  const scan = query.data;
  useDocumentTitle(scan ? t("result.scanTitle", { domain: scan.domain }) : t("nav.result"));

  // Scan supprimé (404) : l'entrée « Résultat » du menu ne doit plus y mener.
  useRememberLastScan(scan, query.error, id);

  if (id === null) return <ErrorState headingLevel={1} title={t("result.notFound")} detail={t("result.invalidId")} />;
  if (query.isPending) return <Loading />;
  if (query.isError) return <ScanError error={query.error} onRetry={() => void query.refetch()} />;

  const data = query.data;
  // Deux onglets quand le détail du score a de quoi se montrer ; l'onglet vit dans l'URL
  // (?tab=score) pour survivre au rechargement et se partager.
  const hasDetails = scoreHasDetails(data.security_score ?? {});
  const active: ResultTab = hasDetails && search.get("tab") === "score" ? "score" : "overview";
  const selectTab = (key: string) =>
    setSearch(
      (previous) => {
        const next = new URLSearchParams(previous);
        if (key === "score") next.set("tab", "score");
        else next.delete("tab");
        return next;
      },
      { replace: true },
    );

  const findings = data.findings ?? [];
  const severe = findings.some((finding) => finding.severity === "critical" || finding.severity === "high");
  const findingsTone: Tone = severe ? "critical" : findings.some((finding) => finding.severity === "medium") ? "warning" : "neutral";

  return (
    <div className={styles.page}>
      <ResultHeader scan={data} stale={query.isPlaceholderData} />
      {hasDetails && (
        <div>
          <Tabs
            tabs={[
              { key: "overview", label: t("result.tabs.overview") },
              { key: "score", label: t("score.title") },
            ]}
            activeKey={active}
            onChange={selectTab}
            label={t("result.tabs.label")}
            idPrefix={TAB_PREFIX}
          />
        </div>
      )}
      <div
        className={styles.panel}
        key={active}
        {...(hasDetails ? { role: "tabpanel", id: tabPanelId(TAB_PREFIX), "aria-labelledby": tabId(TAB_PREFIX, active) } : {})}
      >
        {active === "overview" ? (
          <>
            <section className={styles.section} aria-labelledby="findings-title" data-tone={findingsTone}>
              <SectionTitle
                label={t("result.findingsKicker")}
                title={t("result.findings")}
                id="findings-title"
                after={findings.length > 0 ? <CountBadge count={findings.length} tone={findingsTone} /> : null}
              />
              <FindingsList scan={data} titleId="findings-title" limit={PRIORITY_LIMIT} />
            </section>
            <section className={styles.section} aria-labelledby="families-title">
              <SectionTitle label={t("result.familiesKicker")} title={t("result.families")} id="families-title" />
              <ul className={styles.rows} aria-labelledby="families-title">
                {catalog.families.map((family) => (
                  <li key={family} data-tour="result-family">
                    <FamilyRow scan={data} family={family} />
                  </li>
                ))}
              </ul>
            </section>
          </>
        ) : (
          <ScoreBreakdown score={data.security_score ?? {}} />
        )}
      </div>
    </div>
  );
}
