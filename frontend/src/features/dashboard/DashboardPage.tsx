import { GitCompare, LayoutDashboard } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { errorDetail } from "../../api/client";
import { useDashboard } from "../../api/opsQueries";
import type { DashboardItem } from "../../api/ops";
import { EmptyHint } from "../../components/EmptyHint";
import { GradeBadge } from "../../components/GradeBadge";
import { ErrorState, Loading } from "../../components/PageState";
import { Pill, ScanStatusPill } from "../../components/Pills";
import { SectionTitle } from "../../components/SectionTitle";
import { Sparkline } from "../../components/Sparkline";
import { StatCard } from "../../components/StatCard";
import { useLang } from "../../i18n";
import { formatDate, formatNumber } from "../../lib/format";
import { useDocumentTitle } from "../../lib/useDocumentTitle";
import styles from "../../styles/ops.module.css";

function Row({ item }: { item: DashboardItem }) {
  const { t } = useTranslation();
  const lang = useLang();
  const urgent = item.findings.critical + item.findings.high;
  return (
    <tr>
      <th scope="row">
        <Link to={`/scans/${item.scan_id}`} className={styles.mono}>
          {item.domain}
        </Link>
      </th>
      <td>
        <GradeBadge grade={item.grade} size="sm" />
      </td>
      <td className={styles.mono}>{item.score === null ? t("common.na") : formatNumber(item.score, lang, 1)}</td>
      <td>
        <Sparkline
          values={item.trend.map((point) => point.score)}
          label={t("dashboard.trend", { domain: item.domain })}
        />
      </td>
      <td>
        {item.findings.total === 0 ? (
          <span className={styles.muted}>{t("dashboard.noFindings")}</span>
        ) : (
          <Pill tone={urgent > 0 ? "critical" : "warning"}>
            {t("dashboard.findings", { count: item.findings.total, urgent })}
          </Pill>
        )}
      </td>
      <td>{item.watch ? <Pill tone={item.watch.enabled ? "accent" : "neutral"}>{t(`monitoring.frequency.${item.watch.frequency}`)}</Pill> : <span className={styles.muted}>—</span>}</td>
      <td>
        <ScanStatusPill status={item.status} />
      </td>
      <td className={styles.muted}>{formatDate(item.scan_timestamp, lang)}</td>
      <td>
        {item.scans_count >= 2 && (
          <Link to={`/compare?domain=${encodeURIComponent(item.domain)}`} className="btn" data-variant="ghost">
            <GitCompare aria-hidden />
            {t("dashboard.compare")}
          </Link>
        )}
      </td>
    </tr>
  );
}

export function DashboardPage() {
  const { t } = useTranslation();
  const lang = useLang();
  const dashboard = useDashboard();
  useDocumentTitle(t("dashboard.title"));

  return (
    <div className={styles.page}>
      <SectionTitle level={1} size="page" label={t("dashboard.kicker")} title={t("dashboard.title")} />
      <p className={styles.lead}>{t("dashboard.lead")}</p>
      {dashboard.isPending ? (
        <Loading />
      ) : dashboard.isError ? (
        <ErrorState detail={errorDetail(dashboard.error)} onRetry={() => void dashboard.refetch()} />
      ) : dashboard.data.domains.length === 0 ? (
        <EmptyHint icon={LayoutDashboard} title={t("dashboard.emptyTitle")} text={t("dashboard.emptyText")}>
          <Link to="/" className="btn" data-variant="primary">
            {t("dashboard.emptyAction")}
          </Link>
        </EmptyHint>
      ) : (
        <>
          <div className={styles.grid}>
            <StatCard variant="secondary" label={t("dashboard.stats.domains")} value={dashboard.data.totals.domains} />
            <StatCard
              variant="secondary"
              label={t("dashboard.stats.average")}
              value={
                dashboard.data.totals.average_score === null
                  ? t("common.na")
                  : formatNumber(dashboard.data.totals.average_score, lang, 1)
              }
            />
            <StatCard
              variant="secondary"
              label={t("dashboard.stats.urgent")}
              tone={dashboard.data.totals.with_critical_or_high > 0 ? "critical" : "ok"}
              value={dashboard.data.totals.with_critical_or_high}
            />
            <StatCard variant="secondary" label={t("dashboard.stats.watched")} value={dashboard.data.totals.watched} />
          </div>
          <div className={styles.card}>
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <caption className="visually-hidden">{t("dashboard.tableCaption")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("dashboard.col.domain")}</th>
                    <th scope="col">{t("dashboard.col.grade")}</th>
                    <th scope="col">{t("dashboard.col.score")}</th>
                    <th scope="col">{t("dashboard.col.trend")}</th>
                    <th scope="col">{t("dashboard.col.findings")}</th>
                    <th scope="col">{t("dashboard.col.watch")}</th>
                    <th scope="col">{t("dashboard.col.status")}</th>
                    <th scope="col">{t("dashboard.col.last")}</th>
                    <th scope="col">
                      <span className="visually-hidden">{t("dashboard.col.actions")}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {dashboard.data.domains.map((item) => (
                    <Row key={item.domain} item={item} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
