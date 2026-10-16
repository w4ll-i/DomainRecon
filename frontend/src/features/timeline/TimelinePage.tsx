import { ArrowLeft, CalendarClock, Layers, Trophy } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";
import { ApiError, errorDetail } from "../../api/client";
import { useTimeline } from "../../api/queries";
import type { DnsChange, Lang, TimelineEntry, TimelineResponse } from "../../api/types";
import { GradeBadge } from "../../components/GradeBadge";
import { EmptyState, ErrorState, Loading } from "../../components/PageState";
import { SectionTitle } from "../../components/SectionTitle";
import { StatCard } from "../../components/StatCard";
import { useLang } from "../../i18n";
import { formatDate } from "../../lib/format";
import { timelineScoreView } from "../../lib/score";
import type { Tone } from "../../lib/tones";
import { useDocumentTitle } from "../../lib/useDocumentTitle";
import { dnsValueText } from "../../lib/verdicts";
import { ScoreChart } from "./ScoreChart";
import styles from "./timeline.module.css";

const MAX_CHANGES = 5;
const NA_NOTE_ID = "timeline-na-note";

function ChangeLines({ values, sign, kind }: { values: unknown[] | undefined; sign: string; kind: "added" | "removed" }) {
  const { t } = useTranslation();
  const list = Array.isArray(values) ? values : [];
  return (
    <>
      {list.slice(0, MAX_CHANGES).map((value, index) => (
        <span key={index} className={`${styles.change} mono`} data-kind={kind}>
          {sign} {dnsValueText(value, t("timeline.nullMx"))}
        </span>
      ))}
      {list.length > MAX_CHANGES && <span className={styles.muted}>{t("timeline.more", { count: list.length - MAX_CHANGES })}</span>}
    </>
  );
}

// null : pas de comparaison possible (premier relevé, ou relevé DNS indisponible).
function DnsChanges({ changes, first }: { changes: Record<string, DnsChange> | null; first: boolean }) {
  const { t } = useTranslation();
  if (changes == null || typeof changes !== "object") {
    return first ? (
      <span className={styles.muted}>{t("timeline.first")}</span>
    ) : (
      <span className={styles.muted} title={t("timeline.notComparableTitle")}>
        {t("timeline.notComparable")}
      </span>
    );
  }
  const types = Object.entries(changes).filter(([, change]) => change && typeof change === "object");
  if (!types.length) return <span className={styles.muted}>{t("timeline.noChange")}</span>;
  return (
    <ul className={styles.changes}>
      {types.map(([type, change]) => (
        <li key={type}>
          <span className={styles.recordType}>{type}</span>
          <ChangeLines values={change.added} sign="+" kind="added" />
          <ChangeLines values={change.removed} sign="−" kind="removed" />
        </li>
      ))}
    </ul>
  );
}

function TimelineRow({ entry, first, lang }: { entry: TimelineEntry; first: boolean; lang: Lang }) {
  const { t } = useTranslation();
  // Même règle que Résultat et Historique (lib/score.ts).
  const view = timelineScoreView(entry);
  // Badge toujours affiché, comme dans l'Historique (displayGrade) : N/A sans
  // score affiché ou sans note enregistrée (GradeBadge).
  const grade = view.kind === "score" ? entry.grade : "N/A";
  const count = (value: number | null) =>
    value == null ? <span title={t("timeline.naTitle")}>{t("common.na")}</span> : value;
  const naDescribed = (value: number | null) => (value == null ? NA_NOTE_ID : undefined);
  return (
    <tr className={styles.row}>
      <td className={`${styles.date} mono`}>
        <Link to={`/scans/${entry.scan_id}`} aria-label={t("timeline.openScan", { date: formatDate(entry.timestamp, lang) })}>
          {formatDate(entry.timestamp, lang)}
        </Link>
      </td>
      {/* data-label : sur téléphone, chaque relevé devient une carte dont les libellés viennent de là. */}
      <td className={`${styles.ip} mono`} data-label={t("timeline.col.ip")}>
        {entry.ip_address ?? t("common.na")}
      </td>
      <td className="mono" data-label={t("timeline.col.subdomains")} aria-describedby={naDescribed(entry.subdomains_count)}>
        {count(entry.subdomains_count)}
      </td>
      <td className="mono" data-label={t("timeline.col.ports")} aria-describedby={naDescribed(entry.open_ports_count)}>
        {count(entry.open_ports_count)}
      </td>
      <td data-label={t("timeline.col.score")}>
        <span className={styles.score}>
          <span className="mono" data-low={view.kind === "indicative" ? "true" : undefined}>
            {view.kind === "none"
              ? t("common.na")
              : `${view.value}/100${view.kind === "indicative" ? ` ${t("common.indicative")}` : ""}`}
          </span>
          <GradeBadge grade={grade} size="sm" />
        </span>
        {typeof entry.coverage === "number" && <span className={styles.coverage}>{t("timeline.coverage", { coverage: entry.coverage })}</span>}
      </td>
      <td className={styles.changesCell} data-label={t("timeline.col.changes")}>
        <DnsChanges changes={entry.dns_changes} first={first} />
      </td>
    </tr>
  );
}

function Related({ data }: { data: TimelineResponse }) {
  const { t } = useTranslation();
  const related = (data.related_domains ?? []).filter((item) => item && typeof item.domain === "string");
  if (!related.length) return null;
  return (
    <section className={styles.card} aria-labelledby="related-title">
      <SectionTitle level={2} label={t("timeline.relatedKicker")} title={t("timeline.related", { apex: data.apex })} id="related-title" />
      <ul className={styles.related}>
        {related.map((item) => (
          <li key={item.domain}>
            <Link to={`/history/${encodeURIComponent(item.domain)}`} className="btn mono">
              {t("timeline.relatedCount", { domain: item.domain, count: item.total_scans })}
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}

// Rang des vraies notes (A la meilleure) ; toute autre valeur n'est pas une note.
const GRADE_RANK: Record<string, number> = { A: 5, B: 4, C: 3, D: 2, F: 1 };

// Meilleure note parmi les relevés dont la ligne montre une vraie note (ni score indicatif,
// ni N/A). À note égale, le score le plus haut ; à égalité encore, le relevé le plus récent
// (les relevés vont du plus ancien au plus récent).
function bestGrade(timeline: TimelineEntry[]): { grade: string; score: number } | null {
  let best: { grade: string; score: number; rank: number } | null = null;
  for (const entry of timeline) {
    const view = timelineScoreView(entry);
    const rank = GRADE_RANK[entry.grade ?? ""] ?? 0;
    if (view.kind !== "score" || view.value === null || !rank || !entry.grade) continue;
    if (!best || rank > best.rank || (rank === best.rank && view.value >= best.score)) {
      best = { grade: entry.grade, score: view.value, rank };
    }
  }
  return best && { grade: best.grade, score: best.score };
}

// Ton d'une note : la couleur accompagne toujours la lettre, elle ne la remplace pas.
function gradeTone(grade: string): Tone {
  return grade === "A" || grade === "B" ? "ok" : grade === "F" ? "critical" : "warning";
}

// Trois indicateurs du domaine : nombre de scans, meilleure note, date du dernier scan.
function Kpis({ data, timeline, lang }: { data: TimelineResponse; timeline: TimelineEntry[]; lang: Lang }) {
  const { t } = useTranslation();
  const best = bestGrade(timeline);
  const total = Number(data.total_scans);
  const last = timeline[timeline.length - 1];
  return (
    <div className={styles.kpis} role="group" aria-label={t("timeline.kpi.aria")}>
      <StatCard
        variant="secondary"
        label={t("timeline.kpi.scans")}
        icon={<Layers />}
        tone="accent"
        value={Number.isFinite(total) ? total : t("common.na")}
      />
      <StatCard
        variant="secondary"
        label={t("timeline.kpi.best")}
        icon={<Trophy />}
        tone={best ? gradeTone(best.grade) : "na"}
        value={
          best ? (
            <span className={styles.kpiBest}>
              <GradeBadge grade={best.grade} size="md" />
              <span className={`${styles.kpiValue} mono`}>{t("result.score", { score: best.score })}</span>
            </span>
          ) : (
            t("common.na")
          )
        }
      />
      <StatCard
        variant="secondary"
        label={t("timeline.kpi.last")}
        icon={<CalendarClock />}
        tone="info"
        value={<span className={`${styles.kpiValue} mono`}>{formatDate(last.timestamp, lang)}</span>}
      />
    </div>
  );
}

function TimelineContent({ data, lang }: { data: TimelineResponse; lang: Lang }) {
  const { t } = useTranslation();
  const timeline = data.timeline ?? [];
  if (timeline.length < 2) {
    return (
      <div className={styles.content}>
        {timeline.length > 0 && <Kpis data={data} timeline={timeline} lang={lang} />}
        <div className={styles.card}>
          <p className={styles.cardTitle}>{t("timeline.notEnough")}</p>
          <p className={styles.muted}>{t("timeline.notEnoughText", { count: timeline.length, domain: data.domain })}</p>
        </div>
        <Related data={data} />
      </div>
    );
  }
  // Le premier scan de l'historique n'a pas de relevé antérieur à comparer.
  const complete = Number(data.total_scans) === timeline.length;
  // L'API ne renvoie que les relevés les plus récents (100 par défaut).
  const truncated = Number(data.total_scans) > timeline.length;
  // Courbe : les scans dont la ligne montre un score (indicatif compris), pas
  // ceux qu'elle dit N/A (ancien scan noté sous 50 % sans measured_max).
  const scored = timeline.filter((entry) => timelineScoreView(entry).kind !== "none");
  return (
    <>
      <p className={styles.total}>{t("timeline.total", { count: data.total_scans, domain: data.domain })}</p>
      {truncated && (
        <p className={styles.muted} role="note">
          {t("timeline.truncated", { shown: timeline.length, total: data.total_scans })}
        </p>
      )}
      <div className={styles.content}>
        <Kpis data={data} timeline={timeline} lang={lang} />
        {scored.length >= 2 && (
          <section className={styles.card} aria-labelledby="chart-title">
            <SectionTitle level={2} label={t("timeline.chartKicker")} title={t("timeline.chartTitle")} id="chart-title" />
            <ScoreChart entries={scored} lang={lang} />
          </section>
        )}
        <section className={styles.card} aria-labelledby="table-title">
          <SectionTitle level={2} label={t("timeline.tableKicker")} title={t("timeline.tableTitle")} id="table-title" />
          {/* Le tableau défile à l'horizontale sur un écran étroit : la région est atteignable au clavier. */}
          <div className={styles.tableWrap} role="region" aria-label={t("timeline.tableRegion")} tabIndex={0}>
            <table className={styles.table}>
              <caption className="visually-hidden">{t("timeline.caption", { domain: data.domain })}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("timeline.col.date")}</th>
                  <th scope="col">{t("timeline.col.ip")}</th>
                  <th scope="col">{t("timeline.col.subdomains")}</th>
                  <th scope="col">{t("timeline.col.ports")}</th>
                  <th scope="col">{t("timeline.col.score")}</th>
                  <th scope="col">{t("timeline.col.changes")}</th>
                </tr>
              </thead>
              <tbody>
                {timeline.map((entry, index) => (
                  <TimelineRow key={entry.scan_id} entry={entry} first={index === 0 && complete} lang={lang} />
                ))}
              </tbody>
            </table>
          </div>
          {timeline.some((entry) => entry.subdomains_count == null || entry.open_ports_count == null) && (
            <p id={NA_NOTE_ID} className={styles.muted}>
              {t("timeline.naNote")}
            </p>
          )}
        </section>
        <Related data={data} />
      </div>
    </>
  );
}

export function TimelinePage() {
  const { t } = useTranslation();
  const lang = useLang();
  const { domain = "" } = useParams();
  const query = useTimeline(domain);
  useDocumentTitle(t("timeline.title", { domain }));
  return (
    <div className={styles.page}>
      <Link to="/history" className={styles.back}>
        <ArrowLeft aria-hidden />
        {t("timeline.back")}
      </Link>
      <SectionTitle
        level={1}
        size="page"
        label={t("timeline.kicker")}
        title={t("timeline.title", { domain })}
        accent={domain || undefined}
      />

      {query.isPending ? (
        <Loading />
      ) : query.isError ? (
        query.error instanceof ApiError && query.error.status === 404 ? (
          <EmptyState>{t("timeline.notFound")}</EmptyState>
        ) : query.error instanceof ApiError && (query.error.status === 400 || query.error.status === 422) ? (
          // Adresse saisie à la main avec un nom invalide : « Réessayer » n'y changerait rien.
          <ErrorState title={t("timeline.invalidTitle")} detail={t("timeline.invalid", { domain })}>
            <Link to="/history" className="btn">
              {t("timeline.back")}
            </Link>
          </ErrorState>
        ) : (
          <ErrorState detail={errorDetail(query.error)} onRetry={() => void query.refetch()} />
        )
      ) : (
        <TimelineContent data={query.data} lang={lang} />
      )}
    </div>
  );
}
