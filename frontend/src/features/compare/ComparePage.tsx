import { ArrowRight, GitCompare } from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";
import { errorDetail } from "../../api/client";
import type { CompareResponse } from "../../api/ops";
import { useCompare, useDashboard } from "../../api/opsQueries";
import { useTimeline } from "../../api/queries";
import type { Finding } from "../../api/types";
import { EmptyHint } from "../../components/EmptyHint";
import { GradeBadge } from "../../components/GradeBadge";
import { ErrorState, Loading } from "../../components/PageState";
import { SeverityBadge } from "../../components/Pills";
import { SectionTitle } from "../../components/SectionTitle";
import { useLang } from "../../i18n";
import { formatDate, formatNumber } from "../../lib/format";
import { useDocumentTitle } from "../../lib/useDocumentTitle";
import styles from "../../styles/ops.module.css";

// Une liste de lignes ajoutées (+) ou retirées (−), ou une phrase « aucun changement ».
function DiffLines({ added, removed, emptyText }: { added: string[]; removed: string[]; emptyText: string }) {
  const { t } = useTranslation();
  if (added.length === 0 && removed.length === 0) return <p className={styles.muted}>{emptyText}</p>;
  return (
    <ul className={styles.diffList}>
      {added.map((line) => (
        <li key={`+${line}`}>
          <span className={styles.added} aria-label={t("compare.added")}>
            +
          </span>
          <span className={styles.mono}>{line}</span>
        </li>
      ))}
      {removed.map((line) => (
        <li key={`-${line}`}>
          <span className={styles.removed} aria-label={t("compare.removed")}>
            −
          </span>
          <span className={styles.mono}>{line}</span>
        </li>
      ))}
    </ul>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className={styles.card} aria-label={title}>
      <h3 className={styles.emptyTitle}>{title}</h3>
      {children}
    </section>
  );
}

function plain(value: unknown): string {
  if (value === null || value === undefined) return "—";
  return typeof value === "string" ? value : JSON.stringify(value);
}

function portLabel(port: { port: number; service?: string | null }): string {
  return `${port.port}${port.service ? ` (${port.service})` : ""}`;
}

function FindingList({ title, findings, empty }: { title: string; findings: Finding[]; empty: string }) {
  return (
    <div>
      <p className={styles.label}>{title}</p>
      {findings.length === 0 ? (
        <p className={styles.muted}>{empty}</p>
      ) : (
        <ul className={styles.diffList}>
          {findings.map((finding, index) => (
            <li key={`${finding.module}-${index}`}>
              <SeverityBadge severity={finding.severity} />
              <span>{finding.message}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Differences({ diff }: { diff: CompareResponse }) {
  const { t } = useTranslation();
  const lang = useLang();
  const notMeasured = t("compare.notMeasured");
  const same = t("compare.noChange");

  if (!diff.comparable) {
    return <p className={styles.error}>{t("compare.notComparable")}</p>;
  }
  const delta = diff.score.delta;
  return (
    <div className={styles.stack}>
      <section className={styles.card} aria-label={t("compare.score")}>
        <div className={styles.row}>
          <GradeBadge grade={diff.score.a.grade} />
          <ArrowRight aria-hidden />
          <GradeBadge grade={diff.score.b.grade} />
          <span className={styles.mono}>
            {diff.score.a.score === null ? t("common.na") : formatNumber(diff.score.a.score, lang, 1)}
            {" → "}
            {diff.score.b.score === null ? t("common.na") : formatNumber(diff.score.b.score, lang, 1)}
          </span>
          {delta !== null && (
            <span className={delta < 0 ? styles.error : delta > 0 ? styles.ok : styles.muted}>
              {delta > 0 ? "+" : ""}
              {formatNumber(delta, lang, 1)} {t("compare.points")}
            </span>
          )}
        </div>
        {diff.changes.length === 0 ? (
          <p className={styles.muted}>{t("compare.identical")}</p>
        ) : (
          <ul className={styles.diffList} aria-label={t("compare.summary")}>
            {diff.changes.map((change) => (
              <li key={change}>{change}</li>
            ))}
          </ul>
        )}
      </section>

      <Section title={t("compare.findings")}>
        {diff.findings === null ? (
          <p className={styles.muted}>{notMeasured}</p>
        ) : (
          <>
            <FindingList title={t("compare.newFindings")} findings={diff.findings.new} empty={t("compare.noNewFindings")} />
            <FindingList
              title={t("compare.resolvedFindings")}
              findings={diff.findings.resolved}
              empty={t("compare.noResolvedFindings")}
            />
            <p className={styles.muted}>{t("compare.unchanged", { count: diff.findings.unchanged })}</p>
          </>
        )}
      </Section>

      <Section title={t("compare.ports")}>
        {diff.ports === null ? (
          <p className={styles.muted}>{notMeasured}</p>
        ) : (
          <DiffLines added={diff.ports.opened.map(portLabel)} removed={diff.ports.closed.map(portLabel)} emptyText={same} />
        )}
      </Section>

      <Section title={t("compare.subdomains")}>
        {diff.subdomains === null ? (
          <p className={styles.muted}>{notMeasured}</p>
        ) : (
          <DiffLines added={diff.subdomains.added} removed={diff.subdomains.removed} emptyText={same} />
        )}
      </Section>

      <Section title={t("compare.dns")}>
        {diff.dns === null ? (
          <p className={styles.muted}>{notMeasured}</p>
        ) : Object.keys(diff.dns).length === 0 ? (
          <p className={styles.muted}>{same}</p>
        ) : (
          Object.entries(diff.dns).map(([type, change]) => (
            <div key={type}>
              <p className={styles.label}>{type}</p>
              <DiffLines added={change.added.map(plain)} removed={change.removed.map(plain)} emptyText={same} />
            </div>
          ))
        )}
      </Section>

      <Section title={t("compare.certificate")}>
        {diff.certificate === null ? (
          <p className={styles.muted}>{notMeasured}</p>
        ) : !diff.certificate.changed ? (
          <p className={styles.muted}>{same}</p>
        ) : (
          <ul className={styles.diffList}>
            {Object.entries(diff.certificate.fields).map(([field, values]) => (
              <li key={field}>
                <span className={styles.label}>{t(`compare.certField.${field}`, { defaultValue: field })}</span>
                <span className={styles.mono}>
                  {plain(values.a)} → {plain(values.b)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={t("compare.technologies")}>
        {diff.technologies === null ? (
          <p className={styles.muted}>{notMeasured}</p>
        ) : (
          <DiffLines added={diff.technologies.added} removed={diff.technologies.removed} emptyText={same} />
        )}
      </Section>
    </div>
  );
}

// Comparer : on choisit un domaine puis deux de ses scans (référence et plus récent) ; les
// différences s'affichent en clair : note, constats, ports, sous-domaines, DNS, certificat.
export function ComparePage() {
  const { t } = useTranslation();
  const lang = useLang();
  const [params, setParams] = useSearchParams();
  const domain = params.get("domain") ?? "";
  const [draft, setDraft] = useState(domain);
  const [a, setA] = useState<number | null>(null);
  const [b, setB] = useState<number | null>(null);
  const dashboard = useDashboard();
  const timeline = useTimeline(domain);
  useDocumentTitle(t("compare.title"));

  const scans = useMemo(
    () =>
      [...(timeline.data?.timeline ?? [])].sort(
        (x, y) => new Date(x.timestamp).getTime() - new Date(y.timestamp).getTime(),
      ),
    [timeline.data],
  );

  // Par défaut : l'avant-dernier scan contre le dernier.
  useEffect(() => {
    if (scans.length >= 2) {
      setA(scans[scans.length - 2].scan_id);
      setB(scans[scans.length - 1].scan_id);
    } else {
      setA(null);
      setB(null);
    }
  }, [scans]);

  const compare = useCompare(a, b);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const value = draft.trim();
    setParams(value ? { domain: value } : {});
  };

  const option = (scanId: number, timestamp: string, grade: string | null) =>
    `${formatDate(timestamp, lang)} · ${grade ?? t("common.na")} · #${scanId}`;

  return (
    <div className={styles.page}>
      <SectionTitle level={1} size="page" label={t("compare.kicker")} title={t("compare.title")} />
      <p className={styles.lead}>{t("compare.lead")}</p>

      <form className={styles.card} onSubmit={submit}>
        <div className={styles.field}>
          <label htmlFor="compare-domain">{t("compare.domain")}</label>
          <div className={styles.row}>
            <input
              id="compare-domain"
              className={`${styles.input} ${styles.mono}`}
              list="compare-domains"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              placeholder={t("compare.domainPlaceholder")}
              autoComplete="off"
              spellCheck={false}
            />
            <datalist id="compare-domains">
              {(dashboard.data?.domains ?? []).map((item) => (
                <option key={item.domain} value={item.domain} />
              ))}
            </datalist>
            <button type="submit" className="btn" data-variant="primary">
              {t("compare.choose")}
            </button>
          </div>
        </div>

        {domain !== "" && scans.length >= 2 && (
          <div className={styles.row}>
            <div className={styles.field}>
              <label htmlFor="compare-a">{t("compare.reference")}</label>
              <select id="compare-a" value={a ?? ""} onChange={(event) => setA(Number(event.target.value))}>
                {scans.map((scan) => (
                  <option key={scan.scan_id} value={scan.scan_id}>
                    {option(scan.scan_id, scan.timestamp, scan.grade)}
                  </option>
                ))}
              </select>
            </div>
            <div className={styles.field}>
              <label htmlFor="compare-b">{t("compare.recent")}</label>
              <select id="compare-b" value={b ?? ""} onChange={(event) => setB(Number(event.target.value))}>
                {scans.map((scan) => (
                  <option key={scan.scan_id} value={scan.scan_id}>
                    {option(scan.scan_id, scan.timestamp, scan.grade)}
                  </option>
                ))}
              </select>
            </div>
          </div>
        )}
      </form>

      {domain === "" ? (
        <EmptyHint icon={GitCompare} title={t("compare.emptyTitle")} text={t("compare.emptyText")} />
      ) : timeline.isPending ? (
        <Loading />
      ) : timeline.isError ? (
        <ErrorState detail={errorDetail(timeline.error)} onRetry={() => void timeline.refetch()} />
      ) : scans.length < 2 ? (
        <EmptyHint icon={GitCompare} title={t("compare.needTwoTitle")} text={t("compare.needTwoText", { domain })}>
          <Link to="/" className="btn" data-variant="primary">
            {t("compare.needTwoAction")}
          </Link>
        </EmptyHint>
      ) : a === b ? (
        <p className={styles.muted}>{t("compare.sameScan")}</p>
      ) : compare.isPending ? (
        <Loading />
      ) : compare.isError ? (
        <ErrorState detail={errorDetail(compare.error)} onRetry={() => void compare.refetch()} />
      ) : (
        <Differences diff={compare.data} />
      )}
    </div>
  );
}
