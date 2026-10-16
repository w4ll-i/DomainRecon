import { ChartLine, Search, Trash2 } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";
import { errorDetail } from "../../api/client";
import { HISTORY_PAGE_SIZE, type HistoryParams, useDeleteScan, useHistory } from "../../api/queries";
import type { ScanSummary } from "../../api/types";
import { useConfirm } from "../../components/ConfirmDialog";
import { GradeBadge } from "../../components/GradeBadge";
import { EmptyState, ErrorState, Loading } from "../../components/PageState";
import { Pill, ScanStatusPill } from "../../components/Pills";
import { SectionTitle } from "../../components/SectionTitle";
import { useToast } from "../../components/Toasts";
import { useLang } from "../../i18n";
import { gradeToken } from "../../lib/colors";
import { charCount, formatDate } from "../../lib/format";
import { displayGrade, scoreView } from "../../lib/score";
import { getLastScanId, setLastScanId } from "../../lib/storage";
import { useDocumentTitle } from "../../lib/useDocumentTitle";
import styles from "./HistoryPage.module.css";

const GRADES = ["A", "B", "C", "D", "F", "N/A"];
const STATUSES = ["success", "partial", "error"];
const SEARCH_MAX = 255;
// Dernière page demandable : le décalage envoyé à l'API est borné (2^31 - 1).
const MAX_PAGE = Math.floor((2 ** 31 - 1) / HISTORY_PAGE_SIZE);
const NA_NOTE_ID = "history-na-note";

function HistoryRow({ scan, onDelete }: { scan: ScanSummary; onDelete: () => void }) {
  const { t } = useTranslation();
  const lang = useLang();
  const score = scan.security_score ?? {};
  const view = scoreView(score);
  const grade = displayGrade(score);
  return (
    // data-grade colore le filet gauche de la ligne ; la lettre de la note reste l'indice premier.
    <tr className={styles.row} data-grade={gradeToken(grade)}>
      <th scope="row" className={styles.domainHead}>
        <div className={styles.domainCell}>
          <Link to={`/scans/${scan.id}`} className={`${styles.domain} mono`}>
            {scan.domain}
          </Link>
          {scan.ip_address && <span className={`${styles.ip} mono`}>{scan.ip_address}</span>}
          {(scan.tags ?? []).length > 0 && (
            <span className={styles.tags}>
              {scan.tags.map((tag) => (
                <Pill key={tag} tone="neutral">
                  {tag}
                </Pill>
              ))}
            </span>
          )}
        </div>
      </th>
      <td data-label={t("history.col.grade")}>
        <GradeBadge grade={grade} size="sm" />
      </td>
      <td data-label={t("history.col.score")} className="mono">
        {view.kind === "none" ? (
          t("common.na")
        ) : (
          <span className={styles.score} data-low={view.kind === "indicative" ? "true" : undefined}>
            {`${view.value}/100`}
            {view.kind === "indicative" && ` ${t("common.indicative")}`}
          </span>
        )}
      </td>
      <td data-label={t("history.col.status")}>
        <ScanStatusPill status={scan.status} />
      </td>
      <td
        data-label={t("history.col.subdomains")}
        className="mono"
        aria-describedby={scan.subdomains_count == null ? NA_NOTE_ID : undefined}
      >
        {scan.subdomains_count == null ? <span title={t("history.subdomainsNATitle")}>{t("common.na")}</span> : scan.subdomains_count}
      </td>
      <td data-label={t("history.col.date")} className={styles.date}>
        {formatDate(scan.scan_timestamp, lang)}
      </td>
      <td className={styles.actions}>
        <Link
          to={`/history/${encodeURIComponent(scan.domain)}`}
          className={`btn ${styles.action}`}
          data-variant="ghost"
          aria-label={t("history.timeline", { domain: scan.domain })}
          title={t("history.timeline", { domain: scan.domain })}
        >
          <ChartLine aria-hidden />
        </Link>
        <button
          type="button"
          className={`btn ${styles.action} ${styles.delete}`}
          data-variant="ghost"
          onClick={onDelete}
          aria-label={t("history.delete", { domain: scan.domain })}
          title={t("history.delete", { domain: scan.domain })}
        >
          <Trash2 aria-hidden />
        </button>
      </td>
    </tr>
  );
}

export function HistoryPage() {
  const { t } = useTranslation();
  const lang = useLang();
  const toast = useToast();
  const confirm = useConfirm();
  const remove = useDeleteScan();
  const [searchParams, setSearchParams] = useSearchParams();
  useDocumentTitle(t("history.title"));

  const q = searchParams.get("q") ?? "";
  const gradeParam = searchParams.get("grade") ?? "";
  const statusParam = searchParams.get("status") ?? "";
  const grade = GRADES.includes(gradeParam) ? gradeParam : "";
  const status = STATUSES.includes(statusParam) ? statusParam : "";
  const page = Math.min(MAX_PAGE, Math.max(1, Number.parseInt(searchParams.get("page") ?? "1", 10) || 1));
  const [search, setSearch] = useState(q);
  const tooLong = charCount(search.trim()) > SEARCH_MAX;
  // Dernière recherche envoyée à l'URL : seule une valeur d'URL différente
  // (retour, lien, réinitialisation) resynchronise le champ, jamais celle qu'on
  // vient d'y mettre (sinon un caractère tapé pendant l'aller-retour serait perdu).
  const lastSent = useRef(q);
  // Conteneur du titre : son h1 reçoit le focus après une suppression (voir focusHeading).
  const header = useRef<HTMLDivElement>(null);
  const tableWrap = useRef<HTMLDivElement>(null);

  // Une entrée d'historique par action de l'utilisateur (Précédent fonctionne) ;
  // replace seulement pour les corrections automatiques (page hors limites).
  const update = useCallback(
    (changes: Partial<Record<"q" | "grade" | "status" | "page", string | number>>, replace = false) => {
      setSearchParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          for (const [key, value] of Object.entries(changes)) {
            if (value === "" || value === undefined || (key === "page" && value === 1)) next.delete(key);
            else next.set(key, String(value));
          }
          return next;
        },
        { replace },
      );
    },
    [setSearchParams],
  );

  // L'URL fait foi (bouton Précédent, lien partagé).
  useEffect(() => {
    if (q === lastSent.current) return;
    lastSent.current = q;
    setSearch(q);
  }, [q]);

  // Recherche envoyée au serveur après une courte pause de saisie.
  useEffect(() => {
    const value = search.trim();
    if (tooLong || value === q) return undefined;
    const timer = window.setTimeout(() => {
      lastSent.current = value;
      update({ q: value, page: 1 });
    }, 300);
    return () => window.clearTimeout(timer);
  }, [search, q, tooLong, update]);

  const params: HistoryParams = { q, grade, status, page };
  const query = useHistory(params);
  const total = query.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / HISTORY_PAGE_SIZE));
  const from = total ? (page - 1) * HISTORY_PAGE_SIZE + 1 : 0;
  const to = Math.min(total, page * HISTORY_PAGE_SIZE);
  const filtered = Boolean(q || grade || status);

  // Dernière page vidée par une suppression, ou page d'une URL partagée devenue
  // trop lointaine : retour à la dernière page qui existe (« Chargement » entre
  // temps, pas un « aucun scan » trompeur).
  const settled = query.data !== undefined && !query.isPlaceholderData;
  const outOfRange = settled && page > pages;
  useEffect(() => {
    if (outOfRange) update({ page: pages }, true);
  }, [outOfRange, pages, update]);
  // Page vide d'avant affichée en attendant la suivante (keepPreviousData), par
  // exemple pendant ce retour : rien ne dit encore que la liste est vide.
  const emptyPlaceholder = query.isPlaceholderData && query.data.scans.length === 0;

  // Le titre est un h1 de SectionTitle, qui ne transmet ni ref ni tabIndex : il devient
  // focalisable (tabindex -1) au moment où le focus lui est rendu.
  const focusHeading = () => {
    const heading = header.current?.querySelector("h1");
    if (!heading) return;
    heading.tabIndex = -1;
    heading.focus();
  };

  const onDelete = async (scan: ScanSummary) => {
    const confirmed = await confirm({
      title: t("history.deleteTitle"),
      message: t("history.deleteText", { domain: scan.domain, date: formatDate(scan.scan_timestamp, lang) }),
      confirmLabel: t("common.delete"),
      danger: true,
    });
    if (!confirmed) return;
    // mutateAsync plutôt que les rappels de mutate : ils sont perdus si l'écran
    // est quitté avant la réponse, alors que le dernier scan consulté doit être
    // oublié dans tous les cas.
    try {
      const outcome = await remove.mutateAsync(scan.id);
      if (getLastScanId() === scan.id) setLastScanId(null);
      toast.show(t(outcome === "deleted" ? "history.deleted" : "history.alreadyDeleted"), outcome === "deleted" ? "info" : "warning");
      // La ligne disparaît : le focus passe au titre (sauf si l'utilisateur est
      // déjà ailleurs), au lieu de tomber sur <body>.
      const active = document.activeElement;
      if (!active || active === document.body || tableWrap.current?.contains(active)) focusHeading();
    } catch (error) {
      toast.show(t("history.deleteError", { detail: errorDetail(error) }), "error");
    }
  };

  return (
    <div className={styles.page}>
      <div className={styles.header} ref={header}>
        <SectionTitle level={1} size="page" label={t("history.kicker")} title={t("history.title")} />
      </div>
      <div className={styles.filters} role="search">
        <div className={styles.searchField}>
          <label htmlFor="history-search" className="visually-hidden">
            {t("history.search")}
          </label>
          <Search aria-hidden className={styles.searchIcon} />
          <input
            id="history-search"
            type="search"
            className={styles.input}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder={t("history.searchPlaceholder")}
            autoComplete="off"
            aria-invalid={tooLong ? true : undefined}
            aria-describedby={tooLong ? "history-search-error" : undefined}
          />
        </div>
        <div className={styles.selectField}>
          <label htmlFor="history-grade">{t("history.grade")}</label>
          <select id="history-grade" value={grade} onChange={(event) => update({ grade: event.target.value, page: 1 })}>
            <option value="">{t("history.gradeAll")}</option>
            {GRADES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
        <div className={styles.selectField}>
          <label htmlFor="history-status">{t("history.status")}</label>
          <select id="history-status" value={status} onChange={(event) => update({ status: event.target.value, page: 1 })}>
            <option value="">{t("history.statusAll")}</option>
            {STATUSES.map((value) => (
              <option key={value} value={value}>
                {t(`scanStatus.${value}`)}
              </option>
            ))}
          </select>
        </div>
        {filtered && (
          <button
            type="button"
            className="btn"
            data-variant="ghost"
            onClick={() => {
              setSearch("");
              lastSent.current = "";
              update({ q: "", grade: "", status: "", page: 1 });
            }}
          >
            {t("history.reset")}
          </button>
        )}
      </div>
      {tooLong && (
        <p id="history-search-error" role="alert" className={styles.error}>
          {t("history.searchTooLong", { max: SEARCH_MAX })}
        </p>
      )}

      {query.isPending || outOfRange || emptyPlaceholder ? (
        <Loading />
      ) : query.isError ? (
        <ErrorState detail={t("history.loadError", { detail: errorDetail(query.error) })} onRetry={() => void query.refetch()}>
          {page > 1 && (
            <button type="button" className="btn" onClick={() => update({ page: 1 }, true)}>
              {t("history.firstPage")}
            </button>
          )}
        </ErrorState>
      ) : query.data.scans.length === 0 ? (
        <EmptyState>
          {filtered ? (
            t("history.emptyFiltered")
          ) : (
            <div className={styles.emptyBody}>
              <p>{t("history.empty")}</p>
              <Link to="/" className="btn" data-variant="primary">
                {t("nav.newScan")}
              </Link>
            </div>
          )}
        </EmptyState>
      ) : (
        <>
          <div
            className={styles.tableWrap}
            ref={tableWrap}
            role="region"
            aria-label={t("history.tableRegion")}
            tabIndex={0}
          >
            <table className={styles.table}>
              <caption className="visually-hidden">{t("history.caption")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("history.col.domain")}</th>
                  <th scope="col">{t("history.col.grade")}</th>
                  <th scope="col">{t("history.col.score")}</th>
                  <th scope="col">{t("history.col.status")}</th>
                  <th scope="col">{t("history.col.subdomains")}</th>
                  <th scope="col">{t("history.col.date")}</th>
                  <th scope="col">
                    <span className="visually-hidden">{t("history.col.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {query.data.scans.map((scan) => (
                  <HistoryRow key={scan.id} scan={scan} onDelete={() => void onDelete(scan)} />
                ))}
              </tbody>
            </table>
          </div>
          {query.data.scans.some((scan) => scan.subdomains_count == null) && (
            <p id={NA_NOTE_ID} className={styles.muted}>
              {t("history.naNote")}
            </p>
          )}
          <nav className={styles.pagination} aria-label={t("history.pagination")}>
            <span className={styles.range} aria-live="polite" aria-atomic="true">
              {t("history.range", { from, to, total })}
            </span>
            <div className={styles.pageButtons}>
              <button type="button" className="btn" onClick={() => update({ page: page - 1 })} disabled={page <= 1}>
                {t("history.prev")}
              </button>
              <span className={styles.pageCount}>{t("history.page", { page, pages })}</span>
              <button type="button" className="btn" onClick={() => update({ page: page + 1 })} disabled={page >= pages}>
                {t("history.next")}
              </button>
            </div>
          </nav>
        </>
      )}
    </div>
  );
}
