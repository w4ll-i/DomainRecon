import { Globe, LoaderCircle, Radar, Search } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { errorDetail } from "../../api/client";
import { useRecentScans } from "../../api/queries";
import type { ScanSummary } from "../../api/types";
import { GradeBadge } from "../../components/GradeBadge";
import { Loading } from "../../components/PageState";
import { SectionTitle } from "../../components/SectionTitle";
import { StatCard } from "../../components/StatCard";
import { useLang } from "../../i18n";
import { type GradeToken, gradeToken } from "../../lib/colors";
import { formatDate } from "../../lib/format";
import { displayGrade, scoreView } from "../../lib/score";
import type { Tone } from "../../lib/tones";
import { useDocumentTitle } from "../../lib/useDocumentTitle";
import { ProfilePicker } from "./ProfilePicker";
import { useScanOptions } from "./scanOptions";
import styles from "./NewScanPage.module.css";
import { useLaunchScan } from "./useLaunchScan";

const EXAMPLES = ["example.com", "wikipedia.org", "github.com"];
// Scans proposés sous le champ : les cinq derniers de l'historique.
const RECENT_COUNT = 5;

// Ton de la carte d'un scan récent : la note l'écrit en toutes lettres, la couleur la souligne.
const GRADE_TONES: Readonly<Record<GradeToken, Tone>> = { A: "ok", B: "ok", C: "warning", D: "warning", F: "critical", NA: "na" };

function RecentCard({ scan }: { scan: ScanSummary }) {
  const { t } = useTranslation();
  const lang = useLang();
  const score = scan.security_score ?? {};
  const grade = displayGrade(score);
  // Même règle d'affichage du score que Résultat, Historique et Timeline (lib/score.ts).
  const view = scoreView(score);
  const scoreText =
    view.kind === "none"
      ? t("common.na")
      : `${t("result.score", { score: view.value })}${view.kind === "indicative" ? ` ${t("common.indicative")}` : ""}`;
  return (
    <Link to={`/scans/${scan.id}`} className={styles.recentItem}>
      <StatCard
        variant="secondary"
        label={formatDate(scan.scan_timestamp, lang)}
        icon={<Globe />}
        tone={GRADE_TONES[gradeToken(grade)]}
        value={
          <span className={styles.recentValue}>
            <span className={`${styles.recentDomain} mono`}>{scan.domain}</span>
            <span className={styles.recentResult}>
              <GradeBadge grade={grade} size="sm" />
              <span className={`${styles.recentScore} mono`}>{scoreText}</span>
            </span>
          </span>
        }
      />
    </Link>
  );
}

export function NewScanPage() {
  const { t } = useTranslation();
  const recent = useRecentScans(RECENT_COUNT);
  const { launch, pending, error, clearError } = useLaunchScan("field");
  const [domain, setDomain] = useState("");
  const scan = useScanOptions();
  useDocumentTitle(t("newScan.title"));

  const submit = (event: FormEvent) => {
    event.preventDefault();
    launch(domain, undefined, scan.payload());
  };

  return (
    <div className={styles.page}>
      <header className={styles.hero}>
        <SectionTitle
          label={t("newScan.hero.kicker")}
          title={t("newScan.hero.title")}
          accent={t("newScan.hero.titleAccent")}
          level={1}
          size="hero"
          align="center"
        />
        <p className={styles.lead}>{t("newScan.lead")}</p>
      </header>

      <form className={styles.form} onSubmit={submit} noValidate>
        <label htmlFor="domain-input" className={styles.label}>
          {t("newScan.label")}
        </label>
        <div className={styles.inputRow} data-invalid={error ? "true" : undefined} data-tour="domain">
          <Search aria-hidden className={styles.searchIcon} />
          <input
            id="domain-input"
            name="domain"
            className={`${styles.input} mono`}
            value={domain}
            onChange={(event) => {
              setDomain(event.target.value);
              // L'erreur affichée concernait la saisie précédente.
              clearError();
            }}
            placeholder={t("newScan.placeholder")}
            autoComplete="off"
            spellCheck={false}
            autoFocus
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? "domain-error" : undefined}
          />
          <button type="submit" className={`btn ${styles.submit}`} data-variant="primary" disabled={pending || !scan.valid}>
            {pending ? <LoaderCircle aria-hidden className="spin" /> : <Radar aria-hidden />}
            {t("newScan.submit")}
          </button>
        </div>
        {error && (
          <p id="domain-error" role="alert" className={styles.error}>
            {error}
          </p>
        )}
        <ProfilePicker
          catalog={scan.catalog}
          value={scan.options}
          onChange={scan.setOptions}
          needsAuth={scan.needsAuth}
        />
      </form>

      <div className={styles.examples}>
        <span className={styles.examplesLabel}>{t("newScan.examples")}</span>
        {EXAMPLES.map((example) => (
          <button
            key={example}
            type="button"
            className={`${styles.example} mono`}
            onClick={() => {
              setDomain(example);
              clearError();
            }}
          >
            {example}
          </button>
        ))}
      </div>

      <section className={styles.recent} aria-labelledby="recent-title">
        <div className={styles.recentHead}>
          <SectionTitle label={t("newScan.recentKicker")} title={t("newScan.recent")} id="recent-title" />
          <Link to="/history" className={styles.recentLink}>
            {t("newScan.historyLink")}
          </Link>
        </div>
        {recent.isPending ? (
          <Loading />
        ) : recent.isError ? (
          <p className={styles.muted}>{t("newScan.recentError", { detail: errorDetail(recent.error) })}</p>
        ) : recent.data.scans.length === 0 ? (
          <p className={styles.muted}>{t("newScan.recentEmpty")}</p>
        ) : (
          <ul className={styles.recentList}>
            {recent.data.scans.slice(0, RECENT_COUNT).map((scan) => (
              <li key={scan.id}>
                <RecentCard scan={scan} />
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
