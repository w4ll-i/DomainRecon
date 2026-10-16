import type { TFunction } from "i18next";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import type { EmailSecurity, ScanResponse, SimpleRecordResult } from "../../../api/types";
import { GradeBadge } from "../../../components/GradeBadge";
import { KvList } from "../../../components/KvList";
import { ModuleCard } from "../../../components/ModuleCard";
import { Pill } from "../../../components/Pills";
import type { Tone } from "../../../lib/tones";
import { emailWithoutMail } from "../../../lib/verdicts";
import type { FamilyViewProps } from "../types";
import styles from "./modules.module.css";

const GRADES = ["A", "B", "C", "D", "F"];

// Scan antérieur : une liste peut être null ou absente, jamais un plantage.
function asList<T>(value: readonly T[] | null | undefined): T[] {
  return Array.isArray(value) ? [...value] : [];
}

// Description de la note tirée de ce qui a été trouvé : la note A ne suppose
// pas un DKIM détecté.
function gradeDescription(grade: string, es: EmailSecurity, t: TFunction): string {
  if (!GRADES.includes(grade)) return t(grade === "N/A" ? "email.noData" : "email.notEvaluated");
  const spf = es.spf ?? {};
  const dkim = es.dkim ?? {};
  const dmarc = es.dmarc ?? {};
  const spfText =
    spf.found === true
      ? spf.all
        ? t("email.spf.found", { all: spf.all })
        : t("email.spf.present")
      : spf.found === false
        ? t("email.spf.absent")
        : t("email.spf.unmeasured");
  const dmarcText =
    dmarc.found === true
      ? dmarc.policy
        ? t("email.dmarc.found", { policy: dmarc.policy })
        : t("email.dmarc.present")
      : dmarc.found === false
        ? t("email.dmarc.absent")
        : t("email.dmarc.unmeasured");
  const dkimText =
    dkim.found === true
      ? t("email.dkim.found")
      : dkim.found === false
        ? emailWithoutMail(es)
          ? t("email.dkim.noMail")
          : t("email.dkim.notFound")
        : t("email.dkim.unmeasured");
  return t("email.summary", { level: t(`email.level.${grade}`), spf: spfText, dmarc: dmarcText, dkim: dkimText });
}

interface EmailPartProps {
  name: string;
  found?: boolean | null;
  grade?: string | null;
  error?: string | null;
  issues?: string[] | null;
  notApplicable?: boolean;
  absentTone?: Tone;
  absentLabel?: string;
  children?: ReactNode;
}

// Trois états par partie : trouvé, absent (found === false), non mesuré
// (requête DNS en échec : found null et error). Un enregistrement publié mais
// dont l'évaluation a échoué (found true et error : cible de redirect=
// injoignable) n'est pas « publié » sans réserve.
function EmailPart({ name, found, grade, error, issues, notApplicable = false, absentTone = "critical", absentLabel, children }: EmailPartProps) {
  const { t } = useTranslation();
  const problems = asList(issues);
  const incomplete = found === true && Boolean(error);
  const [tone, label]: [Tone, string] =
    found === true
      ? incomplete
        ? ["warning", t("email.publishedIncomplete")]
        : ["ok", t("email.found")]
      : notApplicable
        ? ["neutral", t("moduleStatus.skipped")]
        : found === false
          ? [absentTone, absentLabel ?? t("email.absent")]
          : ["na", t("email.unmeasured")];
  return (
    <div className={styles.subCard} data-tone={tone}>
      <div className={styles.rowHead}>
        <span className={styles.rowTitle}>{name}</span>
        <Pill tone={tone}>{label}</Pill>
        {grade && <GradeBadge grade={grade} size="sm" />}
      </div>
      {found === true || found === false ? (
        children
      ) : (
        <p className={styles.muted}>{error ? t("email.unmeasuredReason", { reason: error }) : t("email.unmeasured")}</p>
      )}
      {incomplete && <p className={styles.warnText}>{error}</p>}
      {problems.length > 0 && (
        <ul className={styles.issues} data-tone="warning">
          {problems.map((issue, index) => (
            <li key={index}>{issue}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

// MTA-STS et TLS-RPT : mesurés par le serveur, affichés ici pour la première
// fois. Une requête en échec dit sa raison en clair (pas seulement en infobulle).
function RecordState({ result }: { result?: SimpleRecordResult }) {
  const { t } = useTranslation();
  if (result?.found === true) {
    return (
      <span className={styles.pills}>
        <Pill tone="ok">{t("email.found")}</Pill>
        {result.record && <span className="mono">{result.record}</span>}
      </span>
    );
  }
  if (result?.found === false) return <Pill tone="neutral">{t("email.absent")}</Pill>;
  return (
    <span className={styles.pills}>
      <Pill tone="na">{t("email.unmeasured")}</Pill>
      {result?.error && <span className={styles.muted}>{result.error}</span>}
    </span>
  );
}

export function EmailModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const es = scan.email_security ?? {};
  const grade = es.overall_grade ?? "N/A";
  const spf = es.spf ?? {};
  const dkim = es.dkim ?? {};
  const dmarc = es.dmarc ?? {};
  const notes = asList(es.notes).filter((note) => typeof note === "string");
  const recommendations = asList(es.recommendations);
  const noMail = emailWithoutMail(es);
  // SPF : celui du nom interrogé (sans héritage). Scan antérieur : SPF du domaine racine.
  const spfDomain = spf.domain || es.domain;
  const spfOfApex = !spf.domain && Boolean(es.domain) && es.domain !== scan.domain;
  const selectors = asList(dkim.selectors_found);

  return (
    <ModuleCard scan={scan} module="email_security">
      <div className={styles.gradeLine}>
        <GradeBadge grade={grade} size="md" />
        <div>
          <p className={styles.rowTitle}>{t("email.grade")}</p>
          <p className={styles.muted}>{gradeDescription(grade, es, t)}</p>
        </div>
      </div>
      {es.null_mx === true && (
        <p className={styles.note} data-tone="info">
          {t("email.nullMx")}
        </p>
      )}
      {es.partial && (
        <p className={styles.note} data-tone="warning">
          {t("email.partial")}
        </p>
      )}
      {notes.length > 0 && (
        <div className={styles.subCard} data-tone="info">
          <h3 className={styles.subTitle}>{t("email.notes")}</h3>
          <ul className={styles.issues}>
            {notes.map((note, index) => (
              <li key={index}>{note}</li>
            ))}
          </ul>
        </div>
      )}
      <div className={styles.grid3}>
        <EmailPart name="SPF" found={spf.found} grade={spf.grade} error={spf.error} issues={spf.issues}>
          {spf.found === true && spf.record && <p className={`${styles.rowValue} mono`}>{spf.record}</p>}
          {spf.found === false && <p className={styles.errorText}>{t("email.spfNone")}</p>}
          {spfDomain && (
            <p className={styles.muted}>
              {spfOfApex ? t("email.spfOfApex", { domain: spfDomain, target: scan.domain }) : t("email.spfOf", { domain: spfDomain })}
            </p>
          )}
          {spf.apex_record && (
            <p className={styles.muted}>{t("email.spfApexRecord", { domain: spf.apex_domain ?? "", record: spf.apex_record })}</p>
          )}
        </EmailPart>
        <EmailPart
          name="DKIM"
          found={dkim.found}
          error={dkim.error}
          issues={dkim.issues}
          notApplicable={dkim.found === false && noMail}
          absentTone="warning"
          absentLabel={t("email.notDetected")}
        >
          {dkim.found === true && (
            <>
              <p>{t("email.dkimDetected")}</p>
              {selectors.length > 0 && (
                <div className={styles.pills}>
                  <span className={styles.muted}>{t("email.dkimSelectors")}</span>
                  {selectors.map((selector) => (
                    <Pill key={selector} tone="neutral">
                      {selector}
                    </Pill>
                  ))}
                </div>
              )}
            </>
          )}
          {dkim.found === false && <p>{t(noMail ? "email.dkimNoMail" : "email.dkimNotFound")}</p>}
          {dkim.wildcard === "revoked" && <p className={styles.muted}>{t("email.dkimRevoked")}</p>}
          {es.domain && es.domain !== scan.domain && <p className={styles.muted}>{t("email.analysedOn", { domain: es.domain })}</p>}
        </EmailPart>
        <EmailPart name="DMARC" found={dmarc.found} grade={dmarc.grade} error={dmarc.error} issues={dmarc.issues}>
          {dmarc.found === true && (
            <>
              {dmarc.record && <p className={`${styles.rowValue} mono`}>{dmarc.record}</p>}
              {dmarc.source && (
                <p className={styles.muted}>
                  {t("email.dmarcSource", { source: dmarc.source })}
                  {dmarc.inherited ? ` ${t("email.dmarcInherited")}` : ""}
                </p>
              )}
              {dmarc.policy && (
                <p className={styles.pills}>
                  {t("email.dmarcPolicy")}
                  <Pill tone={dmarc.policy === "reject" ? "ok" : dmarc.policy === "quarantine" ? "warning" : "critical"}>
                    {dmarc.policy}
                  </Pill>
                </p>
              )}
            </>
          )}
          {dmarc.found === false && <p className={styles.errorText}>{t("email.dmarcNone")}</p>}
        </EmailPart>
      </div>
      <div className={styles.subCard}>
        <h3 className={styles.subTitle}>{t("email.transport")}</h3>
        <KvList
          rows={[
            { label: t("email.mtaSts"), value: <RecordState result={es.mta_sts} /> },
            { label: t("email.tlsRpt"), value: <RecordState result={es.tls_rpt} /> },
          ]}
        />
      </div>
      {recommendations.length > 0 && (
        <div className={styles.subCard} data-tone="warning">
          <h3 className={styles.subTitle}>{t("email.recommendations")}</h3>
          <ul className={styles.issues}>
            {recommendations.map((recommendation, index) => (
              <li key={index}>{recommendation}</li>
            ))}
          </ul>
        </div>
      )}
    </ModuleCard>
  );
}

export function EmailFamily({ scan }: FamilyViewProps) {
  return <EmailModule scan={scan} />;
}
