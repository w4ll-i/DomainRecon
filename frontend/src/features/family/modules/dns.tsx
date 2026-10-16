import type { TFunction } from "i18next";
import { type ReactNode, useState } from "react";
import { useTranslation } from "react-i18next";
import type { MxRecord, ScanResponse, SoaRecord } from "../../../api/types";
import { KvList } from "../../../components/KvList";
import { ModuleCard } from "../../../components/ModuleCard";
import { Pill } from "../../../components/Pills";
import { isNullMx, subdomainCount, subdomainResolution, takeoverConfirmed, takeoverTested } from "../../../lib/verdicts";
import type { FamilyViewProps } from "../types";
import styles from "./modules.module.css";
import { LazyNetworkGraph } from "./lazyParts";

// Types d'enregistrements ; les clés en minuscules de dns_records sont des métadonnées.
const DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "DMARC"] as const;
const SUBDOMAINS_SHOWN = 200;
const NXDOMAIN_TEXT = /\(NXDOMAIN\)/;

// Scan antérieur : une liste peut être null ou absente, jamais un plantage.
function asList<T>(value: readonly T[] | null | undefined): T[] {
  return Array.isArray(value) ? [...value] : [];
}

function recordText(type: (typeof DNS_TYPES)[number], value: unknown, t: TFunction): ReactNode {
  if (type === "MX" && value && typeof value === "object") {
    const mx = value as MxRecord;
    return isNullMx(mx) ? `[${mx.priority ?? 0}] . — ${t("dns.nullMx")}` : `[${mx.priority ?? "?"}] ${mx.value ?? ""}`;
  }
  if (type === "SOA" && value && typeof value === "object") {
    const soa = value as SoaRecord;
    return t("dns.soa", { mname: soa.mname ?? "?", rname: soa.rname ?? "?", serial: soa.serial ?? "?" });
  }
  return String(value);
}

export function DnsRecordsModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const records = scan.dns_records ?? {};
  const errors = records.errors && typeof records.errors === "object" ? records.errors : {};
  const blocks: ReactNode[] = [];
  const empty: string[] = [];
  for (const type of DNS_TYPES) {
    const values: unknown[] = Array.isArray(records[type]) ? (records[type] as unknown[]) : [];
    const error = Object.hasOwn(errors, type) ? errors[type] : null;
    // Une requête en échec n'est pas une absence d'enregistrement.
    if (error) {
      blocks.push(
        <div key={type} className={styles.recordBlock} data-tone="warning">
          <div className={styles.rowHead}>
            <span className={styles.recordType}>{type}</span>
            <span className={styles.warnText}>{t("dns.queryFailed")}</span>
          </div>
          <p className={`${styles.recordList} mono`}>{error}</p>
        </div>,
      );
      continue;
    }
    if (!values.length) {
      empty.push(type);
      continue;
    }
    blocks.push(
      <div key={type} className={styles.recordBlock}>
        <div className={styles.rowHead}>
          <span className={styles.recordType}>{type}</span>
          <span className={styles.muted}>{t("dns.records", { count: values.length })}</span>
        </div>
        <ul className={`${styles.recordList} mono`}>
          {values.map((value, index) => (
            <li key={index}>{recordText(type, value, t)}</li>
          ))}
        </ul>
        {type === "DMARC" && records.dmarc_source && <p className={styles.muted}>{t("dns.dmarcSource", { source: records.dmarc_source })}</p>}
      </div>,
    );
  }
  // Scan antérieur à dns_records.nxdomain : seul le module e-mail le disait (texte d'origine).
  // Le marqueur « (NXDOMAIN) » est le même dans toutes les langues du serveur.
  const nxdomain =
    records.nxdomain === true ||
    (records.nxdomain === undefined && !blocks.length && NXDOMAIN_TEXT.test(String(scan.email_security?.error ?? "")));
  // La bannière dit déjà « domaine inexistant » : la note du serveur ferait doublon.
  const notes = asList(records.notes).filter((note) => typeof note === "string" && !(nxdomain && NXDOMAIN_TEXT.test(note)));
  return (
    <ModuleCard scan={scan} module="dns_records">
      {nxdomain && (
        <div className={styles.banner} data-tone="critical">
          <p className={styles.rowTitle}>{t("dns.nxdomain")}</p>
          <p>{t("dns.nxdomainText", { domain: scan.domain })}</p>
        </div>
      )}
      {blocks.length > 0 ? <div className={styles.records}>{blocks}</div> : !nxdomain && <p className={styles.muted}>{t("dns.none")}</p>}
      {blocks.length > 0 && empty.length > 0 && <p className={styles.muted}>{t("dns.emptyTypes", { types: empty.join(", ") })}</p>}
      {(records.wildcard === true || notes.length > 0) && (
        <div className={styles.subCard}>
          <h3 className={styles.subTitle}>{t("dns.info")}</h3>
          {records.wildcard === true && (
            <p>
              <Pill tone="warning">{t("dns.wildcard")}</Pill>
            </p>
          )}
          <ul className={styles.issues}>
            {notes.map((note, index) => (
              <li key={index}>{note}</li>
            ))}
          </ul>
        </div>
      )}
    </ModuleCard>
  );
}

export function SubdomainsModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const [showAll, setShowAll] = useState(false);
  const subs = asList(scan.subdomains).filter((sub) => sub && typeof sub === "object");
  const count = subdomainCount(scan);
  const resolved = subs.filter((sub) => sub.ip).length;
  const wildcard = subs.filter((sub) => sub.ip && sub.wildcard === true).length;
  const untested = subs.filter((sub) => !sub.ip && sub.resolution === "not_tested").length;
  const status = scan.module_status?.subdomains;
  const source = status?.source === "certspotter" ? "Cert Spotter" : "crt.sh";
  const visible = showAll ? subs : subs.slice(0, SUBDOMAINS_SHOWN);
  const summary = [
    count.total > count.shown ? t("dns.subdomains.countCapped", count) : t("dns.subdomains.count", { shown: count.shown }),
    `${t("dns.subdomains.resolved", { count: resolved })}${wildcard ? ` ${t("dns.subdomains.wildcardCount", { count: wildcard })}` : ""}`,
    untested ? t("dns.subdomains.untested", { count: untested }) : "",
  ]
    .filter(Boolean)
    .join(" · ");
  return (
    <ModuleCard scan={scan} module="subdomains">
      <p className={styles.lead}>{summary}</p>
      {status?.partial === true && (
        <p className={styles.note} data-tone="warning">
          {t("dns.subdomains.fallback")}
        </p>
      )}
      {subs.length === 0 ? (
        <p className={styles.muted}>{t("dns.subdomains.none", { source })}</p>
      ) : (
        <>
          <ul className={styles.subList}>
            {visible.map((sub, index) => {
              const resolution = subdomainResolution(sub);
              const text =
                resolution.kind === "wildcard"
                  ? t("dns.subdomains.wildcardIp", { ip: resolution.ip })
                  : resolution.kind === "resolved"
                    ? resolution.ip
                    : t(resolution.kind === "untested" ? "dns.subdomains.notTested" : "dns.subdomains.unresolved");
              const title =
                resolution.kind === "wildcard"
                  ? t("dns.subdomains.wildcardTitle")
                  : resolution.kind === "untested"
                    ? t("dns.subdomains.notTestedTitle")
                    : undefined;
              return (
                <li key={`${sub.subdomain}-${index}`} className={styles.subItem}>
                  <span className="mono">{sub.subdomain}</span>
                  <span className={`${styles.resolution} mono`} data-kind={resolution.kind} title={title}>
                    {text}
                  </span>
                </li>
              );
            })}
          </ul>
          {subs.length > SUBDOMAINS_SHOWN && (
            <button type="button" className="btn" onClick={() => setShowAll((value) => !value)}>
              {showAll ? t("common.showLess") : t("common.showAll", { count: subs.length })}
            </button>
          )}
        </>
      )}
    </ModuleCard>
  );
}

export function TakeoverModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const entries = asList(scan.subdomain_takeover).filter((entry) => entry && typeof entry === "object");
  const tested = takeoverTested(scan);
  const total = asList(scan.subdomains).length;
  const confirmed = entries.filter(takeoverConfirmed).length;
  const toCheck = entries.length - confirmed;
  return (
    <ModuleCard scan={scan} module="subdomain_takeover" showChildrenWhenUnavailable={entries.length > 0}>
      {entries.length === 0 ? (
        <div className={styles.banner} data-tone="ok">
          <p className={styles.rowTitle}>{t("dns.takeover.none")}</p>
          {tested !== null && (
            <p>{tested < total ? t("dns.takeover.testedOf", { tested, total }) : t("dns.takeover.tested", { count: tested })}</p>
          )}
        </div>
      ) : (
        <>
          <div className={styles.banner} data-tone={confirmed ? "critical" : "warning"}>
            <p className={styles.rowTitle}>
              {[confirmed ? t("dns.takeover.confirmed", { count: confirmed }) : "", toCheck ? t("dns.takeover.toCheck", { count: toCheck }) : ""]
                .filter(Boolean)
                .join(" · ")}
            </p>
            <p>{t(confirmed ? "dns.takeover.dangerText" : "dns.takeover.checkText")}</p>
          </div>
          <ul className={styles.rows}>
            {entries.map((entry, index) => {
              const isConfirmed = takeoverConfirmed(entry);
              const risk = ["high", "medium", "low"].includes(String(entry.risk)) ? String(entry.risk) : "medium";
              const proof = entry.cname_nxdomain ? "proofNx" : entry.fingerprint_matched ? "proofFingerprint" : "proofNoHttp";
              return (
                <li key={`${entry.subdomain}-${index}`} className={styles.row} data-tone={isConfirmed ? "critical" : "warning"}>
                  <div className={styles.rowHead}>
                    <span className={`${styles.rowTitle} mono`}>{entry.subdomain}</span>
                    <Pill tone={isConfirmed ? "critical" : "warning"}>
                      {t(isConfirmed ? "dns.takeover.confirmedPill" : "dns.takeover.toCheckPill")}
                    </Pill>
                    <Pill tone={risk === "high" ? "critical" : risk === "medium" ? "warning" : "neutral"}>{t(`dns.takeover.risk.${risk}`)}</Pill>
                  </div>
                  <KvList
                    rows={[
                      { label: t("dns.takeover.cname"), value: entry.cname, mono: true },
                      { label: t("dns.takeover.provider"), value: entry.provider || entry.service || t("dns.takeover.unknownProvider") },
                      {
                        label: t("dns.takeover.proof"),
                        value: (
                          <span className={styles.pills}>
                            <Pill tone={proof === "proofNoHttp" ? "neutral" : isConfirmed ? "critical" : "warning"}>{t(`dns.takeover.${proof}`)}</Pill>
                            {entry.status_code != null && <span className="mono">{t("dns.takeover.http", { code: entry.status_code })}</span>}
                          </span>
                        ),
                      },
                    ]}
                  />
                  {entry.evidence && <p className={styles.muted}>{entry.evidence}</p>}
                </li>
              );
            })}
          </ul>
        </>
      )}
    </ModuleCard>
  );
}

export function ReverseDnsModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const rdns = scan.reverse_dns ?? {};
  const aliases = asList(rdns.aliases);
  return (
    <ModuleCard scan={scan} module="reverse_dns">
      <KvList
        rows={[
          { label: t("dns.rdns.ip"), value: scan.ip_address, mono: true },
          ...(rdns.ptr ? [{ label: t("dns.rdns.ptr"), value: rdns.ptr, mono: true }] : []),
          ...(rdns.ptr && aliases.length ? [{ label: t("dns.rdns.aliases"), value: aliases.join(", "), mono: true }] : []),
        ]}
      />
      {!rdns.ptr && (
        <div className={styles.note} data-tone="warning">
          <p>{t("dns.rdns.none")}</p>
          {rdns.error && <p>{rdns.error}</p>}
        </div>
      )}
    </ModuleCard>
  );
}

export function DnsFamily({ scan }: FamilyViewProps) {
  return (
    <>
      <LazyNetworkGraph scan={scan} />
      <DnsRecordsModule scan={scan} />
      <SubdomainsModule scan={scan} />
      <TakeoverModule scan={scan} />
      <ReverseDnsModule scan={scan} />
    </>
  );
}
