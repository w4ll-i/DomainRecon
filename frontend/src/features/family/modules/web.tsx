import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import type { RedirectHop, ScanResponse, WebFile } from "../../../api/types";
import { GradeBadge } from "../../../components/GradeBadge";
import { ModuleCard } from "../../../components/ModuleCard";
import { Pill } from "../../../components/Pills";
import { scanModuleState } from "../../../lib/moduleState";
import type { Tone } from "../../../lib/tones";
import { cleanName, headerChecks } from "../../../lib/verdicts";
import type { FamilyViewProps } from "../types";
import styles from "./modules.module.css";

const HEADER_TONES: Record<string, Tone> = { ok: "ok", weak: "warning", invalid: "critical", missing: "critical", info: "info" };

export function HeadersModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const sec = scan.security_headers ?? {};
  const counts = sec.counts;
  const summary =
    counts && typeof counts.total === "number"
      ? [
          t("web.headers.counts", { ok: counts.ok ?? 0, total: counts.total }),
          counts.weak ? t("web.headers.weak", { count: counts.weak }) : "",
          counts.invalid ? t("web.headers.invalid", { count: counts.invalid }) : "",
          counts.missing ? t("web.headers.missing", { count: counts.missing }) : "",
        ]
          .filter(Boolean)
          .join(" · ")
      : "";
  return (
    <ModuleCard scan={scan} module="security_headers">
      {summary && <p className={styles.lead}>{summary}</p>}
      {sec.off_site_redirect && (
        <p className={styles.note} data-tone="warning">
          {t("web.headers.offSite", { url: sec.off_site_redirect })}
        </p>
      )}
      {sec.https_downgrade === true && (
        <p className={styles.note} data-tone="critical">
          {t("web.headers.downgrade")}
        </p>
      )}
      <ul className={styles.rows}>
        {headerChecks(sec).map((row) => {
          // Ancien scan : seule la présence est connue, la valeur n'a pas été
          // évaluée ; un verdict « Conforme » serait trompeur.
          const unevaluated = row.legacy && row.status === "ok";
          return (
            <li key={row.name} className={styles.row} data-tone={unevaluated ? "neutral" : HEADER_TONES[row.status]}>
              <div className={styles.rowHead}>
                <span className={`${styles.rowTitle} mono`}>{row.name}</span>
                {!unevaluated && <Pill tone={HEADER_TONES[row.status]}>{t(`headerStatus.${row.status}`)}</Pill>}
              </div>
              {row.legacy ? (
                <p className={styles.rowText}>{t(row.status === "ok" ? "web.headers.legacyPresent" : "web.headers.legacyMissing")}</p>
              ) : (
                row.detail && <p className={styles.rowText}>{row.detail}</p>
              )}
              {row.value && <p className={`${styles.rowValue} mono`}>{row.value}</p>}
            </li>
          );
        })}
      </ul>
    </ModuleCard>
  );
}

export function CookiesModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const cs = scan.cookie_security ?? {};
  const cookies = (cs.cookies ?? []).filter((cookie) => cookie && typeof cookie === "object");
  return (
    <ModuleCard scan={scan} module="cookie_security">
      <div className={styles.gradeLine}>
        <GradeBadge grade={cs.score ?? "N/A"} size="md" />
        <span>{t("web.cookies.analysed", { count: cookies.length })}</span>
      </div>
      {cookies.length === 0 ? (
        <p className={styles.muted}>{t("web.cookies.none")}</p>
      ) : (
        <ul className={styles.rows}>
          {cookies.map((cookie, index) => {
            const issues = cookie.issues ?? [];
            const samesite = String(cookie.samesite ?? "").toLowerCase();
            const scope = [
              cookie.domain ? t("web.cookies.scopeDomain", { value: cookie.domain }) : "",
              cookie.path ? t("web.cookies.scopePath", { value: cookie.path }) : "",
            ]
              .filter(Boolean)
              .join(" · ");
            return (
              <li key={`${cookie.name}-${cookie.domain ?? ""}-${cookie.path ?? ""}-${index}`} className={styles.row}>
                <div className={styles.rowHead}>
                  <span className={`${styles.rowTitle} mono`}>{cookie.name}</span>
                  <Pill tone={issues.length ? "warning" : "ok"}>
                    {issues.length ? t("web.cookies.problems", { count: issues.length }) : t("web.cookies.secure")}
                  </Pill>
                </div>
                {scope && <p className={`${styles.rowValue} mono`}>{scope}</p>}
                <div className={styles.pills}>
                  <Pill tone={cookie.secure ? "ok" : "critical"}>
                    {t(cookie.secure ? "web.cookies.flagYes" : "web.cookies.flagNo", { flag: "Secure" })}
                  </Pill>
                  <Pill tone={cookie.httponly ? "ok" : "critical"}>
                    {t(cookie.httponly ? "web.cookies.flagYes" : "web.cookies.flagNo", { flag: "HttpOnly" })}
                  </Pill>
                  <Pill
                    tone={!samesite ? "critical" : samesite === "none" ? "warning" : "ok"}
                    title={samesite === "none" ? t("web.cookies.sameSiteNone") : undefined}
                  >
                    {samesite ? t("web.cookies.sameSite", { value: cookie.samesite }) : t("web.cookies.sameSiteMissing")}
                  </Pill>
                </div>
                {issues.length > 0 && (
                  <ul className={styles.issues} data-tone="warning">
                    {issues.map((issue, position) => (
                      <li key={position}>{issue}</li>
                    ))}
                  </ul>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </ModuleCard>
  );
}

export function CorsModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const cors = scan.cors ?? {};
  // Verdict aligné sur le score : reflet avec credentials (critique),
  // configuration permissive, tests d'origine en échec (aucune conclusion),
  // « * » sans credentials (acceptable), correct, inactif.
  const critical = Boolean(cors.misconfigured && (cors.severity === "critical" || cors.reflects_with_credentials === true));
  const inconclusive = Boolean(cors.partial && !cors.misconfigured);
  const wildcardOnly = !cors.misconfigured && Boolean(cors.allows_any_origin);
  const [tone, key]: [Tone, string] = critical
    ? ["critical", "web.cors.critical"]
    : cors.misconfigured
      ? ["warning", "web.cors.permissive"]
      : inconclusive
        ? ["warning", "web.cors.inconclusive"]
        : wildcardOnly
          ? ["info", "web.cors.wildcard"]
          : cors.cors_enabled
            ? ["ok", "web.cors.ok"]
            : ["neutral", "web.cors.disabled"];
  // Un risque présent est rouge, absent est vert ; « CORS activé : Non » est
  // un état courant (10/10 au score), donc neutre.
  const risk = (value: boolean): Tone => (value ? "critical" : "ok");
  const anyOrigin = Boolean(cors.allows_any_origin);
  const credentialsWildcard = Boolean(cors.allows_credentials_with_wildcard);
  const checks: Array<{ key: string; value: boolean; tone: Tone }> = [
    { key: "web.cors.enabled", value: Boolean(cors.cors_enabled), tone: cors.cors_enabled ? "ok" : "neutral" },
    { key: "web.cors.anyOrigin", value: anyOrigin, tone: anyOrigin && !credentialsWildcard ? "info" : risk(anyOrigin) },
    { key: "web.cors.credentialsWildcard", value: credentialsWildcard, tone: risk(credentialsWildcard) },
    // Les tests d'origine ont échoué : « Non » n'est pas établi, la ligne est omise.
    ...(inconclusive ? [] : [{ key: "web.cors.reflects", value: Boolean(cors.reflects_origin), tone: risk(Boolean(cors.reflects_origin)) }]),
    ...(!inconclusive && cors.reflects_with_credentials !== undefined
      ? [{ key: "web.cors.reflectsCredentials", value: Boolean(cors.reflects_with_credentials), tone: risk(Boolean(cors.reflects_with_credentials)) }]
      : []),
  ];
  const details = cors.details ?? [];
  const errors = cors.partial ? (cors.origin_tests?.errors ?? []) : [];
  return (
    <ModuleCard scan={scan} module="cors">
      <p className={styles.banner} data-tone={tone}>
        {t(key)}
      </p>
      <ul className={styles.checks}>
        {checks.map((check) => (
          <li key={check.key} className={styles.check}>
            <span>{t(check.key)}</span>
            <Pill tone={check.tone}>{t(check.value ? "common.yes" : "common.no")}</Pill>
          </li>
        ))}
      </ul>
      {details.length > 0 && (
        <div>
          <h3 className={styles.subTitle}>{t("web.cors.details")}</h3>
          <ul className={styles.issues}>
            {details.map((detail, index) => (
              <li key={index}>{detail}</li>
            ))}
          </ul>
        </div>
      )}
      {errors.length > 0 && (
        <div>
          <h3 className={styles.subTitle}>
            {t("web.cors.originErrors", { failed: errors.length, total: cors.origin_tests?.total ?? "?" })}
          </h3>
          <ul className={`${styles.issues} mono`}>
            {errors.map((error, index) => (
              <li key={index}>{error}</li>
            ))}
          </ul>
        </div>
      )}
    </ModuleCard>
  );
}

function HopList({ hops }: { hops: RedirectHop[] }) {
  const { t } = useTranslation();
  if (!hops.length) return null;
  return (
    <ol className={styles.hops}>
      {hops.map((hop, index) => {
        const code = hop.status_code ?? 0;
        const tone: Tone = code >= 200 && code < 300 ? "ok" : code >= 300 && code < 400 ? "warning" : "critical";
        const last = index === hops.length - 1;
        return (
          <li key={index} className={styles.hop} data-last={last ? (hop.error ? "error" : "ok") : undefined}>
            <span className={styles.hopIndex} aria-label={t("web.redirects.step", { index: index + 1 })}>
              {index + 1}
            </span>
            <div className={styles.hopBody}>
              <p className={`${styles.rowValue} mono`}>{hop.url}</p>
              <div className={styles.pills}>
                <Pill tone={tone}>{code || "?"}</Pill>
                {hop.server && <span className={styles.muted}>{t("web.redirects.server", { value: hop.server })}</span>}
                {hop.error && <span className={styles.errorText}>{hop.error}</span>}
              </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

export function RedirectsModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const rc = scan.redirect_chain ?? {};
  const clean = (list?: RedirectHop[]) => (Array.isArray(list) ? list.filter((hop) => hop && typeof hop === "object") : []);
  const chain = clean(rc.chain);
  const httpsChain = clean(rc.https_chain);
  const hasChains = chain.length > 0 || httpsChain.length > 0;
  const measured = scanModuleState(scan, "redirect_chain").status === "ok";
  // forces_https null : HTTP sans réponse, ce n'est pas un « Non ».
  const [forcesTone, forcesKey]: [Tone, string] =
    rc.forces_https === true ? ["ok", "common.yes"] : rc.forces_https === false ? ["critical", "common.no"] : ["neutral", "common.unknown"];
  return (
    <ModuleCard scan={scan} module="redirect_chain" showChildrenWhenUnavailable={hasChains}>
      {!hasChains ? (
        <p className={styles.muted}>{t("web.redirects.none")}</p>
      ) : (
        <>
          {measured && (
            <dl className={styles.stats}>
              <div>
                <dt>{t("web.redirects.hops")}</dt>
                <dd className={styles.statValue}>{rc.total_hops ?? t("common.na")}</dd>
              </div>
              <div>
                <dt>{t("web.redirects.forcesHttps")}</dt>
                <dd>
                  <Pill tone={forcesTone}>{t(forcesKey)}</Pill>
                  {rc.https_downgrade === true && (
                    <Pill tone="critical" title={t("web.redirects.downgradeTitle")}>
                      {t("web.redirects.downgrade")}
                    </Pill>
                  )}
                </dd>
              </div>
              <div>
                <dt>{t("web.redirects.finalUrl")}</dt>
                <dd className={`${styles.ellipsis} mono`} title={rc.final_url ?? undefined}>
                  {rc.final_url ?? t("common.na")}
                </dd>
              </div>
            </dl>
          )}
          {(rc.warnings ?? []).map((warning, index) => (
            <p key={index} className={styles.note} data-tone="warning">
              {warning}
            </p>
          ))}
          {chain.length > 0 && httpsChain.length > 0 && <h3 className={styles.subTitle}>{t("web.redirects.fromHttp")}</h3>}
          <HopList hops={chain} />
          {httpsChain.length > 0 && (
            <>
              <h3 className={styles.subTitle}>{t("web.redirects.fromHttps")}</h3>
              <HopList hops={httpsChain} />
            </>
          )}
        </>
      )}
    </ModuleCard>
  );
}

type FileState = "found" | "absent" | "unverified";
// Un fichier absent est un constat courant (sitemap.xml, security.txt), pas une alerte.
const FILE_TONES: Record<FileState, Tone> = { found: "ok", absent: "neutral", unverified: "warning" };

// Trois états : trouvé, absent (found === false), non vérifié (found null).
function FileCard({ name, file, children }: { name: string; file: WebFile; children: ReactNode }) {
  const { t } = useTranslation();
  const state: FileState = file.found ? "found" : file.found === false ? "absent" : "unverified";
  return (
    <div className={styles.subCard}>
      <div className={styles.rowHead}>
        <span className={`${styles.rowTitle} mono`}>{name}</span>
        <Pill tone={FILE_TONES[state]}>{t(`web.files.${state}`)}</Pill>
      </div>
      {state === "unverified" ? <p className={styles.muted}>{file.error || t("web.files.unverifiedDefault")}</p> : children}
    </div>
  );
}

export function WebFilesModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const wf = scan.web_files ?? {};
  const robots = wf.robots_txt ?? {};
  const sitemap = wf.sitemap_xml ?? {};
  const securityTxt = wf.security_txt ?? {};
  const disallowed = robots.disallowed ?? [];
  const sitemaps = robots.sitemaps ?? [];
  return (
    <ModuleCard scan={scan} module="web_files">
      {wf.partial && (
        <p className={styles.note} data-tone="warning">
          {t("web.files.partial")}
        </p>
      )}
      <div className={styles.grid3}>
        <FileCard name="robots.txt" file={robots}>
          {robots.found ? (
            <>
              {disallowed.length > 0 && (
                <>
                  <p className={styles.muted}>{t("web.files.disallowed", { count: disallowed.length })}</p>
                  <ul className={`${styles.scrollList} mono`}>
                    {disallowed.slice(0, 30).map((path, index) => (
                      <li key={index}>{path}</li>
                    ))}
                  </ul>
                </>
              )}
              {sitemaps.length > 0 && (
                <>
                  <p className={styles.muted}>{t("web.files.sitemaps")}</p>
                  <ul className={`${styles.scrollList} mono`}>
                    {sitemaps.map((url, index) => (
                      <li key={index}>{url}</li>
                    ))}
                  </ul>
                </>
              )}
              {!disallowed.length && !sitemaps.length && (
                <>
                  <p>{t("web.files.noRestriction")}</p>
                  {robots.content && <pre className={styles.excerpt}>{robots.content.slice(0, 500)}</pre>}
                </>
              )}
            </>
          ) : (
            <p className={styles.muted}>{t("web.files.notFound")}</p>
          )}
        </FileCard>
        <FileCard name="sitemap.xml" file={sitemap}>
          {sitemap.found ? (
            <>
              <p>{t(sitemap.truncated ? "web.files.urlCountMin" : "web.files.urlCount", { count: sitemap.url_count ?? 0 })}</p>
              {sitemap.truncated && (
                <p className={styles.note} data-tone="warning">
                  {t("web.files.truncated")}
                </p>
              )}
            </>
          ) : (
            <p className={styles.muted}>{t("web.files.notFound")}</p>
          )}
        </FileCard>
        <FileCard name="security.txt" file={securityTxt}>
          {securityTxt.found ? (
            <>
              {securityTxt.contact && <p className="mono">{t("web.files.contact", { value: securityTxt.contact })}</p>}
              {securityTxt.content && <pre className={styles.excerpt}>{securityTxt.content.slice(0, 500)}</pre>}
            </>
          ) : (
            <p className={styles.muted}>{t("web.files.recommended")}</p>
          )}
        </FileCard>
      </div>
    </ModuleCard>
  );
}

export function TechnologiesModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const technologies = (scan.technologies ?? []).filter((tech) => tech && typeof tech === "object");
  return (
    <ModuleCard scan={scan} module="technologies">
      {technologies.length === 0 ? (
        <p className={styles.muted}>{t("web.tech.none")}</p>
      ) : (
        <ul className={styles.chips}>
          {technologies.map((tech, index) => (
            <li key={`${tech.name}-${index}`} className={styles.chip}>
              <span className={styles.chipName}>{tech.name}</span>
              {tech.category && <span className={styles.muted}>{tech.category}</span>}
            </li>
          ))}
        </ul>
      )}
    </ModuleCard>
  );
}

const WAF_CONFIDENCES = ["high", "medium", "low"];

export function WafModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const waf = scan.waf ?? {};
  const evidence = waf.evidence ?? [];
  const cdnEvidence = waf.cdn_evidence ?? [];
  // Nom ou confiance manquants : un libellé générique, jamais « WAF » ni « ? »
  // en guise de valeur.
  const wafName = cleanName(waf.waf_name);
  const cdnName = cleanName(waf.cdn_name);
  const confidence = typeof waf.confidence === "string" && WAF_CONFIDENCES.includes(waf.confidence) ? waf.confidence : null;
  return (
    <ModuleCard scan={scan} module="waf">
      {waf.detected ? (
        <div className={styles.subCard} data-tone="ok">
          <p className={styles.bigValue}>{wafName || t("web.waf.unnamed")}</p>
          <p className={styles.muted}>
            {confidence
              ? t("web.waf.detected", { confidence: t(`confidence.${confidence}`) })
              : t("web.waf.detectedNoConfidence")}
          </p>
          {evidence.length > 0 && (
            <>
              <h3 className={styles.subTitle}>{t("web.waf.evidence")}</h3>
              <ul className={`${styles.issues} mono`}>
                {evidence.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      ) : (
        <div className={styles.subCard}>
          <p className={styles.rowTitle}>{t("web.waf.none")}</p>
          <p className={styles.muted}>{t("web.waf.noneText")}</p>
        </div>
      )}
      {waf.cdn_detected && (
        <div className={styles.subCard} data-tone="info">
          <p className={styles.rowTitle}>{cdnName ? t("web.waf.cdn", { name: cdnName }) : t("web.waf.cdnUnnamed")}</p>
          <p className={styles.muted}>{t("web.waf.cdnText")}</p>
          {cdnEvidence.length > 0 && (
            <ul className={`${styles.issues} mono`}>
              {cdnEvidence.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          )}
        </div>
      )}
      {waf.off_site_redirect && <p className={styles.muted}>{t("web.waf.offSite", { url: waf.off_site_redirect })}</p>}
    </ModuleCard>
  );
}

export function WebFamily({ scan }: FamilyViewProps) {
  return (
    <>
      <HeadersModule scan={scan} />
      <CookiesModule scan={scan} />
      <CorsModule scan={scan} />
      <RedirectsModule scan={scan} />
      <WebFilesModule scan={scan} />
      <TechnologiesModule scan={scan} />
      <WafModule scan={scan} />
    </>
  );
}
