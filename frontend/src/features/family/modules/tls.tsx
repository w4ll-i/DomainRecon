import { useTranslation } from "react-i18next";
import type { ScanResponse } from "../../../api/types";
import { KvList } from "../../../components/KvList";
import { ModuleCard } from "../../../components/ModuleCard";
import { Pill } from "../../../components/Pills";
import { UnavailableNotice } from "../../../components/UnavailableNotice";
import { scanModuleState } from "../../../lib/moduleState";
import type { Tone } from "../../../lib/tones";
import { tlsVerdict } from "../../../lib/verdicts";
import type { FamilyViewProps } from "../types";
import styles from "./modules.module.css";

// Verdict en tête : un certificat invalide ou l'absence de HTTPS sont des
// constats (0/20 au score), pas des détails ni des mesures manquées.
export function TlsModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const tls = scan.tls_certificate ?? {};
  const verdict = tlsVerdict(scan);
  const state = scanModuleState(scan, "tls_certificate");
  const invalid = verdict.level === "critical" && verdict.label === "verdict.tls.invalid";
  const downgrade = scan.redirect_chain?.https_downgrade === true || scan.security_headers?.https_downgrade === true;
  const hasCertificate = "not_after" in tls || Boolean(tls.subject);
  const san = Array.isArray(tls.san) ? tls.san : [];
  const days = tls.days_remaining;
  const daysTone: Tone = invalid ? "critical" : days == null ? "neutral" : days > 30 ? "ok" : days > 7 ? "warning" : "critical";

  if (verdict.level === "na") {
    return (
      <ModuleCard scan={scan} module="tls_certificate">
        {state.status === "ok" && <UnavailableNotice state={{ status: "failed", error: tls.error ?? verdict.detail ?? null }} />}
      </ModuleCard>
    );
  }

  return (
    <ModuleCard scan={scan} module="tls_certificate">
      {tls.https === false ? (
        <div className={styles.banner} data-tone="critical">
          <p className={styles.rowTitle}>{t("tls.noHttps")}</p>
          {tls.verify_error && <p>{tls.verify_error}</p>}
        </div>
      ) : invalid ? (
        <div className={styles.banner} data-tone="critical">
          <p className={styles.rowTitle}>{t("tls.invalid")}</p>
          <p>
            {verdict.detail ?? t("tls.refused")}
            {tls.verify_code != null && <span className="mono"> ({t("tls.verifyCode", { code: tls.verify_code })})</span>}
          </p>
          <p className={styles.rowText}>{t("tls.invalidHint")}</p>
        </div>
      ) : (
        tls.valid === true && (
          <p className={styles.note} data-tone="ok">
            {t("tls.valid")}
          </p>
        )
      )}
      {downgrade && (
        <p className={styles.note} data-tone="critical">
          {t("tls.downgrade")}
        </p>
      )}
      {hasCertificate ? (
        <div className={styles.grid2}>
          <div className={styles.subCard}>
            <h3 className={styles.subTitle}>{t("tls.certificate")}</h3>
            <KvList
              rows={[
                { label: t("tls.subject"), value: tls.subject, mono: true },
                { label: t("tls.issuer"), value: tls.issuer_org || tls.issuer_cn },
                { label: t("tls.serial"), value: tls.serial_number, mono: true },
                { label: t("tls.version"), value: tls.version },
              ]}
            />
          </div>
          <div className={styles.subCard}>
            <h3 className={styles.subTitle}>{t("tls.validity")}</h3>
            <KvList
              rows={[
                ...(typeof tls.valid === "boolean"
                  ? [
                      {
                        label: t("tls.status"),
                        value: (
                          <Pill tone={tls.valid ? "ok" : "critical"}>
                            {t(tls.valid ? "tls.statusValid" : "tls.statusInvalid")}
                          </Pill>
                        ),
                      },
                    ]
                  : []),
                { label: t("tls.notBefore"), value: tls.not_before, mono: true },
                { label: t("tls.notAfter"), value: tls.not_after, mono: true },
                { label: t("tls.daysRemaining"), value: days != null ? <Pill tone={daysTone}>{days}</Pill> : null },
              ]}
            />
          </div>
          <div className={styles.subCard}>
            <h3 className={styles.subTitle}>{t("tls.connection")}</h3>
            <KvList
              rows={[
                { label: t("tls.protocol"), value: tls.protocol, mono: true },
                { label: t("tls.cipher"), value: tls.cipher, mono: true },
                { label: t("tls.bits"), value: tls.cipher_bits },
              ]}
            />
          </div>
          <div className={styles.subCard}>
            <h3 className={styles.subTitle}>{t("tls.san", { count: san.length })}</h3>
            <ul className={`${styles.scrollList} mono`}>
              {san.map((name, index) => (
                <li key={`${name}-${index}`}>{name}</li>
              ))}
            </ul>
          </div>
        </div>
      ) : (
        // « Aucune information » seulement si rien d'autre n'a été dit : ni
        // constat en tête, ni certificat valide, ni rétrogradation.
        !invalid && tls.https !== false && tls.valid !== true && !downgrade && <p className={styles.muted}>{t("tls.noInfo")}</p>
      )}
    </ModuleCard>
  );
}

export function TlsFamily({ scan }: FamilyViewProps) {
  return <TlsModule scan={scan} />;
}
