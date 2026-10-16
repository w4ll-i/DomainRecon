import { useTranslation } from "react-i18next";
import type { ScanResponse } from "../../../api/types";
import { KvList } from "../../../components/KvList";
import { ModuleCard } from "../../../components/ModuleCard";
import { Pill } from "../../../components/Pills";
import { whoisOtherDomain, whoisStatuses } from "../../../lib/verdicts";
import type { FamilyViewProps } from "../types";
import styles from "./modules.module.css";
import { NotesTags } from "./NotesTags";
import { ScreenshotModule } from "./Screenshot";

export function WhoisModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const whois = scan.whois_data ?? {};
  const other = whoisOtherDomain(scan);
  const statuses = whoisStatuses(whois.status);
  const servers = whois.name_servers ?? [];
  return (
    <ModuleCard scan={scan} module="whois_data">
      {whois.error && !whois.registrar ? (
        <p className={styles.errorText}>{whois.error}</p>
      ) : (
        <>
          {other && (
            <p className={styles.note} data-tone="info">
              {t("identity.whois.otherDomain", { queried: other, domain: scan.domain })}
            </p>
          )}
          {whois.registered === false ? (
            <p className={styles.muted}>{t("identity.whois.notRegistered")}</p>
          ) : (
            <KvList
              rows={[
                { label: t("identity.whois.registrar"), value: whois.registrar },
                { label: t("identity.whois.registrant"), value: whois.registrant },
                { label: t("identity.whois.created"), value: whois.creation_date, mono: true },
                { label: t("identity.whois.expires"), value: whois.expiration_date, mono: true },
                { label: t("identity.whois.updated"), value: whois.updated_date, mono: true },
                { label: t("identity.whois.dnssec"), value: whois.dnssec },
                { label: t("identity.whois.emails"), value: (whois.emails ?? []).join(", "), mono: true },
                {
                  label: t("identity.whois.statuses"),
                  value: statuses.length ? (
                    <span className={styles.pills}>
                      {statuses.map((status) => (
                        <Pill key={status} tone="neutral">
                          {status}
                        </Pill>
                      ))}
                    </span>
                  ) : null,
                },
                {
                  label: t("identity.whois.nameServers"),
                  value: servers.length ? (
                    <ul className="mono">
                      {servers.map((server, index) => (
                        <li key={`${server}-${index}`}>{server}</li>
                      ))}
                    </ul>
                  ) : null,
                },
              ]}
            />
          )}
        </>
      )}
    </ModuleCard>
  );
}

export function IdentityFamily({ scan }: FamilyViewProps) {
  return (
    <>
      <WhoisModule scan={scan} />
      <ScreenshotModule scan={scan} />
      <NotesTags key={scan.id} scan={scan} />
    </>
  );
}
