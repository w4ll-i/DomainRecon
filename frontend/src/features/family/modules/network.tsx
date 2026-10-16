import { useTranslation } from "react-i18next";
import type { ScanResponse } from "../../../api/types";
import { KvList } from "../../../components/KvList";
import { ModuleCard } from "../../../components/ModuleCard";
import { Pill } from "../../../components/Pills";
import { useLang } from "../../../i18n";
import { countryCode, countryName } from "../../../lib/format";
import { isValidCoordinate } from "../../../lib/geo";
import { normalizeOpenPorts } from "../../../lib/ports";
import { neighborsCount, sharedCdnIp } from "../../../lib/verdicts";
import type { FamilyViewProps } from "../types";
import { LazyGeoMap } from "./lazyParts";
import styles from "./modules.module.css";

function SharedCdnNotice({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  if (!sharedCdnIp(scan)) return null;
  return (
    <p className={styles.note} data-tone="warning">
      {t("network.geo.sharedCdn")}
    </p>
  );
}

export function GeoModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const lang = useLang();
  const geo = scan.geo_data ?? {};
  const lat = Number(geo.lat);
  const lon = Number(geo.lon);
  const hasCoords = geo.lat != null && geo.lon != null && isValidCoordinate(lat, lon);
  const code = countryCode(geo);
  const country = countryName(geo, lang);
  const place = [geo.city, country].filter(Boolean).join(", ");
  return (
    <ModuleCard scan={scan} module="geo_data">
      <SharedCdnNotice scan={scan} />
      {!hasCoords && !country ? (
        <p className={styles.muted}>{t("network.geo.noData")}</p>
      ) : (
        <div className={styles.grid2}>
          <KvList
            rows={[
              { label: t("network.geo.country"), value: country && code && country !== code ? `${country} (${code})` : country },
              { label: t("network.geo.region"), value: geo.region },
              { label: t("network.geo.city"), value: geo.city },
              { label: t("network.geo.coordinates"), value: hasCoords ? `${lat}, ${lon}` : null, mono: true },
              { label: t("network.geo.timezone"), value: geo.timezone },
              { label: t("network.geo.isp"), value: geo.isp },
              { label: t("network.geo.asn"), value: geo.as_info, mono: true },
            ]}
          />
          {hasCoords && (
            <LazyGeoMap lat={lat} lon={lon} title={scan.domain} subtitle={[place, scan.ip_address].filter(Boolean).join(" · ")} />
          )}
        </div>
      )}
    </ModuleCard>
  );
}

export function PortsModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const ports = normalizeOpenPorts(scan.open_ports);
  // Ports sensibles : pénalités « port_<n> » du score (score.py, SENSITIVE_PORTS).
  const sensitive = new Set(
    (scan.security_score?.penalties ?? [])
      .map((penalty) => penalty?.key)
      .filter((key): key is string => typeof key === "string" && key.startsWith("port_"))
      .map((key) => Number(key.slice(5))),
  );
  return (
    <ModuleCard scan={scan} module="open_ports">
      {ports.length === 0 ? (
        <p className={styles.muted}>{t("network.ports.none")}</p>
      ) : (
        <ul className={styles.ports}>
          {ports.map((port, index) => (
            <li key={`${port.port}-${index}`} className={styles.port} data-sensitive={sensitive.has(port.port) ? "true" : undefined}>
              <span className={`${styles.portNumber} mono`}>{port.port}</span>
              {port.service && <span>{port.service}</span>}
              {port.state && <Pill tone="neutral">{port.state}</Pill>}
              {sensitive.has(port.port) && <Pill tone="critical">{t("network.ports.sensitive")}</Pill>}
            </li>
          ))}
        </ul>
      )}
    </ModuleCard>
  );
}

export function NetworkExtModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const net = scan.network_extended ?? {};
  const asn = net.asn_info ?? {};
  const neighbors = net.reverse_ip_neighbors ?? [];
  const count = neighborsCount(net);
  return (
    <ModuleCard scan={scan} module="network_extended">
      <SharedCdnNotice scan={scan} />
      <div className={styles.subCard}>
        <h3 className={styles.subTitle}>{t("network.ext.asn")}</h3>
        {net.asn_error ? (
          <p className={styles.warnText}>{t("network.ext.sourceError", { reason: net.asn_error })}</p>
        ) : (
          <KvList
            rows={[
              { label: t("network.geo.asn"), value: asn.asn, mono: true },
              { label: t("network.ext.org"), value: asn.org },
              { label: t("network.ext.hostname"), value: asn.hostname, mono: true },
              { label: t("network.ext.anycast"), value: asn.anycast },
            ]}
          />
        )}
      </div>
      <div className={styles.subCard}>
        <div className={styles.rowHead}>
          <h3 className={`${styles.subTitle} ${styles.rowTitle}`}>{t("network.ext.neighbors")}</h3>
          {!net.neighbors_error && (
            <Pill tone="neutral" title={net.neighbors_truncated ? t("network.ext.truncated") : undefined}>
              {count.total > count.shown ? t("network.ext.countOf", count) : t("network.ext.count", { shown: count.shown })}
            </Pill>
          )}
        </div>
        {net.neighbors_error ? (
          <p className={styles.warnText}>{t("network.ext.sourceError", { reason: net.neighbors_error })}</p>
        ) : neighbors.length ? (
          <ol className={`${styles.scrollList} mono`}>
            {neighbors.map((neighbor, index) => (
              <li key={`${neighbor}-${index}`}>{neighbor}</li>
            ))}
          </ol>
        ) : (
          <p className={styles.muted}>{t("network.ext.none")}</p>
        )}
      </div>
    </ModuleCard>
  );
}

export function NetworkFamily({ scan }: FamilyViewProps) {
  return (
    <>
      <GeoModule scan={scan} />
      <PortsModule scan={scan} />
      <NetworkExtModule scan={scan} />
    </>
  );
}
