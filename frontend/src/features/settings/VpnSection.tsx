import { Shield, ShieldOff } from "lucide-react";
import { useTranslation } from "react-i18next";
import { errorDetail } from "../../api/client";
import { useVpn } from "../../api/opsQueries";
import { Loading } from "../../components/PageState";
import { SectionTitle } from "../../components/SectionTitle";
import ops from "../../styles/ops.module.css";
import styles from "./settings.module.css";

// Statut du VPN Mullvad, en lecture seule : DomainRecon ne se connecte ni ne se déconnecte.
export function VpnSection() {
  const { t } = useTranslation();
  const vpn = useVpn();
  return (
    <section className={styles.card} aria-labelledby="settings-vpn">
      <SectionTitle level={2} label={t("settings.vpn.kicker")} title={t("settings.vpn.title")} id="settings-vpn" />
      {vpn.isPending ? (
        <Loading />
      ) : vpn.isError ? (
        <p className={styles.error}>{t("settings.vpn.error", { detail: errorDetail(vpn.error) })}</p>
      ) : (
        <>
          <p className={vpn.data.connected ? ops.ok : ops.muted} role="status">
            {vpn.data.connected ? <Shield aria-hidden /> : <ShieldOff aria-hidden />} {vpn.data.message}
          </p>
          {(vpn.data.ip || vpn.data.country) && (
            <p className={`${styles.muted} mono`}>{[vpn.data.ip, vpn.data.country].filter(Boolean).join(" · ")}</p>
          )}
          <p className={styles.muted}>{t("settings.vpn.hint")}</p>
        </>
      )}
    </section>
  );
}
