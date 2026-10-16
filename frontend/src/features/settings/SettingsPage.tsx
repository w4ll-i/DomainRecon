import { useQueryClient } from "@tanstack/react-query";
import { FolderOpen, KeyRound } from "lucide-react";
import { useSyncExternalStore } from "react";
import { useTranslation } from "react-i18next";
import { errorDetail, getToken, isLocalOnly, setToken, subscribeToken } from "../../api/client";
import { useOpenDataDir, useSystemInfo } from "../../api/queries";
import { Loading } from "../../components/PageState";
import { SectionTitle } from "../../components/SectionTitle";
import { useToast } from "../../components/Toasts";
import { useTokenDialog } from "../../components/TokenDialog";
import { SUPPORTED_LANGS, setLang, useLang } from "../../i18n";
import { setTheme, type Theme, useTheme } from "../../lib/theme";
import { useDocumentTitle } from "../../lib/useDocumentTitle";
import { ApiKeysSection } from "./ApiKeysSection";
import { ChannelsSection } from "./ChannelsSection";
import { ImportSection } from "./ImportSection";
import { LICENSES } from "./licenses";
import { NetworkSection } from "./NetworkSection";
import { UninstallSection } from "./UninstallSection";
import { VpnSection } from "./VpnSection";
import styles from "./settings.module.css";

export function SettingsPage() {
  const { t } = useTranslation();
  const lang = useLang();
  const toast = useToast();
  const tokenDialog = useTokenDialog();
  const queryClient = useQueryClient();
  const info = useSystemInfo();
  const open = useOpenDataDir();
  const { theme } = useTheme();
  const hasToken = useSyncExternalStore(subscribeToken, () => getToken() !== "");
  useDocumentTitle(t("settings.title"));

  const openDataDir = () =>
    open.mutate(undefined, {
      onSuccess: () => toast.show(t("settings.opened"), "success"),
      // Requête venue d'une autre machine : une règle de l'application (avertissement), pas une panne.
      onError: (error) =>
        toast.show(t("settings.openError", { detail: errorDetail(error) }), isLocalOnly(error) ? "warning" : "error"),
    });

  // Les données reçues avec l'ancien jeton ne doivent pas rester à l'écran :
  // resetQueries prévient les vues montées (clear() ne le fait pas) et relit
  // sans jeton ce qui est affiché.
  const forgetToken = () => {
    setToken("");
    void queryClient.resetQueries();
    toast.show(t("token.forgotten"), "info");
  };

  return (
    <div className={styles.page}>
      <SectionTitle level={1} size="page" label={t("settings.kicker")} title={t("settings.title")} />

      <div className={styles.cards}>
        <section className={styles.card} aria-labelledby="settings-lang">
          <SectionTitle level={2} label={t("settings.section.language")} title={t("settings.language")} id="settings-lang" />
          <fieldset className={styles.radios}>
            <legend className="visually-hidden">{t("settings.language")}</legend>
            {SUPPORTED_LANGS.map((code) => (
              <label key={code} className={styles.radio}>
                <input type="radio" name="lang" value={code} checked={lang === code} onChange={() => void setLang(code)} />
                <span lang={code}>{t(`lang.${code}`)}</span>
              </label>
            ))}
          </fieldset>
          <p className={styles.muted}>{t("settings.languageHint")}</p>
        </section>

        <section className={styles.card} aria-labelledby="settings-theme">
          <SectionTitle level={2} label={t("settings.section.language")} title={t("settings.theme")} id="settings-theme" />
          <fieldset className={styles.radios}>
            <legend className="visually-hidden">{t("settings.theme")}</legend>
            {(["dark", "light"] as const).map((code: Theme) => (
              <label key={code} className={styles.radio}>
                <input type="radio" name="theme" value={code} checked={theme === code} onChange={() => setTheme(code)} />
                <span>{t(`settings.themes.${code}`)}</span>
              </label>
            ))}
          </fieldset>
        </section>

        <section className={styles.card} aria-labelledby="settings-data">
          <SectionTitle level={2} label={t("settings.section.data")} title={t("settings.data")} id="settings-data" />
          {info.isPending ? (
            <Loading />
          ) : info.isError ? (
            <p className={styles.error}>{t("settings.infoError", { detail: errorDetail(info.error) })}</p>
          ) : (
            <>
              <p className={`${styles.path} mono`}>{info.data.data_dir}</p>
              {info.data.portable && <p className={styles.muted}>{t("settings.portable")}</p>}
              <p className={styles.muted}>{t("settings.dataHint")}</p>
              <div>
                <button type="button" className="btn" onClick={openDataDir} disabled={open.isPending}>
                  <FolderOpen aria-hidden />
                  {t("settings.open")}
                </button>
              </div>
            </>
          )}
        </section>

        <section className={styles.card} aria-labelledby="settings-version">
          <SectionTitle level={2} label={t("settings.section.version")} title={t("settings.version")} id="settings-version" />
          <p className={`${styles.version} mono`}>{t("settings.versionValue", { version: info.data?.version ?? "…" })}</p>
          {/* docs_enabled absent (serveur plus ancien) ou lecture en échec : la documentation est supposée disponible ; masquée pendant le chargement pour éviter un clignotement. */}
          {!info.isPending && info.data?.docs_enabled !== false && (
            <p>
              <a href="/api/docs" target="_blank" rel="noreferrer">
                {t("settings.apiDocs")}
              </a>
            </p>
          )}
        </section>

        <section className={styles.card} aria-labelledby="settings-token">
          <SectionTitle level={2} label={t("settings.section.token")} title={t("settings.token")} id="settings-token" />
          <p className={styles.muted}>{t(hasToken ? "settings.tokenSet" : "settings.tokenUnset")}</p>
          <div className={styles.actions}>
            <button type="button" className="btn" onClick={tokenDialog.open}>
              <KeyRound aria-hidden />
              {t("settings.tokenEnter")}
            </button>
            {hasToken && (
              <button type="button" className="btn" data-variant="ghost" onClick={forgetToken}>
                {t("token.forget")}
              </button>
            )}
          </div>
        </section>

        <ApiKeysSection />
        <NetworkSection />
        <VpnSection />
        <ChannelsSection />

        <ImportSection />

        <section className={styles.card} aria-labelledby="settings-licenses">
          <SectionTitle level={2} label={t("settings.section.licenses")} title={t("settings.licenses")} id="settings-licenses" />
          <p className={styles.muted}>{t("settings.licensesIntro")}</p>
          <table className={styles.table} aria-labelledby="settings-licenses">
            <thead>
              <tr>
                <th scope="col">{t("settings.licenseName")}</th>
                <th scope="col">{t("settings.licenseType")}</th>
              </tr>
            </thead>
            <tbody>
              {LICENSES.map((entry) => (
                <tr key={entry.name}>
                  <th scope="row">{entry.name}</th>
                  <td className="mono">{entry.license}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <UninstallSection />
      </div>
    </div>
  );
}
