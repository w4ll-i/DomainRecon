import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorDetail } from "../../api/client";
import type { SettingsView } from "../../api/ops";
import { useSaveSettings, useSettings } from "../../api/opsQueries";
import { Loading } from "../../components/PageState";
import { SectionTitle } from "../../components/SectionTitle";
import { useToast } from "../../components/Toasts";
import ops from "../../styles/ops.module.css";
import styles from "./settings.module.css";

const MIN_TIMEOUT = 5;
const MAX_TIMEOUT = 600;

function Form({ settings }: { settings: SettingsView }) {
  const { t } = useTranslation();
  const toast = useToast();
  const save = useSaveSettings();
  const [scanTimeout, setScanTimeout] = useState(String(settings.scan_timeout));
  const [quickTimeout, setQuickTimeout] = useState(String(settings.quick_timeout));
  const [screenshot, setScreenshot] = useState(settings.screenshot_enabled);
  // Proxy : l'adresse enregistrée revient avec son mot de passe masqué ; la renvoyer telle quelle ne la change pas.
  const [proxy, setProxy] = useState(settings.proxy_url);

  const inRange = (value: string) => {
    const number = Number(value);
    return Number.isInteger(number) && number >= MIN_TIMEOUT && number <= MAX_TIMEOUT;
  };
  const valid = inRange(scanTimeout) && inRange(quickTimeout);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!valid) return;
    save.mutate(
      {
        scan_timeout: Number(scanTimeout),
        quick_timeout: Number(quickTimeout),
        screenshot_enabled: screenshot,
        proxy_url: proxy.trim(),
      },
      {
        onSuccess: () => toast.show(t("settings.network.saved"), "success"),
        onError: (error) => toast.show(errorDetail(error), "error"),
      },
    );
  };

  return (
    <form className={ops.stack} onSubmit={submit}>
      <div className={ops.row}>
        <div className={ops.field}>
          <label htmlFor="set-scan-timeout">{t("settings.network.scanTimeout")}</label>
          <input
            id="set-scan-timeout"
            type="number"
            min={MIN_TIMEOUT}
            max={MAX_TIMEOUT}
            className={ops.input}
            value={scanTimeout}
            onChange={(event) => setScanTimeout(event.target.value)}
            aria-invalid={!inRange(scanTimeout) || undefined}
          />
        </div>
        <div className={ops.field}>
          <label htmlFor="set-quick-timeout">{t("settings.network.quickTimeout")}</label>
          <input
            id="set-quick-timeout"
            type="number"
            min={MIN_TIMEOUT}
            max={MAX_TIMEOUT}
            className={ops.input}
            value={quickTimeout}
            onChange={(event) => setQuickTimeout(event.target.value)}
            aria-invalid={!inRange(quickTimeout) || undefined}
          />
        </div>
      </div>
      <p className={styles.muted}>{t("settings.network.timeoutHint", { min: MIN_TIMEOUT, max: MAX_TIMEOUT })}</p>

      <label className={ops.check}>
        <input type="checkbox" checked={screenshot} onChange={(event) => setScreenshot(event.target.checked)} />
        <span>{t("settings.network.screenshot")}</span>
      </label>
      <p className={styles.muted}>{t("settings.network.screenshotHint")}</p>

      <div className={ops.field}>
        <label htmlFor="set-proxy">{t("settings.network.proxy")}</label>
        <input
          id="set-proxy"
          className={`${ops.input} ${ops.mono}`}
          value={proxy}
          autoComplete="off"
          spellCheck={false}
          placeholder="socks5h://127.0.0.1:1080"
          onChange={(event) => setProxy(event.target.value)}
        />
      </div>
      <p className={styles.muted}>{t("settings.network.proxyHint")}</p>
      <p className={styles.muted} role="note">
        {t("settings.network.proxyDns")}
      </p>

      <div>
        <button type="submit" className="btn" data-variant="primary" disabled={!valid || save.isPending}>
          {t("settings.network.save")}
        </button>
      </div>
    </form>
  );
}

// Délais des scans, capture d'écran et proxy HTTP/SOCKS. Le DNS ne passe pas par le proxy.
export function NetworkSection() {
  const { t } = useTranslation();
  const settings = useSettings();
  return (
    <section className={styles.card} aria-labelledby="settings-network">
      <SectionTitle level={2} label={t("settings.network.kicker")} title={t("settings.network.title")} id="settings-network" />
      {settings.isPending ? (
        <Loading />
      ) : settings.isError ? (
        <p className={styles.error}>{t("settings.loadError", { detail: errorDetail(settings.error) })}</p>
      ) : (
        <Form key={JSON.stringify([settings.data.scan_timeout, settings.data.quick_timeout, settings.data.screenshot_enabled, settings.data.proxy_url])} settings={settings.data} />
      )}
    </section>
  );
}
