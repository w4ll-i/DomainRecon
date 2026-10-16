import { useState } from "react";
import { useTranslation } from "react-i18next";
import { errorDetail } from "../../api/client";
import type { ChannelName, ChannelView } from "../../api/ops";
import { useChannels, useSaveChannel, useTestChannel } from "../../api/opsQueries";
import { Loading } from "../../components/PageState";
import { SectionTitle } from "../../components/SectionTitle";
import { useToast } from "../../components/Toasts";
import ops from "../../styles/ops.module.css";
import styles from "./settings.module.css";

const SECURITY_MODES = ["starttls", "ssl", "none"] as const;

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

// Un canal d'alerte : adresse du webhook (masquée par le serveur une fois enregistrée), ou
// réglages SMTP. Un secret laissé vide reste inchangé.
function ChannelCard({ channel }: { channel: ChannelView }) {
  const { t } = useTranslation();
  const toast = useToast();
  const save = useSaveChannel();
  const test = useTestChannel();
  const name: ChannelName = channel.name;
  const config = channel.config;
  const [enabled, setEnabled] = useState(channel.enabled);
  const [url, setUrl] = useState("");
  const [host, setHost] = useState(text(config.host));
  const [port, setPort] = useState(String(config.port ?? ""));
  const [security, setSecurity] = useState(text(config.security) || "starttls");
  const [sender, setSender] = useState(text(config.sender));
  const [recipients, setRecipients] = useState(Array.isArray(config.recipients) ? config.recipients.join(", ") : "");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);
  const isWebhook = name === "discord" || name === "slack" || name === "teams" || name === "webhook";

  // Seuls les secrets saisis sont envoyés : le serveur garde les autres.
  const build = (): Record<string, unknown> => {
    if (isWebhook) return url.trim() ? { url: url.trim() } : {};
    if (name === "email") {
      const body: Record<string, unknown> = {
        host: host.trim(),
        security,
        sender: sender.trim(),
        recipients: recipients.split(/[,;\s]+/).filter(Boolean),
      };
      if (port.trim()) body.port = Number(port);
      if (username) body.username = username;
      if (password) body.password = password;
      return body;
    }
    return {};
  };

  const onSave = () =>
    save.mutate(
      { name, enabled, config: build() },
      {
        onSuccess: () => {
          setUrl("");
          setUsername("");
          setPassword("");
          toast.show(t("settings.channels.saved", { name: t(`settings.channels.names.${name}`) }), "success");
        },
        onError: (error) => toast.show(errorDetail(error), "error"),
      },
    );

  const onTest = () =>
    test.mutate(name, {
      onSuccess: (data) =>
        setResult({ ok: data.ok, message: data.ok ? t("settings.channels.testOk") : (data.error ?? t("settings.channels.testFailed")) }),
      onError: (error) => setResult({ ok: false, message: errorDetail(error) }),
    });

  const label = t(`settings.channels.names.${name}`);
  return (
    <li className={styles.apiRow}>
      <div className={ops.row}>
        <strong>{label}</strong>
        <span className={channel.configured ? ops.ok : ops.muted}>
          {t(channel.configured ? "settings.channels.configured" : "settings.channels.notConfigured")}
        </span>
      </div>
      <label className={ops.check}>
        <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
        <span>{t("settings.channels.enable", { name: label })}</span>
      </label>
      {isWebhook && (
        <div className={ops.field}>
          <label htmlFor={`channel-${name}-url`}>{t("settings.channels.url")}</label>
          <input
            id={`channel-${name}-url`}
            type="password"
            className={`${ops.input} ${ops.mono}`}
            autoComplete="off"
            spellCheck={false}
            value={url}
            placeholder={text(config.url) || "https://"}
            onChange={(event) => setUrl(event.target.value)}
          />
        </div>
      )}
      {name === "email" && (
        <div className={ops.row}>
          <div className={ops.field}>
            <label htmlFor="smtp-host">{t("settings.channels.smtp.host")}</label>
            <input id="smtp-host" className={ops.input} value={host} onChange={(event) => setHost(event.target.value)} />
          </div>
          <div className={ops.field}>
            <label htmlFor="smtp-port">{t("settings.channels.smtp.port")}</label>
            <input id="smtp-port" type="number" min={1} max={65535} className={ops.input} value={port} onChange={(event) => setPort(event.target.value)} />
          </div>
          <div className={ops.field}>
            <label htmlFor="smtp-security">{t("settings.channels.smtp.security")}</label>
            <select id="smtp-security" value={security} onChange={(event) => setSecurity(event.target.value)}>
              {SECURITY_MODES.map((mode) => (
                <option key={mode} value={mode}>
                  {t(`settings.channels.smtp.modes.${mode}`)}
                </option>
              ))}
            </select>
          </div>
          <div className={ops.field}>
            <label htmlFor="smtp-sender">{t("settings.channels.smtp.sender")}</label>
            <input id="smtp-sender" className={ops.input} value={sender} onChange={(event) => setSender(event.target.value)} />
          </div>
          <div className={ops.field}>
            <label htmlFor="smtp-recipients">{t("settings.channels.smtp.recipients")}</label>
            <input id="smtp-recipients" className={ops.input} value={recipients} onChange={(event) => setRecipients(event.target.value)} />
          </div>
          <div className={ops.field}>
            <label htmlFor="smtp-user">{t("settings.channels.smtp.username")}</label>
            <input id="smtp-user" type="password" autoComplete="off" className={ops.input} value={username} placeholder={text(config.username)} onChange={(event) => setUsername(event.target.value)} />
          </div>
          <div className={ops.field}>
            <label htmlFor="smtp-password">{t("settings.channels.smtp.password")}</label>
            <input id="smtp-password" type="password" autoComplete="new-password" className={ops.input} value={password} placeholder={text(config.password)} onChange={(event) => setPassword(event.target.value)} />
          </div>
        </div>
      )}
      {name === "desktop" && <p className={styles.muted}>{t("settings.channels.desktopHint")}</p>}
      <div className={ops.row}>
        <button type="button" className="btn" data-variant="primary" disabled={save.isPending} onClick={onSave}>
          {t("settings.channels.save")}
        </button>
        <button type="button" className="btn" disabled={test.isPending || !channel.configured} onClick={onTest}>
          {t("settings.channels.test")}
        </button>
      </div>
      {result && (
        <p className={result.ok ? ops.ok : ops.error} role="status">
          {result.message}
        </p>
      )}
    </li>
  );
}

// Canaux d'alerte : webhooks Discord, Slack, Teams et JSON, e-mail SMTP, notification de bureau.
// Les secrets sont chiffrés par le serveur et ne reviennent jamais en clair.
export function ChannelsSection() {
  const { t } = useTranslation();
  const channels = useChannels();
  return (
    <section className={styles.card} aria-labelledby="settings-channels">
      <SectionTitle level={2} label={t("settings.channels.kicker")} title={t("settings.channels.title")} id="settings-channels" />
      <p className={styles.muted}>{t("settings.channels.hint")}</p>
      {channels.isPending ? (
        <Loading />
      ) : channels.isError ? (
        <p className={styles.error}>{t("settings.loadError", { detail: errorDetail(channels.error) })}</p>
      ) : (
        <ul className={styles.apiList}>
          {channels.data.channels.map((channel) => (
            <ChannelCard key={channel.name} channel={channel} />
          ))}
        </ul>
      )}
    </section>
  );
}
