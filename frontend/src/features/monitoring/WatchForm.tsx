import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorDetail } from "../../api/client";
import type { AlertRules, Frequency, WatchChannel } from "../../api/ops";
import { useCreateWatch } from "../../api/opsQueries";
import { useToast } from "../../components/Toasts";
import { useLang } from "../../i18n";
import styles from "../../styles/ops.module.css";
import { BOOLEAN_RULES, DEFAULT_RULES, FREQUENCIES, WATCH_CHANNELS } from "./watchConfig";
import { ProfilePicker } from "../newscan/ProfilePicker";
import { useScanOptions } from "../newscan/scanOptions";

// Règles d'alerte : quatre cases et le seuil d'expiration du certificat (vide : règle désactivée).
export function RulesFields({ rules, onChange, idPrefix }: { rules: AlertRules; onChange: (rules: AlertRules) => void; idPrefix: string }) {
  const { t } = useTranslation();
  return (
    <fieldset className={styles.options}>
      <legend className={styles.label}>{t("monitoring.rules.legend")}</legend>
      {BOOLEAN_RULES.map((rule) => (
        <label key={rule} className={styles.check}>
          <input
            type="checkbox"
            checked={rules[rule]}
            onChange={(event) => onChange({ ...rules, [rule]: event.target.checked })}
          />
          <span>{t(`monitoring.rules.${rule}`)}</span>
        </label>
      ))}
      <div className={styles.field}>
        <label htmlFor={`${idPrefix}-cert`}>{t("monitoring.rules.cert_expiry_days")}</label>
        <input
          id={`${idPrefix}-cert`}
          type="number"
          min={1}
          max={365}
          className={styles.input}
          value={rules.cert_expiry_days ?? ""}
          placeholder={t("monitoring.rules.certOff")}
          onChange={(event) => {
            const raw = event.target.value;
            onChange({ ...rules, cert_expiry_days: raw === "" ? null : Math.min(365, Math.max(1, Number(raw))) });
          }}
        />
      </div>
    </fieldset>
  );
}

// Canaux d'une surveillance : le centre de notifications et les canaux configurés dans les Réglages.
export function ChannelFields({ channels, onChange }: { channels: WatchChannel[]; onChange: (channels: WatchChannel[]) => void }) {
  const { t } = useTranslation();
  const toggle = (channel: WatchChannel, on: boolean) =>
    onChange(WATCH_CHANNELS.filter((item) => (item === channel ? on : channels.includes(item))));
  return (
    <fieldset className={styles.options}>
      <legend className={styles.label}>{t("monitoring.channels.legend")}</legend>
      {WATCH_CHANNELS.map((channel) => (
        <label key={channel} className={styles.check}>
          <input type="checkbox" checked={channels.includes(channel)} onChange={(event) => toggle(channel, event.target.checked)} />
          <span>{t(`monitoring.channels.${channel}`)}</span>
        </label>
      ))}
      <p className={styles.muted}>{t("monitoring.channels.hint")}</p>
    </fieldset>
  );
}

// Ajout d'une surveillance : domaine, profil, fréquence, règles d'alerte et canaux.
export function WatchForm() {
  const { t } = useTranslation();
  const lang = useLang();
  const toast = useToast();
  const create = useCreateWatch();
  const scan = useScanOptions();
  const [domain, setDomain] = useState("");
  const [frequency, setFrequency] = useState<Frequency>("daily");
  const [rules, setRules] = useState<AlertRules>(DEFAULT_RULES);
  const [channels, setChannels] = useState<WatchChannel[]>(["center"]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const payload = scan.payload();
    create.mutate(
      {
        domain: domain.trim(),
        frequency,
        rules,
        channels,
        lang,
        ...payload,
        profile: scan.options.profile,
      },
      {
        onSuccess: () => {
          toast.show(t("monitoring.added", { domain: domain.trim() }), "success");
          setDomain("");
        },
        onError: (error) => toast.show(errorDetail(error), "error"),
      },
    );
  };

  return (
    <form className={styles.card} onSubmit={submit} aria-label={t("monitoring.add.title")}>
      <h2 className={styles.emptyTitle}>{t("monitoring.add.title")}</h2>
      <div className={styles.row}>
        <div className={styles.field}>
          <label htmlFor="watch-domain">{t("monitoring.add.domain")}</label>
          <input
            id="watch-domain"
            className={`${styles.input} ${styles.mono}`}
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
            placeholder={t("newScan.placeholder")}
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <div className={styles.field}>
          <label htmlFor="watch-frequency">{t("monitoring.add.frequency")}</label>
          <select id="watch-frequency" value={frequency} onChange={(event) => setFrequency(event.target.value as Frequency)}>
            {FREQUENCIES.map((value) => (
              <option key={value} value={value}>
                {t(`monitoring.frequency.${value}`)}
              </option>
            ))}
          </select>
        </div>
      </div>
      <ProfilePicker catalog={scan.catalog} value={scan.options} onChange={scan.setOptions} needsAuth={scan.needsAuth} />
      <RulesFields rules={rules} onChange={setRules} idPrefix="watch-new" />
      <ChannelFields channels={channels} onChange={setChannels} />
      <div>
        <button type="submit" className="btn" data-variant="primary" disabled={create.isPending || domain.trim().length < 3 || !scan.valid}>
          {t("monitoring.add.submit")}
        </button>
      </div>
    </form>
  );
}
