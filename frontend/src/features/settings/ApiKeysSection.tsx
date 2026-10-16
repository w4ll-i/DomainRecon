import { CircleCheck, CircleX, KeyRound, LoaderCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorDetail } from "../../api/client";
import { useSaveSettings, useSettings, useTestService } from "../../api/opsQueries";
import { useCatalog } from "../../api/queries";
import { Loading } from "../../components/PageState";
import { SectionTitle } from "../../components/SectionTitle";
import { useToast } from "../../components/Toasts";
import { BASE_TESTABLE, type Service, servicesOf } from "./services";
import ops from "../../styles/ops.module.css";
import styles from "./settings.module.css";

function ServiceRow({
  service,
  masked,
  testable,
  values,
  onEdit,
  onClear,
}: {
  service: Service;
  masked: Record<string, string>;
  testable: boolean;
  values: Record<string, string>;
  onEdit: (name: string, value: string) => void;
  onClear: (name: string) => void;
}) {
  const { t } = useTranslation();
  const test = useTestService();
  const outcome = test.data;
  return (
    <li className={styles.apiRow}>
      <div className={ops.row}>
        <strong>{service.label}</strong>
        {service.keys.some((key) => masked[key.name]) ? (
          <span className={ops.ok}>{t("settings.apiKeys.configured")}</span>
        ) : (
          <span className={ops.muted}>{t("settings.apiKeys.missing")}</span>
        )}
      </div>
      <div className={ops.row}>
        {service.keys.map((key) => (
          <div key={key.name} className={ops.field}>
            <label htmlFor={`key-${key.name}`}>{key.label || key.name}</label>
            <div className={ops.row}>
              <input
                id={`key-${key.name}`}
                type="password"
                className={`${ops.input} ${ops.mono}`}
                autoComplete="off"
                spellCheck={false}
                value={values[key.name] ?? ""}
                placeholder={masked[key.name] || t("settings.apiKeys.placeholder")}
                onChange={(event) => onEdit(key.name, event.target.value)}
              />
              {masked[key.name] && (
                <button type="button" className="btn" data-variant="ghost" onClick={() => onClear(key.name)}>
                  {t("settings.apiKeys.remove")}
                </button>
              )}
            </div>
          </div>
        ))}
        {testable && (
          <button type="button" className="btn" disabled={test.isPending} onClick={() => test.mutate(service.id)}>
            {test.isPending ? <LoaderCircle aria-hidden className="spin" /> : <KeyRound aria-hidden />}
            {t("settings.apiKeys.test")}
          </button>
        )}
      </div>
      {test.isError && <p className={ops.error}>{errorDetail(test.error)}</p>}
      {outcome && (
        <p className={outcome.success ? ops.ok : ops.error} role="status">
          {outcome.success ? <CircleCheck aria-hidden /> : <CircleX aria-hidden />} {outcome.message}
        </p>
      )}
    </li>
  );
}

// Clés d'API par service, lues dans le catalogue des modules. La saisie est masquée ; une
// clé enregistrée s'affiche masquée par le serveur et n'est jamais renvoyée en clair.
export function ApiKeysSection() {
  const { t } = useTranslation();
  const toast = useToast();
  const catalog = useCatalog();
  const settings = useSettings();
  const save = useSaveSettings();
  const [values, setValues] = useState<Record<string, string>>({});
  const [cleared, setCleared] = useState<string[]>([]);

  const services = useMemo(() => servicesOf(catalog.moduleNames.map((name) => catalog.info(name) ?? {})), [catalog]);
  const testable = useMemo(() => {
    const set = new Set(BASE_TESTABLE);
    for (const name of catalog.moduleNames) for (const service of catalog.info(name)?.key_tests ?? []) set.add(service);
    return set;
  }, [catalog]);

  const dirty = Object.values(values).some((value) => value.trim() !== "") || cleared.length > 0;

  const submit = () => {
    const api_keys: Record<string, string> = {};
    for (const [name, value] of Object.entries(values)) if (value.trim() !== "") api_keys[name] = value.trim();
    for (const name of cleared) api_keys[name] = "";
    save.mutate(
      { api_keys },
      {
        onSuccess: () => {
          setValues({});
          setCleared([]);
          toast.show(t("settings.apiKeys.saved"), "success");
        },
        onError: (error) => toast.show(errorDetail(error), "error"),
      },
    );
  };

  const masked = settings.data?.api_keys ?? {};
  const shown = (name: string) => (cleared.includes(name) ? "" : (masked[name] ?? ""));
  const maskedView = Object.fromEntries(services.flatMap((service) => service.keys.map((key) => [key.name, shown(key.name)])));

  return (
    <section className={styles.card} aria-labelledby="settings-api-keys" data-slot="api-keys">
      <SectionTitle level={2} label={t("settings.apiKeys.kicker")} title={t("settings.apiKeys.title")} id="settings-api-keys" />
      <p className={styles.muted}>{t("settings.apiKeys.hint")}</p>
      {settings.isPending ? (
        <Loading />
      ) : settings.isError ? (
        <p className={styles.error}>{t("settings.loadError", { detail: errorDetail(settings.error) })}</p>
      ) : services.length === 0 ? (
        <p className={styles.muted}>{t("settings.apiKeys.none")}</p>
      ) : (
        <>
          <ul className={styles.apiList}>
            {services.map((service) => (
              <ServiceRow
                key={service.id}
                service={service}
                masked={maskedView}
                testable={testable.has(service.id)}
                values={values}
                onEdit={(name, value) => {
                  setValues((current) => ({ ...current, [name]: value }));
                  setCleared((current) => current.filter((item) => item !== name));
                }}
                onClear={(name) => {
                  setValues((current) => ({ ...current, [name]: "" }));
                  setCleared((current) => [...current, name]);
                }}
              />
            ))}
          </ul>
          <p className={styles.muted}>{t("settings.apiKeys.testHint")}</p>
          <div>
            <button type="button" className="btn" data-variant="primary" disabled={!dirty || save.isPending} onClick={submit}>
              {t("settings.apiKeys.save")}
            </button>
          </div>
        </>
      )}
    </section>
  );
}
