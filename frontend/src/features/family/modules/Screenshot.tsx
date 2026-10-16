import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { apiRequest, errorDetail } from "../../../api/client";
import type { ScanResponse } from "../../../api/types";
import { ModuleCard } from "../../../components/ModuleCard";
import { Loading } from "../../../components/PageState";
import { currentLang } from "../../../i18n";
import styles from "./modules.module.css";

type ShotState = { status: "loading" } | { status: "ready"; url: string } | { status: "error"; detail: string };

// La capture passe par apiRequest (jeton d'API éventuel) puis s'affiche en URL
// blob: (autorisée par la CSP), révoquée quand le composant disparaît.
export function ScreenshotModule({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const name = scan.screenshot_path;
  const [shot, setShot] = useState<ShotState>({ status: "loading" });

  useEffect(() => {
    if (!name) return undefined;
    const controller = new AbortController();
    let objectUrl: string | null = null;
    setShot({ status: "loading" });
    // Langue des erreurs du serveur : celle de l'interface (l'image, elle, n'en dépend pas).
    apiRequest(`/screenshot/${encodeURIComponent(name)}`, { lang: currentLang(), signal: controller.signal })
      .then((res) => res.blob())
      .then((blob) => {
        if (controller.signal.aborted) return;
        objectUrl = URL.createObjectURL(blob);
        setShot({ status: "ready", url: objectUrl });
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) setShot({ status: "error", detail: errorDetail(error) });
      });
    return () => {
      controller.abort();
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [name]);

  return (
    <ModuleCard scan={scan} module="screenshot">
      {!name ? (
        <p className={styles.muted}>{t("identity.screenshot.none")}</p>
      ) : shot.status === "loading" ? (
        <Loading label={t("identity.screenshot.loading")} />
      ) : shot.status === "error" ? (
        <p className={styles.warnText}>{t("identity.screenshot.unavailable", { detail: shot.detail })}</p>
      ) : (
        <figure className={styles.screenshot}>
          <img
            src={shot.url}
            alt={t("identity.screenshot.alt", { domain: scan.domain })}
            className={styles.screenshotImg}
            onError={() => setShot({ status: "error", detail: t("identity.screenshot.undecodable") })}
          />
          <figcaption className={styles.muted}>{t("identity.screenshot.caption")}</figcaption>
        </figure>
      )}
    </ModuleCard>
  );
}
