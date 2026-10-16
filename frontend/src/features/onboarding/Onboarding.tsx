import { Compass, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useRecentScans } from "../../api/queries";
import { Modal } from "../../components/Modal";
import modal from "../../components/Modal.module.css";
import { GuidedTour } from "./GuidedTour";
import styles from "./Onboarding.module.css";
import { markOnboardingSeen, onboardingSeen, OPEN_ONBOARDING_EVENT } from "./onboardingEvents";
import { buildSteps } from "./steps";

type Phase = "closed" | "welcome" | "tour";

// Premier lancement : un court accueil (à quoi sert l'outil, usage autorisé seulement) propose
// la visite guidée de l'interface. « Plus tard », Échap, « Passer » ou « Terminer » la marquent
// comme faite ; la page Aide et la palette de commandes la relancent (sans l'accueil).
// Les scans récents (même requête que la palette) disent si la visite peut ouvrir un exemple
// de résultat.
export function Onboarding({ waitMs }: { waitMs?: number }) {
  const { t } = useTranslation();
  const [phase, setPhase] = useState<Phase>(() => (onboardingSeen() ? "closed" : "welcome"));
  // Chaque relance repart de la première étape.
  const [run, setRun] = useState(0);
  const recent = useRecentScans(5);
  const scanId = recent.data?.scans[0]?.id ?? null;
  const steps = useMemo(() => buildSteps(scanId), [scanId]);
  const startButton = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const start = () => {
      setRun((value) => value + 1);
      setPhase("tour");
    };
    window.addEventListener(OPEN_ONBOARDING_EVENT, start);
    return () => window.removeEventListener(OPEN_ONBOARDING_EVENT, start);
  }, []);

  const close = useCallback(() => {
    markOnboardingSeen();
    setPhase("closed");
  }, []);

  return (
    <>
      <Modal open={phase === "welcome"} labelledBy="onboarding-title" describedBy="onboarding-text" onCancel={close} initialFocus={startButton}>
        <div className={styles.body}>
          <Compass aria-hidden className={styles.icon} />
          <h2 id="onboarding-title" className={modal.title}>
            {t("onboarding.welcome.title")}
          </h2>
          <p id="onboarding-text" className={styles.text}>
            {t("onboarding.welcome.text")}
          </p>
          <p className={styles.notice}>
            <ShieldAlert aria-hidden />
            <span>{t("onboarding.welcome.authorized")}</span>
          </p>
          <p className={styles.text}>{t("onboarding.welcome.tour")}</p>
          <p className={styles.hint}>{t("onboarding.welcome.replay")}</p>
          <div className={styles.actions}>
            <button type="button" className="btn" data-variant="ghost" onClick={close}>
              {t("onboarding.welcome.later")}
            </button>
            <button
              ref={startButton}
              type="button"
              className="btn"
              data-variant="primary"
              onClick={() => {
                setRun((value) => value + 1);
                setPhase("tour");
              }}
            >
              {t("onboarding.welcome.start")}
            </button>
          </div>
        </div>
      </Modal>
      {phase === "tour" && <GuidedTour key={run} steps={steps} onClose={close} waitMs={waitMs} />}
    </>
  );
}
