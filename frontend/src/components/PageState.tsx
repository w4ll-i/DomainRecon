import { CircleAlert, LoaderCircle, RotateCw } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import styles from "./PageState.module.css";

export function Loading({ label }: { label?: string }) {
  const { t } = useTranslation();
  return (
    <div className={styles.loading} role="status">
      <LoaderCircle aria-hidden className="spin" />
      <span>{label ?? t("common.loading")}</span>
    </div>
  );
}

interface ErrorStateProps {
  title?: string;
  // Niveau du titre : 1 pour un écran entier (sans autre titre), absent pour un
  // état intégré à une page qui a déjà son titre.
  headingLevel?: 1 | 2 | 3;
  detail?: string;
  onRetry?: () => void;
  children?: ReactNode;
}

export function ErrorState({ title, detail, headingLevel, onRetry, children }: ErrorStateProps) {
  const { t } = useTranslation();
  const Title = headingLevel ? (`h${headingLevel}` as const) : "p";
  return (
    <div className={styles.error} role="alert">
      <CircleAlert aria-hidden className={styles.icon} />
      <div className={styles.body}>
        <Title className={styles.title}>{title ?? t("errors.title")}</Title>
        {detail && <p className={styles.detail}>{detail}</p>}
        {(onRetry || children) && (
          <div className={styles.actions}>
            {onRetry && (
              <button type="button" className="btn" onClick={onRetry}>
                <RotateCw aria-hidden />
                {t("common.retry")}
              </button>
            )}
            {children}
          </div>
        )}
      </div>
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className={styles.empty}>{children}</div>;
}
