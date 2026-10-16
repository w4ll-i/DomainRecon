import { useTranslation } from "react-i18next";
import { Link, useRouteError } from "react-router";
import { ErrorState } from "../components/PageState";
import { useDocumentTitle } from "../lib/useDocumentTitle";
import styles from "../styles/page.module.css";

// Erreur de rendu imprévue : message, rechargement et sortie vers le nouveau
// scan (si le plantage est déterministe, recharger ne suffit pas), jamais un
// écran blanc.
export function RouteError() {
  const { t } = useTranslation();
  const error = useRouteError();
  useDocumentTitle(t("errors.routeTitle"));
  return (
    <div className={styles.page}>
      <ErrorState headingLevel={1} title={t("errors.routeTitle")} detail={error instanceof Error ? error.message : String(error ?? "")}>
        <button type="button" className="btn" onClick={() => window.location.reload()}>
          {t("errors.reload")}
        </button>
        <Link to="/" className="btn">
          {t("nav.newScan")}
        </Link>
      </ErrorState>
    </div>
  );
}
