import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { ApiError, errorDetail } from "../../api/client";
import { ErrorState } from "../../components/PageState";

// Scan illisible : 404 (supprimé, base remplacée) avec une sortie, sinon
// l'erreur telle que rendue par le serveur et « Réessayer ».
export function ScanError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const { t } = useTranslation();
  if (error instanceof ApiError && error.status === 404) {
    return (
      <ErrorState headingLevel={1} title={t("result.notFound")} detail={t("result.notFoundText")}>
        <Link to="/history" className="btn">
          {t("live.openHistory")}
        </Link>
      </ErrorState>
    );
  }
  return <ErrorState headingLevel={1} detail={errorDetail(error)} onRetry={onRetry} />;
}
