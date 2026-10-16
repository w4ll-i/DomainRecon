import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { useDocumentTitle } from "../lib/useDocumentTitle";
import styles from "../styles/page.module.css";

export function NotFoundPage() {
  const { t } = useTranslation();
  useDocumentTitle(t("notFound.title"));
  return (
    <div className={styles.page}>
      <h1 className={styles.title}>{t("notFound.title")}</h1>
      <p className={styles.muted}>{t("notFound.text")}</p>
      <div>
        <Link to="/" className="btn" data-variant="primary">
          {t("notFound.home")}
        </Link>
      </div>
    </div>
  );
}
