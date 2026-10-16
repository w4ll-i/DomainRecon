import { ChartLine, RotateCw } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";
import { errorDetail } from "../../api/client";
import { useStartScan } from "../../api/queries";
import type { ScanResponse } from "../../api/types";
import { useToast } from "../../components/Toasts";
import { ExportMenu } from "./ExportMenu";
import styles from "./result.module.css";

// `stale` : le scan affiché vient de l'autre langue (relecture en cours après un
// changement de langue) ; l'export attend le texte à jour pour ne pas mélanger deux langues.
export function ResultActions({ scan, stale = false }: { scan: ScanResponse; stale?: boolean }) {
  const { t } = useTranslation();
  const toast = useToast();
  const navigate = useNavigate();
  const start = useStartScan();

  const rescan = () =>
    start.mutate(scan.domain, {
      onSuccess: (job) => navigate(`/scans/live/${job.id}`, { state: { domain: scan.domain } }),
      onError: (error) => toast.show(errorDetail(error), "error"),
    });

  return (
    <div className={styles.actions} role="group" aria-label={t("result.actions")} data-tour="result-export">
      <button type="button" className="btn" data-variant="primary" onClick={rescan} disabled={start.isPending}>
        <RotateCw aria-hidden />
        {t("result.rescan")}
      </button>
      <ExportMenu scanId={scan.id} disabled={stale} />
      <Link to={`/history/${encodeURIComponent(scan.domain)}`} className="btn">
        <ChartLine aria-hidden />
        {t("result.timeline")}
      </Link>
    </div>
  );
}
