import { useQueryClient } from "@tanstack/react-query";
import { CircleX, RotateCw, TriangleAlert, X } from "lucide-react";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useLocation, useNavigate, useParams } from "react-router";
import { ApiError, errorDetail } from "../../api/client";
import { useCancelJob, useCatalog, useJobStatus, useStartScan } from "../../api/queries";
import { ErrorState } from "../../components/PageState";
import { SectionTitle } from "../../components/SectionTitle";
import { useToast } from "../../components/Toasts";
import { useDocumentTitle } from "../../lib/useDocumentTitle";
import { LiveProgress } from "./LiveProgress";
import { LiveTile } from "./LiveTile";
import styles from "./LiveScanPage.module.css";
import { useElapsedSeconds } from "./useElapsedSeconds";
import { useJobEvents } from "./useJobEvents";

// Bandeau d'issue (annulée, échouée, suivi perdu) : l'icône et le titre disent l'état,
// la couleur le souligne.
function Outcome({
  tone,
  title,
  detail,
  alert = false,
  children,
}: {
  tone: "warning" | "critical";
  title: string;
  detail?: string | null;
  alert?: boolean;
  children: ReactNode;
}) {
  const Icon = tone === "critical" ? CircleX : TriangleAlert;
  return (
    <div className={styles.outcome} data-tone={tone} role={alert ? "alert" : "status"}>
      <Icon aria-hidden className={styles.outcomeIcon} />
      <div className={styles.outcomeBody}>
        <p className={styles.outcomeTitle}>{title}</p>
        {detail && <p className={styles.outcomeDetail}>{detail}</p>}
        <div className={styles.outcomeActions}>{children}</div>
      </div>
    </div>
  );
}

// Identifiant de tâche du serveur (32 caractères hexadécimaux, comme l'API).
const JOB_ID = /^[0-9a-f]{32}$/;

// Lien profond mal formé : message clair, sans appel au serveur.
function InvalidJob() {
  const { t } = useTranslation();
  useDocumentTitle(t("live.invalidJobTitle"));
  return (
    <div className={styles.page}>
      <ErrorState headingLevel={1} title={t("live.invalidJobTitle")} detail={t("live.invalidJob")}>
        <Link to="/history" className="btn">
          {t("live.openHistory")}
        </Link>
        <Link to="/" className="btn" data-variant="primary">
          {t("live.newScan")}
        </Link>
      </ErrorState>
    </div>
  );
}

// Une instance par tâche : « Relancer » navigue vers un autre jobId et doit
// repartir d'un état neuf (réducteur, chronomètre, redirection).
export function LiveScanPage() {
  const { jobId = "" } = useParams();
  if (!JOB_ID.test(jobId)) return <InvalidJob />;
  return <LiveScan key={jobId} jobId={jobId} />;
}

function LiveScan({ jobId }: { jobId: string }) {
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const toast = useToast();
  const queryClient = useQueryClient();
  const status = useJobStatus(jobId);
  const catalog = useCatalog();
  const live = useJobEvents(jobId);
  const cancel = useCancelJob();
  const start = useStartScan();
  const navigated = useRef(false);
  // Annulation acceptée (202) : le bouton reste désactivé jusqu'à l'événement final.
  const [cancelRequested, setCancelRequested] = useState(false);

  const initialDomain = (location.state as { domain?: string } | null)?.domain ?? null;
  const domain = status.data?.domain ?? initialDomain;
  const running = live.phase === "connecting" || live.phase === "running";
  const elapsed = useElapsedSeconds(running);
  const finished = live.phase === "done" || live.phase === "failed" || live.phase === "cancelled";
  const jobMissing = status.error instanceof ApiError && (status.error.status === 404 || status.error.status === 422);
  // Jamais « perdue » en même temps qu'une issue connue (échec, annulation, fin).
  const lost = !finished && (live.phase === "lost" || (jobMissing && live.done === 0));
  useDocumentTitle(domain ? t("live.title", { domain }) : t("live.titleUnknown"));

  useEffect(() => {
    // Toute fin de tâche peut avoir enregistré un scan (annulation arrivée
    // pendant la sauvegarde) : l'historique et les timelines (qui citent les
    // scans) sont rechargés dans tous les cas.
    if (finished) {
      void queryClient.invalidateQueries({ queryKey: ["history"] });
      void queryClient.invalidateQueries({ queryKey: ["timeline"] });
    }
  }, [finished, queryClient]);

  useEffect(() => {
    if (live.phase !== "done" || live.scanId === null || navigated.current) return;
    navigated.current = true;
    if (domain) toast.show(t("live.done", { domain }), "success");
    navigate(`/scans/${live.scanId}`, { replace: true });
  }, [live.phase, live.scanId, domain, navigate, queryClient, t, toast]);

  const restart = () => {
    if (!domain) {
      navigate("/");
      return;
    }
    start.mutate(domain, {
      onSuccess: (job) => navigate(`/scans/live/${job.id}`, { replace: true, state: { domain } }),
      onError: (error) => toast.show(errorDetail(error), "error"),
    });
  };

  const onCancel = () =>
    cancel.mutate(jobId, {
      onSuccess: () => setCancelRequested(true),
      onError: (error) => {
        // 409 : la tâche se termine déjà, l'événement final va arriver : rien à signaler.
        if (error instanceof ApiError && error.status === 409) {
          setCancelRequested(true);
          return;
        }
        toast.show(t("live.cancelError", { detail: errorDetail(error) }), "error");
      },
    });
  const cancelling = cancel.isPending || cancelRequested;
  // Avant le premier événement, le total de l'état est celui par défaut (18 modules) : celui du plan
  // de cette tâche, que le serveur donne dès son état, évite d'afficher « 0 modules sur 18 » puis de
  // corriger quand le profil lance un autre nombre de modules.
  const announced =
    live.phase === "connecting" && status.data && status.data.total > 0 ? { ...live, total: status.data.total } : live;

  const restartButton = (
    <button type="button" className="btn" onClick={restart} disabled={start.isPending}>
      <RotateCw aria-hidden />
      {t("live.restart")}
    </button>
  );

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <div className={styles.heading}>
          <h1 className={styles.title}>{domain ? t("live.title", { domain }) : t("live.titleUnknown")}</h1>
        </div>
        {running && !lost && (
          <button type="button" className="btn" onClick={onCancel} disabled={cancelling}>
            <X aria-hidden />
            {cancelling ? t("live.cancelling") : t("live.cancel")}
          </button>
        )}
      </header>

      <LiveProgress live={announced} elapsed={elapsed} />

      {live.phase === "connecting" && live.done === 0 && !lost && (
        <p className={styles.muted} role="status">
          {t("live.connecting")}
        </p>
      )}

      {live.phase === "cancelled" && (
        <Outcome tone="warning" title={t("live.cancelled")} detail={t("live.cancelledText")}>
          <Link to="/" className="btn" data-variant="primary">
            {t("live.newScan")}
          </Link>
          {restartButton}
        </Outcome>
      )}

      {live.phase === "failed" && (
        <Outcome tone="critical" title={t("live.failed")} detail={live.error?.detail} alert>
          {restartButton}
          <Link to="/" className="btn">
            {t("live.newScan")}
          </Link>
        </Outcome>
      )}

      {lost && (
        <Outcome tone="warning" title={t("live.lost")} detail={live.error?.detail ?? t("live.jobNotFound")}>
          <Link to="/history" className="btn">
            {t("live.openHistory")}
          </Link>
          {restartButton}
        </Outcome>
      )}

      <section className={styles.tilesSection} aria-labelledby="live-tiles-title">
        <SectionTitle label={t("live.tiles.kicker")} title={t("live.tiles.title")} id="live-tiles-title" />
        <ul className={styles.tiles}>
          {catalog.families.map((family) => (
            <li key={family}>
              <LiveTile family={family} state={live} />
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
