import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { ApiError, errorDetail } from "../../api/client";
import { type StartScanInput, useStartScan } from "../../api/queries";
import { useToast } from "../../components/Toasts";
import { charCount } from "../../lib/format";

// Bornes de ScanRequest (API) : vérifiées avant l'envoi, le serveur restant juge.
export const DOMAIN_MIN = 3;
export const DOMAIN_MAX = 255;

type ErrorTarget = "field" | "toast";

// Lancement d'un scan, partagé par le champ de « Nouveau scan » et le champ de scan
// rapide de l'en-tête : validation de longueur, envoi, puis ouverture du suivi en
// direct. `report` dit où va un refus : « field » (texte `error` à afficher près du
// champ, le cas de « Nouveau scan ») ou « toast » (notification, pour l'en-tête qui
// n'a pas de place pour un message). Trop de scans en cours (429) n'est jamais une
// faute de saisie : toujours une notification, annoncée une seule fois.
export function useLaunchScan(report: ErrorTarget = "field") {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const toast = useToast();
  const start = useStartScan();
  const [error, setError] = useState<string | null>(null);

  // Renvoie faux quand la saisie est refusée avant tout envoi. `onStarted` est appelé
  // quand le serveur a accepté le scan (par exemple pour vider le champ), avant l'ouverture
  // du suivi en direct. `options` : profil, modules choisis et autorisation (voir scanOptions.ts).
  const launch = (raw: string, onStarted?: () => void, options?: Omit<StartScanInput, "domain">): boolean => {
    const value = raw.trim();
    const length = charCount(value);
    if (length < DOMAIN_MIN || length > DOMAIN_MAX) {
      const message = t("newScan.lengthError", { min: DOMAIN_MIN, max: DOMAIN_MAX });
      if (report === "toast") toast.show(message, "warning");
      else setError(message);
      return false;
    }
    setError(null);
    start.mutate(options ? { domain: value, ...options } : value, {
      onSuccess: (job) => {
        onStarted?.();
        navigate(`/scans/live/${job.id}`, { state: { domain: value } });
      },
      onError: (failure) => {
        const detail = errorDetail(failure);
        if (failure instanceof ApiError && failure.status === 429) toast.show(detail, "warning");
        else if (report === "toast") toast.show(detail, "error");
        else setError(detail);
      },
    });
    return true;
  };

  return { launch, pending: start.isPending, error, clearError: () => setError(null) };
}
