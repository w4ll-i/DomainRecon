import type { ModuleName } from "../../api/types";
import type { Lang } from "../../i18n";
import { STATIC_CATALOG } from "../../lib/catalog";
import type { Catalog } from "../../lib/catalog";
import { formatNumber } from "../../lib/format";
import type { LiveState } from "./liveReducer";

// Ce que l'écran dit du module « en cours ». Le serveur n'annonce un module qu'à sa
// FIN : il n'existe donc pas de module « en cours » exact. On montre le premier module
// qui n'est pas encore terminé (ordre d'exécution du catalogue), avec le nombre de
// ceux qui le suivent. C'est exact pour le profil complet, où tous les modules sont
// lancés ; `total` (donné par le serveur) borne le décompte pour un plan plus court.
export type CurrentModule =
  | { kind: "waiting" }
  | { kind: "running"; name: ModuleName; more: number }
  | { kind: "finalizing" }
  | { kind: "none" };

export function currentModule(state: LiveState, catalog: Catalog = STATIC_CATALOG): CurrentModule {
  // Tâche terminée, annulée, échouée ou perdue : plus rien n'est « en cours ».
  if (state.phase !== "connecting" && state.phase !== "running") return { kind: "none" };
  if (state.done === 0 && Object.keys(state.modules).length === 0) return { kind: "waiting" };
  const remaining = catalog.moduleNames.filter((name) => !state.modules[name]);
  const left = Math.min(remaining.length, Math.max(0, state.total - state.done));
  // Tout est terminé mais l'événement final n'est pas encore arrivé (sauvegarde du scan).
  if (left === 0) return { kind: "finalizing" };
  return { kind: "running", name: remaining[0], more: left - 1 };
}

const two = (value: number) => String(value).padStart(2, "0");

// Secondes entières, jamais négatives ni fractionnaires (NaN et infini valent 0).
const wholeSeconds = (seconds: number) => Math.max(0, Math.floor(Number.isFinite(seconds) ? seconds : 0));

// Chronomètre : « 0:07 », « 12:05 », « 1:02:03 ».
export function formatClock(seconds: number): string {
  const total = wholeSeconds(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const rest = total % 60;
  return hours > 0 ? `${hours}:${two(minutes)}:${two(rest)}` : `${minutes}:${two(rest)}`;
}

// Durée ISO 8601 pour l'attribut dateTime d'un <time> : « PT7S », « PT1M5S », « PT1H2M3S ».
export function isoDuration(seconds: number): string {
  const total = wholeSeconds(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const rest = total % 60;
  const parts = [hours ? `${hours}H` : "", minutes ? `${minutes}M` : "", rest || total === 0 ? `${rest}S` : ""];
  return `PT${parts.join("")}`;
}

// Durée d'un module : deux décimales sous 10 s (les modules rapides se comptent en
// centièmes), une au-delà ; « — » quand la valeur n'est pas un nombre.
export function formatModuleDuration(seconds: number, lang: Lang): string {
  if (typeof seconds !== "number" || !Number.isFinite(seconds)) return "—";
  const value = Math.max(0, seconds);
  return `${formatNumber(value, lang, value < 10 ? 2 : 1)} s`;
}
