import type { FamilyState } from "../api/types";

// Tonalités visuelles (attribut data-tone) : la couleur n'est jamais le seul
// indice, un texte ou une icône l'accompagne toujours.
export type Tone = "ok" | "warning" | "critical" | "info" | "neutral" | "na" | "accent";

const FAMILY_STATE_TONES: Record<FamilyState, Tone> = {
  ok: "ok",
  warning: "warning",
  critical: "critical",
  unmeasured: "na",
  skipped: "neutral",
  info: "info",
};

export function familyStateTone(state: FamilyState | undefined): Tone {
  return state ? FAMILY_STATE_TONES[state] : "na";
}
