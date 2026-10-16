import { readLocal, STORAGE_KEYS, writeLocal } from "../../lib/storage";

// Événement qui relance la visite guidée (page Aide, palette de commandes).
export const OPEN_ONBOARDING_EVENT = "domainrecon:onboarding";

export const startGuidedTour = (): void => {
  window.dispatchEvent(new Event(OPEN_ONBOARDING_EVENT));
};

// Repli en mémoire quand le stockage du navigateur refuse l'écriture (navigation privée,
// données de site bloquées) : la visite ne se propose qu'au premier affichage de la session,
// elle ne revient pas à chaque remontage de la coquille.
let seenInMemory = false;

// La visite n'est proposée qu'une fois : le navigateur retient qu'elle a été faite ou écartée.
export const onboardingSeen = (): boolean => seenInMemory || readLocal(STORAGE_KEYS.onboarded) === "1";

export function markOnboardingSeen(): void {
  writeLocal(STORAGE_KEYS.onboarded, "1");
  if (readLocal(STORAGE_KEYS.onboarded) !== "1") seenInMemory = true;
}

// Tests : oublie le repli en mémoire (nouvelle session simulée).
export function resetOnboardingMemory(): void {
  seenInMemory = false;
}
