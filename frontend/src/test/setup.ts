import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach } from "vitest";
import i18n from "../i18n";
import { markOnboardingSeen } from "../features/onboarding/onboardingEvents";

beforeEach(async () => {
  window.localStorage.clear();
  window.sessionStorage.clear();
  // L'accueil du premier lancement ne gêne pas les autres écrans ; il a ses propres tests.
  markOnboardingSeen();
  await i18n.changeLanguage("fr");
  document.documentElement.lang = "fr";
  // Thème posé par un test précédent (bascule du menu) : retour au défaut sombre.
  document.documentElement.removeAttribute("data-theme");
});

// Sans `globals: true`, Testing Library ne démonte pas seul entre deux tests.
afterEach(() => {
  cleanup();
});
