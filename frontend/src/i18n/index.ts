import i18n from "i18next";
import { initReactI18next, useTranslation } from "react-i18next";
import { STORAGE_KEYS, readLocal, writeLocal } from "../lib/storage";
import en from "./en.json";
import fr from "./fr.json";

export type Lang = "fr" | "en";

export const SUPPORTED_LANGS: readonly Lang[] = ["fr", "en"];

// Choix mémorisé, sinon langue du navigateur : français si elle commence par
// « fr », anglais sinon.
export function detectLang(stored: string | null, navigatorLang: string | undefined): Lang {
  if (stored === "fr" || stored === "en") return stored;
  return (navigatorLang ?? "").toLowerCase().startsWith("fr") ? "fr" : "en";
}

void i18n.use(initReactI18next).init({
  resources: { fr: { translation: fr }, en: { translation: en } },
  lng: detectLang(readLocal(STORAGE_KEYS.lang), typeof navigator === "undefined" ? undefined : navigator.language),
  fallbackLng: "fr",
  supportedLngs: ["fr", "en"],
  // React échappe déjà tout texte rendu.
  interpolation: { escapeValue: false },
});

export function currentLang(): Lang {
  return i18n.language === "en" ? "en" : "fr";
}

if (typeof document !== "undefined") document.documentElement.lang = currentLang();

export async function setLang(lang: Lang): Promise<void> {
  writeLocal(STORAGE_KEYS.lang, lang);
  document.documentElement.lang = lang;
  await i18n.changeLanguage(lang);
}

// Langue courante, avec nouveau rendu au changement de langue.
export function useLang(): Lang {
  const { i18n: instance } = useTranslation();
  return instance.language === "en" ? "en" : "fr";
}

export default i18n;
