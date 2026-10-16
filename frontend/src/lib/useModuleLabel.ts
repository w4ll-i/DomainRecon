import { useTranslation } from "react-i18next";
import { useCatalog } from "../api/queries";
import { moduleLabel } from "./catalog";

// Fonction de libellé d'un module (voir moduleLabel) pour les composants.
export function useModuleLabel(): (name: string) => string {
  const { t } = useTranslation();
  const catalog = useCatalog();
  return (name) => moduleLabel(t, catalog, name);
}
