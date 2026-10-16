import { ModuleCard } from "../../components/ModuleCard";
import { useCatalog } from "../../api/queries";
import type { FamilyViewProps } from "./types";

// Repli de l'écran d'une famille (les onglets sont dans tabs.ts) : une carte honnête
// (statut, raison) par module de la famille, pour un module qui n'aurait pas encore
// d'onglet.
export function GenericFamilyView({ scan, family }: FamilyViewProps) {
  const catalog = useCatalog();
  return (
    <>
      {catalog.modules(family).map((module) => (
        <ModuleCard key={module} scan={scan} module={module} />
      ))}
    </>
  );
}
