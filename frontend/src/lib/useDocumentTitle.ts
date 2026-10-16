import { useEffect } from "react";

// Titre de l'onglet (et de la fenêtre pywebview) par écran.
export function useDocumentTitle(title: string | null): void {
  useEffect(() => {
    document.title = title ? `${title} · DomainRecon` : "DomainRecon";
  }, [title]);
}
