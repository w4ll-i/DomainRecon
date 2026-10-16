import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { HOSTILE, makeScan } from "../test/fixtures";
import { GradeBadge } from "./GradeBadge";
import { KvList } from "./KvList";
import { ModuleCard } from "./ModuleCard";
import { ErrorState, Loading } from "./PageState";
import { ModuleStatusPill, ScanStatusPill, SeverityBadge } from "./Pills";

describe("note", () => {
  it("expose la note avec un libellé ARIA et sa couleur par attribut", () => {
    render(<GradeBadge grade="B" size="xl" label="Note globale : B" />);
    const badge = screen.getByRole("img", { name: "Note globale : B" });
    expect(badge).toHaveTextContent("B");
    expect(badge).toHaveAttribute("data-grade", "B");
  });

  it("affiche N/A pour une note absente ou inconnue", () => {
    render(<GradeBadge grade="Z" />);
    expect(screen.getByRole("img", { name: "Note N/A" })).toHaveAttribute("data-grade", "NA");
  });
});

describe("pastilles", () => {
  it("traduit les statuts de scan, de module et la gravité", () => {
    render(
      <>
        <ScanStatusPill status="partial" />
        <ScanStatusPill status="bizarre" />
        <ModuleStatusPill status="timeout" />
        <ModuleStatusPill status="running" />
        <SeverityBadge severity="critical" />
      </>,
    );
    expect(screen.getByText("Partiel")).toBeInTheDocument();
    expect(screen.getByText("Inconnu")).toBeInTheDocument();
    expect(screen.getByText("Non mesuré (délai dépassé)")).toBeInTheDocument();
    expect(screen.getByText("En cours")).toBeInTheDocument();
    expect(screen.getByText("Critique")).toBeInTheDocument();
  });
});

describe("carte de module", () => {
  it("affiche le contenu d'un module mesuré", () => {
    render(
      <ModuleCard scan={makeScan()} module="cors">
        <p>Détails CORS</p>
      </ModuleCard>,
    );
    expect(screen.getByRole("heading", { name: "CORS" })).toBeInTheDocument();
    expect(screen.getByText("Mesuré")).toBeInTheDocument();
    expect(screen.getByText("Détails CORS")).toBeInTheDocument();
  });

  it("n'affiche jamais « rien trouvé » pour un module en échec : statut et raison", () => {
    const scan = makeScan({
      module_status: { ...makeScan().module_status, cors: { status: "failed", error: "Site injoignable" } },
    });
    render(
      <ModuleCard scan={scan} module="cors">
        <p>CORS non activé</p>
      </ModuleCard>,
    );
    expect(screen.getAllByText("Non mesuré (échec du module)")).toHaveLength(2);
    expect(screen.getByText("Site injoignable")).toBeInTheDocument();
    expect(screen.queryByText("CORS non activé")).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: "CORS" })).toHaveAttribute("data-status", "failed");
  });

  it("distingue « sans objet »", () => {
    render(<ModuleCard scan={makeScan()} module="screenshot" />);
    expect(screen.getAllByText("Sans objet")).toHaveLength(2);
    expect(screen.getByText("Ce module est sans objet pour cette cible.")).toBeInTheDocument();
  });

  it("peut garder un contenu partiel sous l'avertissement", () => {
    const scan = makeScan({
      module_status: { ...makeScan().module_status, redirect_chain: { status: "failed", error: "HTTPS injoignable" } },
    });
    render(
      <ModuleCard scan={scan} module="redirect_chain" showChildrenWhenUnavailable>
        <p>Chaîne partielle</p>
      </ModuleCard>,
    );
    expect(screen.getByText("Chaîne partielle")).toBeInTheDocument();
  });
});

describe("listes et états", () => {
  it("affiche N/A pour une valeur vide et du texte brut pour une valeur hostile", () => {
    render(
      <KvList
        rows={[
          { label: "Registrar", value: HOSTILE },
          { label: "DNSSEC", value: null },
          { label: "E-mails", value: "" },
        ]}
      />,
    );
    expect(screen.getByText(HOSTILE)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getAllByText("N/A")).toHaveLength(2);
  });

  it("affiche un booléen mesuré « Oui » ou « Non », jamais N/A", () => {
    render(
      <KvList
        rows={[
          { label: "DNSSEC signé", value: false },
          { label: "Anycast", value: true },
          { label: "Registrant", value: undefined },
        ]}
      />,
    );
    expect(screen.getByText("DNSSEC signé").nextElementSibling).toHaveTextContent("Non");
    expect(screen.getByText("Anycast").nextElementSibling).toHaveTextContent("Oui");
    expect(screen.getAllByText("N/A")).toHaveLength(1);
  });

  it("annonce le chargement et propose de réessayer après une erreur", async () => {
    const retry = vi.fn();
    render(
      <>
        <Loading />
        <ErrorState detail="Serveur injoignable" onRetry={retry} />
      </>,
    );
    expect(screen.getByRole("status")).toHaveTextContent("Chargement…");
    expect(screen.getByRole("alert")).toHaveTextContent("Serveur injoignable");
    await userEvent.click(screen.getByRole("button", { name: "Réessayer" }));
    expect(retry).toHaveBeenCalledOnce();
  });
});
