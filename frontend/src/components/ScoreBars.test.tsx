import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { CriterionScore } from "../api/types";
import { makeScan } from "../test/fixtures";
import { ScoreBars } from "./ScoreBars";

const breakdown = makeScan().security_score.breakdown as Record<string, CriterionScore>;

describe("barres de décomposition du score", () => {
  it("rend une ligne par critère d'un vrai barème, avec sa valeur en attribut HTML", () => {
    const { container } = render(<ScoreBars breakdown={breakdown} />);
    const list = screen.getByRole("list", { name: "Détail du score" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(8);

    // Critères mesurés et comptés : une vraie barre, nommée par son étiquette.
    const headers = screen.getByRole("progressbar", { name: "En-têtes" });
    expect(headers).toHaveAttribute("value", "19");
    expect(headers).toHaveAttribute("max", "25");
    expect(headers).toHaveAttribute("aria-valuetext", "19/25");
    expect(screen.getByRole("progressbar", { name: "TLS" })).toHaveAttribute("value", "20");
    expect(screen.getByRole("progressbar", { name: "CORS" })).toHaveAttribute("value", "10");
    expect(screen.getAllByRole("progressbar")).toHaveLength(6);

    // Plus aucune ligne n'a besoin d'un style ni d'une balise <style>.
    expect(container.querySelector("[style]")).toBeNull();
    expect(container.querySelector("style")).toBeNull();
  });

  it("distingue mesuré, bonus, non mesuré et sans objet par data-kind et par le texte", () => {
    const { container } = render(
      <ScoreBars
        breakdown={{
          ...breakdown,
          email: { score: 0, max: 15, detail: "Cible IP", measured: false, counted: false, applicable: false },
        }}
      />,
    );
    const row = (label: string) => screen.getByText(label).closest("li");
    expect(row("En-têtes")).toHaveAttribute("data-kind", "points");
    expect(row("WAF")).toHaveAttribute("data-kind", "bonus");
    expect(row("Takeover")).toHaveAttribute("data-kind", "notMeasured");
    expect(row("E-mail")).toHaveAttribute("data-kind", "notApplicable");
    expect(within(row("WAF") as HTMLElement).getByText("bonus")).toBeInTheDocument();
    expect(within(row("Takeover") as HTMLElement).getByText("non mesuré")).toBeInTheDocument();
    expect(within(row("E-mail") as HTMLElement).getByText("sans objet")).toBeInTheDocument();

    // Bonus, non mesuré et sans objet : barre vide et cachée aux lecteurs d'écran
    // (zéro se lirait « 0 point »).
    const hidden = container.querySelectorAll("progress[aria-hidden='true']");
    expect(hidden).toHaveLength(3);
    for (const bar of hidden) expect(bar).toHaveAttribute("value", "0");
  });

  it("explications des critères sur demande (showDetails) : sous la barre, en texte, jamais en HTML", () => {
    const { container, rerender } = render(<ScoreBars breakdown={breakdown} />);
    // Par défaut, aucune explication : les barres seules.
    expect(screen.queryByText("4/6 conformes, 1 partiel(s)")).not.toBeInTheDocument();
    rerender(
      <ScoreBars
        showDetails
        breakdown={{
          ...breakdown,
          cors: { score: 10, max: 10, detail: "<img src=x onerror=alert(1)>", measured: true, counted: true, applicable: true },
        }}
      />,
    );
    const headers = screen.getByText("En-têtes").closest("li") as HTMLElement;
    expect(within(headers).getByText("4/6 conformes, 1 partiel(s)")).toBeInTheDocument();
    // Bonus : l'explication dit que le bonus n'est pas obtenu et reste hors barème.
    const waf = screen.getByText("WAF").closest("li") as HTMLElement;
    expect(within(waf).getByText("Aucun WAF détecté, sans pénalité — bonus non obtenu, hors barème")).toBeInTheDocument();
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("ne casse pas sur une clé inconnue, un maximum nul ou une entrée illisible", () => {
    render(
      <ScoreBars
        breakdown={
          {
            inconnu: { score: 3, max: 0, measured: true, counted: true },
            invalide: null,
            "<img src=x>": { score: 5, max: 10, measured: true, counted: true },
          } as unknown as Record<string, CriterionScore>
        }
      />,
    );
    // Clé sans traduction : affichée telle quelle, en texte ; maximum nul : borné à 1.
    expect(screen.getByRole("progressbar", { name: "inconnu" })).toHaveAttribute("max", "1");
    expect(screen.getByRole("progressbar", { name: "inconnu" })).toHaveAttribute("value", "1");
    expect(screen.getByText("<img src=x>")).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getAllByRole("listitem")).toHaveLength(2);
  });

  it("nomme le critère WHOIS en toutes lettres, pas par sa clé technique", () => {
    render(<ScoreBars breakdown={{ whois: { score: 0, max: 5, measured: true, counted: false, applicable: false } } as unknown as Record<string, CriterionScore>} />);
    expect(screen.getByText("WHOIS")).toBeInTheDocument();
    expect(screen.queryByText("whois")).toBeNull();
  });

  it("n'affiche rien sans critère", () => {
    const { container } = render(<ScoreBars breakdown={{}} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("aucune animation d'entrée : les barres ont d'emblée leur valeur", () => {
    render(<ScoreBars breakdown={breakdown} />);
    expect(screen.getByRole("progressbar", { name: "En-têtes" })).toHaveAttribute("value", "19");
    expect(screen.getByRole("progressbar", { name: "TLS" })).toHaveAttribute("value", "20");
  });
});
