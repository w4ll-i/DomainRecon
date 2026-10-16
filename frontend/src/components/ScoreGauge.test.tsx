import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ScoreGauge } from "./ScoreGauge";

describe("note en grand", () => {
  it("note attribuée : lettre typographique, score et couleur par attribut", () => {
    const { container } = render(<ScoreGauge grade="B" score={78} coverage={90} indicative={false} />);
    const gauge = screen.getByRole("img", { name: "Note B, score 78 sur 100, couverture 90 %" });
    expect(gauge).toHaveAttribute("data-state", "score");
    expect(gauge).toHaveAttribute("data-grade", "B");
    expect(gauge).toHaveTextContent("B");
    expect(gauge).toHaveTextContent("78/100");
    // Typographique : aucun dessin (anneau SVG), aucun style en ligne (CSP stricte).
    expect(container.querySelector("svg")).toBeNull();
    expect(container.querySelector("[style]")).toBeNull();
  });

  it.each(["A", "C", "D", "F"])("la note %s se lit en toutes lettres et sur l'attribut de couleur", (grade) => {
    render(<ScoreGauge grade={grade} score={50} coverage={null} indicative={false} />);
    // Sans couverture, le libellé ARIA ne la mentionne pas.
    const gauge = screen.getByRole("img", { name: `Note ${grade}, score 50 sur 100` });
    expect(gauge).toHaveAttribute("data-grade", grade);
    expect(gauge).toHaveTextContent(grade);
  });

  it("borne le score entre 0 et 100", () => {
    const { rerender } = render(<ScoreGauge grade="A" score={130} coverage={null} indicative={false} />);
    expect(screen.getByRole("img")).toHaveTextContent("100/100");
    rerender(<ScoreGauge grade="F" score={-5} coverage={null} indicative={false} />);
    expect(screen.getByRole("img")).toHaveTextContent("0/100");
  });

  it("sans note : « N/A » en grand, ni score ni couleur de note", () => {
    render(<ScoreGauge grade="N/A" score={null} coverage={0} indicative={false} />);
    const gauge = screen.getByRole("img", { name: "Note N/A, couverture 0 %" });
    expect(gauge).toHaveAttribute("data-state", "na");
    expect(gauge).toHaveAttribute("data-grade", "NA");
    expect(gauge).toHaveTextContent("N/A");
    expect(gauge).not.toHaveTextContent("/100");
  });

  it("score indicatif : jamais de note, même reçue ; la mention « indicatif » est écrite", () => {
    render(<ScoreGauge grade="A" score={50} coverage={30} indicative />);
    const gauge = screen.getByRole("img", {
      name: "Score indicatif 50 sur 100, sans note (couverture insuffisante), couverture 30 %",
    });
    expect(gauge).toHaveAttribute("data-state", "indicative");
    expect(gauge).toHaveAttribute("data-grade", "NA");
    expect(gauge).toHaveTextContent("N/A");
    expect(gauge).toHaveTextContent("indicatif");
  });

  it("un score sans note valide s'affiche « N/A » plutôt qu'une lettre inventée", () => {
    render(<ScoreGauge grade="Z" score={40} coverage={null} indicative={false} />);
    expect(screen.getByRole("img")).toHaveAttribute("data-state", "na");
  });
});
