import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderWithProviders } from "../test/render";
import { CategoryBadge } from "./CategoryBadge";
import { Sparkline } from "./Sparkline";
import { GlossaryText } from "./Term";

describe("Sparkline", () => {
  it("trace une courbe avec au moins deux scores mesurés", () => {
    const { container } = render(<Sparkline values={[50, null, 70, 90]} label="Tendance" />);
    expect(screen.getByRole("img", { name: "Tendance" })).toBeInTheDocument();
    const points = container.querySelector("polyline")?.getAttribute("points")?.split(" ") ?? [];
    expect(points).toHaveLength(3);
    // Un score plus haut est tracé plus haut (y plus petit).
    const ys = points.map((point) => Number(point.split(",")[1]));
    expect(ys[0]).toBeGreaterThan(ys[2]);
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("ne trace rien avec moins de deux points", () => {
    render(<Sparkline values={[null, 80]} label="Tendance" />);
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });
});

describe("CategoryBadge", () => {
  it.each([
    ["passif", "Passif"],
    ["actif", "Actif"],
    ["cle_api", "Clé d'API"],
    ["sensible", "Sensible"],
    ["inconnue", "Passif"],
  ])("%s : %s", (category, label) => {
    renderWithProviders(<CategoryBadge category={category} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });
});

describe("GlossaryText", () => {
  it("garde le texte et ajoute une infobulle aux sigles connus", () => {
    renderWithProviders(<GlossaryText text="Activez HSTS et la CSP." />);
    expect(screen.getAllByRole("tooltip")).toHaveLength(2);
  });
});
