import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type TabItem, Tabs } from "./Tabs";

// Rangée qui déborde : jsdom ne calcule aucune mise en page, les dimensions sont simulées.
// Chaque onglet mesure 280 px et commence tous les 300 px ; la rangée en montre 500.
const TABS: TabItem[] = [
  { key: "headers", label: "En-têtes de sécurité", count: 3, tone: "critical" },
  { key: "cookies", label: "Cookies", count: 1, tone: "warning" },
  { key: "hsts", label: "HSTS et préchargement" },
];

const STEP = 300;
const WIDTH = 280;
const VIEW = 500;
const CONTENT = STEP * TABS.length;

const indexOf = (element: HTMLElement) => TABS.findIndex((tab) => element.id.endsWith(`-tab-${tab.key}`));

function Harness({ initial, onChange }: { initial: string; onChange?: (key: string) => void }) {
  const [key, setKey] = useState(initial);
  return (
    <Tabs
      tabs={TABS}
      activeKey={key}
      label="Modules de la famille Web"
      idPrefix="web"
      onChange={(next) => {
        onChange?.(next);
        setKey(next);
      }}
    />
  );
}

describe("onglets qui débordent", () => {
  const scrollTo = vi.fn();

  beforeEach(() => {
    scrollTo.mockReset();
    vi.spyOn(HTMLElement.prototype, "scrollWidth", "get").mockImplementation(function (this: HTMLElement) {
      return this.getAttribute("role") === "tablist" ? CONTENT : 0;
    });
    vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockImplementation(function (this: HTMLElement) {
      return this.getAttribute("role") === "tablist" ? VIEW : 0;
    });
    vi.spyOn(HTMLElement.prototype, "offsetLeft", "get").mockImplementation(function (this: HTMLElement) {
      return this.getAttribute("role") === "tab" ? indexOf(this) * STEP : 0;
    });
    vi.spyOn(HTMLElement.prototype, "offsetWidth", "get").mockImplementation(function (this: HTMLElement) {
      return this.getAttribute("role") === "tab" ? WIDTH : 0;
    });
    Object.defineProperty(HTMLElement.prototype, "scrollTo", { configurable: true, value: scrollTo });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete (HTMLElement.prototype as { scrollTo?: unknown }).scrollTo;
  });

  it("garde les noms complets, sans troncature, et ajoute boutons de défilement et menu « Tous »", () => {
    const { container } = render(<Harness initial="headers" />);
    const root = container.firstElementChild as HTMLElement;
    expect(root).toHaveAttribute("data-overflow", "true");
    // Au début de la rangée : rien de caché à gauche, des onglets à droite.
    expect(root).not.toHaveAttribute("data-start");
    expect(root).toHaveAttribute("data-end", "true");
    expect(screen.getByRole("button", { name: "Onglets précédents" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Onglets suivants" })).toBeEnabled();
    // Les boutons de bord restent hors de la tabulation : les flèches parcourent déjà les onglets.
    expect(screen.getByRole("button", { name: "Onglets suivants" }).tabIndex).toBe(-1);
    // Libellé entier dans le nom de chaque onglet.
    expect(screen.getByRole("tab", { name: "HSTS et préchargement" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Tous les onglets 3" })).toHaveAttribute("aria-expanded", "false");
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("le bouton suivant avance d'environ une largeur de rangée", async () => {
    render(<Harness initial="headers" />);
    scrollTo.mockClear();
    await userEvent.click(screen.getByRole("button", { name: "Onglets suivants" }));
    expect(scrollTo).toHaveBeenCalledExactlyOnceWith({ left: VIEW * 0.8, behavior: "smooth" });
  });

  it("ramène l'onglet actif d'un lien profond dans la partie visible, sans animation", () => {
    render(<Harness initial="hsts" />);
    // Dernier onglet : 600 à 880 px, plus la marge du fondu, borné à la fin de la rangée.
    expect(scrollTo).toHaveBeenCalledWith({ left: CONTENT - VIEW, behavior: "auto" });
  });

  it("menu « Tous » : liste complète cochée, flèches, choix qui active l'onglet et lui rend le focus", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Harness initial="cookies" onChange={onChange} />);
    const trigger = screen.getByRole("button", { name: "Tous les onglets 3" });
    await user.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    const menu = screen.getByRole("menu", { name: "Tous les onglets : Modules de la famille Web" });
    expect(trigger).toHaveAttribute("aria-controls", menu.id);
    const items = within(menu).getAllByRole("menuitemradio");
    expect(items.map((item) => item.textContent)).toEqual(["En-têtes de sécurité 3", "Cookies 1", "HSTS et préchargement"]);
    expect(items.map((item) => item.getAttribute("aria-checked"))).toEqual(["false", "true", "false"]);
    // Le focus se pose sur l'onglet affiché, les flèches parcourent la liste en boucle.
    expect(items[1]).toHaveFocus();
    await user.keyboard("{ArrowDown}");
    expect(items[2]).toHaveFocus();
    await user.keyboard("{ArrowDown}");
    expect(items[0]).toHaveFocus();
    await user.keyboard("{End}");
    expect(items[2]).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(onChange).toHaveBeenCalledExactlyOnceWith("hsts");
    expect(screen.queryByRole("menu")).toBeNull();
    const hsts = screen.getByRole("tab", { name: "HSTS et préchargement" });
    expect(hsts).toHaveAttribute("aria-selected", "true");
    expect(hsts).toHaveFocus();
  });

  it("menu « Tous » : Échap le referme et rend le focus au bouton, un clic ailleurs aussi", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Harness initial="headers" onChange={onChange} />);
    const trigger = screen.getByRole("button", { name: "Tous les onglets 3" });
    trigger.focus();
    await user.keyboard("{ArrowDown}");
    expect(screen.getAllByRole("menuitemradio")[0]).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).toBeNull();
    expect(trigger).toHaveFocus();
    await user.click(trigger);
    expect(screen.getByRole("menu")).toBeInTheDocument();
    await user.click(document.body);
    expect(screen.queryByRole("menu")).toBeNull();
    expect(onChange).not.toHaveBeenCalled();
  });
});

describe("onglets qui tiennent", () => {
  it("ni bouton de défilement, ni menu, ni fondu", () => {
    const { container } = render(<Harness initial="headers" />);
    const root = container.firstElementChild as HTMLElement;
    expect(root).not.toHaveAttribute("data-overflow");
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.getAllByRole("tab")).toHaveLength(3);
  });
});
