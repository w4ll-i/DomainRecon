import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { tabId, tabPanelId } from "../lib/tabs";
import { CountBadge } from "./CountBadge";
import { SectionTitle } from "./SectionTitle";
import { StatCard } from "./StatCard";
import { type TabItem, Tabs } from "./Tabs";

describe("carte de chiffre clé", () => {
  it("grande carte : étiquette, valeur et ton", () => {
    const { container } = render(
      <StatCard variant="hero" label="Sous-domaines" value="12" icon={<svg data-testid="icon" />} tone="critical" />,
    );
    const card = screen.getByText("Sous-domaines").closest("[data-variant]");
    expect(card).toHaveAttribute("data-variant", "hero");
    expect(card).toHaveAttribute("data-tone", "critical");
    expect(screen.getByText("12")).toBeInTheDocument();
    // L'icône est décorative : le texte dit déjà l'état.
    expect(screen.getByTestId("icon").parentElement).toHaveAttribute("aria-hidden", "true");
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("petite carte : ton neutre par défaut, classe fournie, sans icône", () => {
    const { container } = render(<StatCard variant="secondary" label="Ports" value={3} className="extra" />);
    const card = screen.getByText("Ports").closest("[data-variant]");
    expect(card).toHaveAttribute("data-variant", "secondary");
    expect(card).toHaveAttribute("data-tone", "neutral");
    expect(card).toHaveClass("extra");
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(container.querySelector("[aria-hidden]")).toBeNull();
  });

  it("affiche une valeur riche telle quelle", () => {
    render(<StatCard variant="secondary" label="Durée" value={<strong>23,4 s</strong>} />);
    expect(screen.getByText("23,4 s").tagName).toBe("STRONG");
  });
});

describe("titre de section", () => {
  it("étiquette puis titre de niveau 2 portant l'identifiant", () => {
    render(<SectionTitle label="Reconnaissance · OSINT" title="Analyse de domaine" id="analyse" />);
    const heading = screen.getByRole("heading", { level: 2, name: "Analyse de domaine" });
    expect(heading).toHaveAttribute("id", "analyse");
    expect(screen.getByText("Reconnaissance · OSINT")).toBeInTheDocument();
    // L'étiquette précède le titre dans le document.
    expect(screen.getByText("Reconnaissance · OSINT").compareDocumentPosition(heading) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("titre de niveau 3 pour une sous-section, et nom d'une région par aria-labelledby", () => {
    render(
      <section aria-labelledby="sous">
        <SectionTitle label="Famille" title="Réseau" id="sous" level={3} />
      </section>,
    );
    expect(screen.getByRole("heading", { level: 3, name: "Réseau" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Réseau" })).toBeInTheDocument();
  });

  it("affiche du texte brut, jamais du HTML", () => {
    const { container } = render(<SectionTitle label="<b>x</b>" title="<img src=x onerror=alert(1)>" />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  });

  it("titre d'écran (niveau 1) et taille « héros » : attributs lus par le CSS", () => {
    render(<SectionTitle label="Reconnaissance · OSINT" title="Analyse de domaine" level={1} size="hero" align="center" />);
    const heading = screen.getByRole("heading", { level: 1, name: "Analyse de domaine" });
    expect(heading).toHaveAttribute("data-size", "hero");
    expect(heading).toHaveAttribute("data-level", "1");
    expect(heading.parentElement).toHaveAttribute("data-align", "center");
  });

  it("taille « section » par défaut, alignement au début", () => {
    render(<SectionTitle label="Famille" title="Réseau" />);
    const heading = screen.getByRole("heading", { level: 2, name: "Réseau" });
    expect(heading).toHaveAttribute("data-size", "section");
    expect(heading.parentElement).toHaveAttribute("data-align", "start");
  });

  it("mot d'accent : la dernière occurrence dans le titre, le nom accessible reste le titre entier", () => {
    render(<SectionTitle label="Reconnaissance · OSINT" title="Analyse de domaine" accent="domaine" level={1} size="hero" />);
    const heading = screen.getByRole("heading", { level: 1, name: "Analyse de domaine" });
    expect(screen.getByText("domaine")).toBeInTheDocument();
    expect(screen.getByText("domaine").tagName).toBe("SPAN");
    expect(heading).toHaveTextContent(/^Analyse de domaine$/);
    // Dernière occurrence : « domaine » dans « Analyse de domaine de domaine » peint le second.
    const { container } = render(<SectionTitle label="x" title="domaine de domaine" accent="domaine" />);
    expect(container.querySelector("h2")?.firstChild?.textContent).toBe("domaine de ");
  });

  it("mot d'accent absent du titre : le titre s'affiche tel quel", () => {
    render(<SectionTitle label="Famille" title="Réseau" accent="introuvable" />);
    const heading = screen.getByRole("heading", { name: "Réseau" });
    expect(heading.querySelector("span")).toBeNull();
  });

  it("élément après le titre (pastille de compte) : sur sa ligne, hors du titre dont le nom reste le texte", () => {
    render(<SectionTitle label="Priorités" title="À corriger" id="constats" after={<CountBadge count={12} tone="critical" />} />);
    const heading = screen.getByRole("heading", { level: 2, name: "À corriger" });
    const badge = screen.getByText("12");
    expect(heading).not.toContainElement(badge);
    expect(heading.nextElementSibling).toBe(badge);
    expect(badge).toHaveAttribute("data-tone", "critical");
    // Sans élément : pas de ligne de plus.
    const { container } = render(<SectionTitle label="Famille" title="Réseau" />);
    expect(container.querySelector("h2")?.parentElement).toHaveAttribute("data-align", "start");
  });

  it("sans titre : l'étiquette seule, qui nomme une liste, sans niveau de titre", () => {
    const { container } = render(
      <>
        <SectionTitle label="Navigation" id="menu" />
        <ul aria-labelledby="menu">
          <li>Historique</li>
        </ul>
      </>,
    );
    expect(screen.queryByRole("heading")).not.toBeInTheDocument();
    expect(screen.getByText("Navigation")).toHaveAttribute("id", "menu");
    expect(screen.getByRole("list", { name: "Navigation" })).toBeInTheDocument();
    expect(container.querySelector("[style]")).toBeNull();
  });
});

describe("pastille de compte", () => {
  it("affiche le compte avec le ton demandé, neutre par défaut", () => {
    render(
      <>
        <CountBadge count={3} tone="critical" />
        <CountBadge count={7} />
      </>,
    );
    expect(screen.getByText("3")).toHaveAttribute("data-tone", "critical");
    expect(screen.getByText("7")).toHaveAttribute("data-tone", "neutral");
  });

  it("plafonne les grands comptes et assainit les valeurs aberrantes", () => {
    render(
      <>
        <CountBadge count={150} />
        <CountBadge count={12} max={9} />
        <CountBadge count={99} />
        <CountBadge count={-4} />
        <CountBadge count={Number.NaN} />
        <CountBadge count={2.9} />
      </>,
    );
    expect(screen.getByText("99+")).toBeInTheDocument();
    expect(screen.getByText("9+")).toBeInTheDocument();
    expect(screen.getByText("99")).toBeInTheDocument();
    expect(screen.getAllByText("0")).toHaveLength(2);
    expect(screen.getByText("2")).toBeInTheDocument();
  });
});

const TABS: TabItem[] = [
  { key: "dns", label: "DNS" },
  { key: "subs", label: "Sous-domaines", count: 12 },
  { key: "takeover", label: "Takeover", count: 2, tone: "critical" },
];

function Harness({ initial = "dns", onChange }: { initial?: string; onChange?: (key: string) => void }) {
  const [key, setKey] = useState(initial);
  return (
    <Tabs
      tabs={TABS}
      activeKey={key}
      label="Modules"
      idPrefix="mod"
      onChange={(next) => {
        onChange?.(next);
        setKey(next);
      }}
    />
  );
}

describe("onglets", () => {
  it("expose tablist, onglets, aria-selected et le lien vers le panneau", () => {
    render(<Harness />);
    const list = screen.getByRole("tablist", { name: "Modules" });
    const tabs = within(list).getAllByRole("tab");
    expect(tabs).toHaveLength(3);
    expect(tabs.map((tab) => tab.getAttribute("aria-selected"))).toEqual(["true", "false", "false"]);
    // Identifiants prévus pour le panneau de l'appelant (lib/tabs.ts).
    expect(tabs[1]).toHaveAttribute("id", tabId("mod", "subs"));
    expect(tabs[1]).toHaveAttribute("aria-controls", tabPanelId("mod"));
    // Un seul onglet à la tabulation : tabindex itinérant.
    expect(tabs.map((tab) => tab.tabIndex)).toEqual([0, -1, -1]);
  });

  it("affiche le compte de chaque onglet dans une pastille, avec son ton", () => {
    render(<Harness />);
    // Le nom accessible se lit « libellé, compte ».
    const subs = screen.getByRole("tab", { name: "Sous-domaines 12" });
    expect(within(subs).getByText("12")).toHaveAttribute("data-tone", "neutral");
    expect(within(screen.getByRole("tab", { name: "Takeover 2" })).getByText("2")).toHaveAttribute("data-tone", "critical");
    // Sans compte, pas de pastille.
    expect(within(screen.getByRole("tab", { name: "DNS" })).queryByText(/\d/)).toBeNull();
  });

  it("change d'onglet au clic", async () => {
    const onChange = vi.fn();
    render(<Harness onChange={onChange} />);
    await userEvent.click(screen.getByRole("tab", { name: /^Takeover/ }));
    expect(onChange).toHaveBeenCalledExactlyOnceWith("takeover");
    expect(screen.getByRole("tab", { name: /^Takeover/ })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: "DNS" })).toHaveAttribute("aria-selected", "false");
  });

  it("se parcourt aux flèches, en boucle, avec Début et Fin ; le focus suit la sélection", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Harness onChange={onChange} />);
    const [dns, subs, takeover] = screen.getAllByRole("tab");

    await user.tab();
    expect(dns).toHaveFocus();
    await user.keyboard("{ArrowRight}");
    expect(subs).toHaveFocus();
    expect(subs).toHaveAttribute("aria-selected", "true");
    expect(subs.tabIndex).toBe(0);
    expect(dns.tabIndex).toBe(-1);

    await user.keyboard("{ArrowRight}");
    expect(takeover).toHaveFocus();
    // Après le dernier, retour au premier.
    await user.keyboard("{ArrowRight}");
    expect(dns).toHaveFocus();
    // Avant le premier, le dernier.
    await user.keyboard("{ArrowLeft}");
    expect(takeover).toHaveFocus();
    await user.keyboard("{Home}");
    expect(dns).toHaveFocus();
    expect(dns).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{End}");
    expect(takeover).toHaveFocus();
    expect(onChange.mock.calls.map(([key]) => key)).toEqual(["subs", "takeover", "dns", "takeover", "dns", "takeover"]);

    // Une autre touche ne fait rien.
    await user.keyboard("a");
    expect(takeover).toHaveFocus();
    expect(onChange).toHaveBeenCalledTimes(6);
  });

  it("garde le premier onglet atteignable quand la clé active est inconnue", () => {
    render(<Tabs tabs={TABS} activeKey="absent" onChange={() => {}} />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((tab) => tab.getAttribute("aria-selected"))).toEqual(["false", "false", "false"]);
    expect(tabs.map((tab) => tab.tabIndex)).toEqual([0, -1, -1]);
  });

  it("génère ses identifiants sans préfixe, sans style en ligne, et accepte une liste vide", () => {
    const { container, rerender } = render(<Tabs tabs={TABS} activeKey="dns" onChange={() => {}} />);
    const ids = screen.getAllByRole("tab").map((tab) => tab.id);
    expect(new Set(ids).size).toBe(3);
    expect(container.querySelector("[style]")).toBeNull();
    rerender(<Tabs tabs={[]} activeKey="" onChange={() => {}} />);
    expect(screen.getByRole("tablist")).toBeEmptyDOMElement();
  });
});
