import { act, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useLocation } from "react-router";
import { CommandPalette } from "../../app/CommandPalette";
import { setLang } from "../../i18n";
import { mockFetch } from "../../test/fetchMock";
import { makeSummary } from "../../test/fixtures";
import { renderWithProviders } from "../../test/render";
import { Onboarding } from "./Onboarding";
import { markOnboardingSeen, onboardingSeen, resetOnboardingMemory, startGuidedTour } from "./onboardingEvents";

const KEY = "domainrecon.onboarded";

// Coquille factice : les points d'ancrage de la visite, comme dans l'application ; ceux du
// résultat n'existent que sur /scans/…, ceux qu'on retire (`without`) manquent.
function FakeShell({ without = [], waitMs = 0 }: { without?: string[]; waitMs?: number }) {
  const { pathname } = useLocation();
  const anchor = (name: string) => (without.includes(name) ? undefined : name);
  return (
    <>
      <button type="button" data-tour={anchor("palette")}>
        Rechercher
      </button>
      <button type="button" onClick={startGuidedTour}>
        Relancer
      </button>
      <nav data-tour={anchor("nav")}>
        <a href="/settings" data-tour={anchor("nav-settings")}>
          Réglages
        </a>
        <a href="/help" data-tour={anchor("nav-help")}>
          Aide
        </a>
      </nav>
      {pathname === "/" && (
        <>
          <div data-tour={anchor("domain")}>
            <input aria-label="Domaine" />
          </div>
          <div data-tour={anchor("profiles")}>Profils</div>
        </>
      )}
      {pathname.startsWith("/scans/") && (
        <>
          <div data-tour="result-score">Note</div>
          <ul>
            <li data-tour="result-finding">Constat</li>
          </ul>
          <ul>
            <li data-tour="result-family">Famille</li>
          </ul>
          <div data-tour="result-export">Exporter</div>
        </>
      )}
      <Onboarding waitMs={waitMs} />
    </>
  );
}

const bubble = () => screen.getByRole("dialog");
const title = () => within(bubble()).getByRole("heading", { level: 2 }).textContent;

beforeEach(() => {
  mockFetch({ "/api/history": { total: 0, scans: [] } });
});

afterEach(() => {
  resetOnboardingMemory();
  vi.restoreAllMocks();
});

describe("accueil du premier lancement", () => {
  it("s'affiche sans indicateur « visite faite » : outil, usage autorisé, deux choix", () => {
    window.localStorage.removeItem(KEY);
    renderWithProviders(<FakeShell />);
    const dialog = screen.getByRole("dialog", { name: "Bienvenue dans DomainRecon" });
    expect(within(dialog).getByText(/audite la sécurité publique de vos propres domaines/)).toBeInTheDocument();
    expect(within(dialog).getByText(/Usage autorisé uniquement/)).toBeInTheDocument();
    expect(within(dialog).getByText(/depuis l'Aide ou la palette de commandes/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Commencer la visite" })).toHaveFocus();
    expect(within(dialog).getByRole("button", { name: "Plus tard" })).toBeInTheDocument();
  });

  it("ne s'affiche pas quand la visite est déjà faite", () => {
    renderWithProviders(<FakeShell />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("« Plus tard » et Échap l'écartent et le retiennent", async () => {
    window.localStorage.removeItem(KEY);
    const { user, unmount } = renderWithProviders(<FakeShell />);
    await user.click(screen.getByRole("button", { name: "Plus tard" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(window.localStorage.getItem(KEY)).toBe("1");
    unmount();

    window.localStorage.removeItem(KEY);
    const second = renderWithProviders(<FakeShell />);
    expect(screen.getByRole("dialog", { name: "Bienvenue dans DomainRecon" })).toBeInTheDocument();
    await second.user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(onboardingSeen()).toBe(true);
  });

  it("stockage indisponible : la visite ne se propose qu'au premier affichage de la session", async () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("bloqué");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("bloqué");
    });
    const { user, unmount } = renderWithProviders(<FakeShell />);
    await user.click(screen.getByRole("button", { name: "Plus tard" }));
    expect(onboardingSeen()).toBe(true);
    unmount();
    // Coquille remontée dans la même session : rien ne revient.
    renderWithProviders(<FakeShell />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    // Nouvelle session (rechargement) : le stockage ne retient rien, l'accueil revient une fois.
    resetOnboardingMemory();
    expect(onboardingSeen()).toBe(false);
  });
});

describe("visite guidée", () => {
  it("se déroule étape par étape, puis ne revient plus", async () => {
    window.localStorage.removeItem(KEY);
    const { user, unmount } = renderWithProviders(<FakeShell />);
    await user.click(screen.getByRole("button", { name: "Commencer la visite" }));

    const expected = [
      "Recherche rapide",
      "Domaine à analyser",
      "Profil de scan",
      "Menu de navigation",
      "Réglages",
      "Aide et glossaire",
      "Écran de résultat",
    ];
    for (const [position, name] of expected.entries()) {
      await waitFor(() => expect(title()).toBe(name));
      expect(within(bubble()).getByText(`Étape ${position + 1} sur ${expected.length}`)).toBeInTheDocument();
      expect(bubble()).toHaveAttribute("aria-modal", "true");
      expect(within(bubble()).queryByRole("button", { name: "Précédent" }) !== null).toBe(position > 0);
      if (position < expected.length - 1) {
        expect(within(bubble()).getByRole("button", { name: "Passer" })).toBeInTheDocument();
        await user.click(within(bubble()).getByRole("button", { name: "Suivant" }));
      }
    }
    // Profils : les trois choix et la case d'autorisation sont expliqués.
    // Dernière étape (sans scan enregistré) : l'écran de résultat expliqué sans navigation.
    expect(within(bubble()).getByText(/Le bouton Exporter/)).toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent(/^\/$/);
    expect(within(bubble()).queryByRole("button", { name: "Passer" })).not.toBeInTheDocument();
    await user.click(within(bubble()).getByRole("button", { name: "Terminer" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByTestId("guided-tour")).not.toBeInTheDocument();
    expect(onboardingSeen()).toBe(true);
    unmount();
    renderWithProviders(<FakeShell />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("explique les profils, la case d'autorisation et les cinq écrans du menu", async () => {
    const { user } = renderWithProviders(<FakeShell />);
    act(() => startGuidedTour());
    await waitFor(() => expect(title()).toBe("Recherche rapide"));
    expect(within(bubble()).getByText(/Ctrl\+K/)).toBeInTheDocument();
    await user.click(within(bubble()).getByRole("button", { name: "Suivant" }));
    await user.click(within(bubble()).getByRole("button", { name: "Suivant" }));
    await waitFor(() => expect(title()).toBe("Profil de scan"));
    for (const text of [/^Rapide/, /^Complet/, /^Personnalisé.*case d'autorisation/]) {
      expect(within(bubble()).getByText(text)).toBeInTheDocument();
    }
    await user.click(within(bubble()).getByRole("button", { name: "Suivant" }));
    await waitFor(() => expect(title()).toBe("Menu de navigation"));
    expect(within(bubble()).getAllByRole("listitem").map((item) => item.textContent?.split(" :")[0])).toEqual([
      "Tableau de bord",
      "Historique",
      "Lot",
      "Comparer",
      "Surveillance",
    ]);
    await user.click(within(bubble()).getByRole("button", { name: "Suivant" }));
    await waitFor(() => expect(title()).toBe("Réglages"));
    expect(within(bubble()).getByText(/Clés d'API, facultatives/)).toBeInTheDocument();
  });

  it("saute proprement une étape dont l'élément manque, dans les deux sens", async () => {
    const { user } = renderWithProviders(<FakeShell without={["profiles", "nav-help"]} />);
    act(() => startGuidedTour());
    await waitFor(() => expect(title()).toBe("Recherche rapide"));
    await user.click(within(bubble()).getByRole("button", { name: "Suivant" }));
    await waitFor(() => expect(title()).toBe("Domaine à analyser"));
    await user.click(within(bubble()).getByRole("button", { name: "Suivant" }));
    // « Profil de scan » est sauté : le compte total s'ajuste.
    await waitFor(() => expect(title()).toBe("Menu de navigation"));
    // L'absence de « Aide et glossaire » n'est connue qu'à son tour : 6 étapes pour l'instant.
    expect(within(bubble()).getByText("Étape 3 sur 6")).toBeInTheDocument();
    await user.click(within(bubble()).getByRole("button", { name: "Précédent" }));
    await waitFor(() => expect(title()).toBe("Domaine à analyser"));
    await user.click(within(bubble()).getByRole("button", { name: "Suivant" }));
    await user.click(within(bubble()).getByRole("button", { name: "Suivant" }));
    await waitFor(() => expect(title()).toBe("Réglages"));
    await user.click(within(bubble()).getByRole("button", { name: "Suivant" }));
    // « Aide et glossaire » manque aussi.
    await waitFor(() => expect(title()).toBe("Écran de résultat"));
    expect(within(bubble()).getByText("Étape 5 sur 5")).toBeInTheDocument();
  });

  it("toutes les étapes absentes sauf la dernière : la visite n'affiche qu'elle", async () => {
    renderWithProviders(<FakeShell without={["palette", "domain", "profiles", "nav", "nav-settings", "nav-help"]} />);
    act(() => startGuidedTour());
    await waitFor(() => expect(title()).toBe("Écran de résultat"));
    expect(within(bubble()).getByText("Étape 1 sur 1")).toBeInTheDocument();
  });

  it("clavier : flèches, Entrée, focus piégé, Échap ferme et rend le focus", async () => {
    const { user } = renderWithProviders(<FakeShell />);
    const relaunch = screen.getByRole("button", { name: "Relancer" });
    await user.click(relaunch);
    await waitFor(() => expect(title()).toBe("Recherche rapide"));
    // Le bouton principal reçoit le focus.
    expect(within(bubble()).getByRole("button", { name: "Suivant" })).toHaveFocus();
    await user.keyboard("{ArrowRight}");
    await waitFor(() => expect(title()).toBe("Domaine à analyser"));
    await user.keyboard("{ArrowLeft}");
    await waitFor(() => expect(title()).toBe("Recherche rapide"));
    // Flèche gauche à la première étape : rien ne bouge.
    await user.keyboard("{ArrowLeft}");
    expect(title()).toBe("Recherche rapide");
    // Entrée sur le bouton « Suivant » avance.
    await user.keyboard("{Enter}");
    await waitFor(() => expect(title()).toBe("Domaine à analyser"));
    // Entrée sur la bulle elle-même avance aussi.
    act(() => bubble().focus());
    await user.keyboard("{Enter}");
    await waitFor(() => expect(title()).toBe("Profil de scan"));
    // Tab et Maj+Tab restent dans la bulle.
    for (let i = 0; i < 5; i += 1) {
      await user.tab();
      expect(bubble().contains(document.activeElement)).toBe(true);
    }
    for (let i = 0; i < 5; i += 1) {
      await user.tab({ shift: true });
      expect(bubble().contains(document.activeElement)).toBe(true);
    }
    // Un élément de la page qui prend le focus le rend à la bulle.
    act(() => screen.getByLabelText("Domaine").focus());
    expect(bubble().contains(document.activeElement)).toBe(true);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(relaunch).toHaveFocus();
    expect(onboardingSeen()).toBe(true);
  });

  it("annonce chaque étape à un lecteur d'écran (aria-live)", async () => {
    const { user } = renderWithProviders(<FakeShell />);
    act(() => startGuidedTour());
    await waitFor(() => expect(title()).toBe("Recherche rapide"));
    const live = screen.getByTestId("guided-tour").querySelector("[aria-live='polite']");
    expect(live).toHaveTextContent("Étape 1 sur 7 : Recherche rapide");
    await user.click(within(bubble()).getByRole("button", { name: "Suivant" }));
    await waitFor(() => expect(live).toHaveTextContent("Étape 2 sur 7 : Domaine à analyser"));
  });

  it("« Passer » ferme la visite et la marque comme faite", async () => {
    window.localStorage.removeItem(KEY);
    const { user } = renderWithProviders(<FakeShell />);
    await user.click(screen.getByRole("button", { name: "Commencer la visite" }));
    await waitFor(() => expect(title()).toBe("Recherche rapide"));
    await user.click(within(bubble()).getByRole("button", { name: "Passer" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(window.localStorage.getItem(KEY)).toBe("1");
  });

  it("avec un scan enregistré, ouvre son résultat et en montre la note, les constats, les familles et l'export", async () => {
    mockFetch({ "/api/history": { total: 1, scans: [makeSummary({ id: 42 })] } });
    const { user, queryClient } = renderWithProviders(<FakeShell waitMs={2000} />);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0));
    act(() => startGuidedTour());
    for (let i = 0; i < 6; i += 1) {
      await waitFor(() => expect(within(bubble()).getByText(`Étape ${i + 1} sur 10`)).toBeInTheDocument());
      await user.click(within(bubble()).getByRole("button", { name: "Suivant" }));
    }
    const expected = ["Note de sécurité", "Constats", "Familles de contrôles", "Actions et export"];
    for (const [position, name] of expected.entries()) {
      await waitFor(() => expect(title()).toBe(name));
      expect(screen.getByTestId("location")).toHaveTextContent("/scans/42");
      expect(within(bubble()).getByText(`Étape ${position + 7} sur 10`)).toBeInTheDocument();
      if (position < expected.length - 1) await user.click(within(bubble()).getByRole("button", { name: "Suivant" }));
    }
    expect(within(bubble()).getByText(/Exporter/)).toBeInTheDocument();
    // Retour en arrière jusqu'aux étapes de l'écran de scan : la visite y retourne.
    const press = async (name: string) => user.click(await screen.findByRole("button", { name }));
    for (let i = 0; i < 7; i += 1) await press("Précédent");
    await waitFor(() => expect(title()).toBe("Profil de scan"));
    expect(screen.getByTestId("location")).toHaveTextContent(/^\/$/);
    for (let i = 0; i < 4; i += 1) await press("Suivant");
    await waitFor(() => expect(title()).toBe("Note de sécurité"));
    expect(screen.getByTestId("location")).toHaveTextContent("/scans/42");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("la palette de commandes la relance (« visite », « tutoriel »)", async () => {
    const onClose = vi.fn();
    const { user } = renderWithProviders(
      <>
        <CommandPalette open onClose={onClose} />
        <FakeShell />
      </>,
    );
    const input = screen.getByRole("combobox");
    // Liste par défaut inchangée : la relance n'apparaît qu'à la recherche.
    expect(screen.queryByRole("option", { name: "Relancer la visite guidée" })).not.toBeInTheDocument();
    await user.type(input, "tuto");
    expect(screen.getByRole("option", { name: "Relancer la visite guidée" })).toBeInTheDocument();
    await user.clear(input);
    await user.type(input, "visite");
    await user.keyboard("{Enter}");
    expect(onClose).toHaveBeenCalled();
    await waitFor(() => expect(screen.getByRole("dialog", { name: "Recherche rapide" })).toBeInTheDocument());
  });

  it("s'affiche en anglais", async () => {
    await act(async () => {
      await setLang("en");
    });
    window.localStorage.removeItem(KEY);
    const { user } = renderWithProviders(<FakeShell />);
    expect(screen.getByRole("dialog", { name: "Welcome to DomainRecon" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Start the tour" }));
    await waitFor(() => expect(title()).toBe("Quick search"));
    expect(within(bubble()).getByText("Step 1 of 7")).toBeInTheDocument();
    expect(within(bubble()).getByRole("button", { name: "Next" })).toBeInTheDocument();
  });
});

describe("indicateur « visite faite »", () => {
  it("se lit et s'écrit dans le stockage local", () => {
    window.localStorage.removeItem(KEY);
    expect(onboardingSeen()).toBe(false);
    markOnboardingSeen();
    expect(window.localStorage.getItem(KEY)).toBe("1");
    expect(onboardingSeen()).toBe(true);
  });
});
