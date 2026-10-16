import { act, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GLOSSARY_KEYS, splitGlossary } from "../../lib/glossary";
import { mockFetch } from "../../test/fetchMock";
import { renderWithProviders } from "../../test/render";
import { setLang } from "../../i18n";
import en from "../../i18n/en.json";
import fr from "../../i18n/fr.json";
import { Term } from "../../components/Term";
import { HelpPage } from "./HelpPage";
import { Onboarding } from "../onboarding/Onboarding";

type Entry = { name: string; def: string };

describe("glossaire", () => {
  it("compte une cinquantaine de termes, tous définis en français et en anglais", () => {
    expect(GLOSSARY_KEYS.length).toBeGreaterThanOrEqual(50);
    for (const key of GLOSSARY_KEYS) {
      const frEntry = (fr.glossary as Record<string, Entry>)[key];
      const enEntry = (en.glossary as Record<string, Entry>)[key];
      expect(frEntry?.name, key).toBeTruthy();
      expect(frEntry?.def.length, key).toBeGreaterThan(20);
      expect(enEntry?.def.length, key).toBeGreaterThan(20);
    }
    // Aucun terme défini sans clé déclarée.
    expect(Object.keys(fr.glossary).sort()).toEqual([...GLOSSARY_KEYS].sort());
  });

  it("couvre les termes demandés : SPF, DKIM, DMARC, HSTS, CSP, CAA, DNSSEC, ASN, CT, MTA-STS", () => {
    for (const key of ["spf", "dkim", "dmarc", "hsts", "csp", "caa", "dnssec", "asn", "ct", "mta_sts"]) {
      expect(GLOSSARY_KEYS).toContain(key);
    }
  });

  it("repère les sigles entiers d'un texte, pas ceux collés à d'autres lettres", () => {
    const segments = splitGlossary("Publiez SPF et DMARC (MTA-STS), pas SPFX ni xCSP.");
    expect(segments.filter((segment) => segment.term).map((segment) => segment.text)).toEqual(["SPF", "DMARC", "MTA-STS"]);
    expect(segments.map((segment) => segment.text).join("")).toBe("Publiez SPF et DMARC (MTA-STS), pas SPFX ni xCSP.");
  });
});

describe("infobulle Term", () => {
  it("décrit le terme à l'ouverture clavier et se ferme avec Échap", async () => {
    const { user, container } = renderWithProviders(<Term k="hsts" />);
    const term = screen.getByText("HSTS", { selector: "span[tabindex]" });
    const tip = screen.getByRole("tooltip");
    expect(term).toHaveAttribute("aria-describedby", tip.id);
    expect(tip).toHaveTextContent("force le navigateur à n'utiliser que HTTPS");
    await user.tab();
    expect(term).toHaveFocus();
    expect(term).not.toHaveAttribute("data-dismissed");
    await user.keyboard("{Escape}");
    expect(term).toHaveAttribute("data-dismissed", "true");
    expect(container.querySelector("[style]")).toBeNull();
  });
});

describe("page Aide", () => {
  it("présente guide, profils, cadre légal, FAQ et glossaire", () => {
    renderWithProviders(<HelpPage />, { route: "/help", path: "/help" });
    expect(screen.getByRole("heading", { level: 1, name: "Aide" })).toBeInTheDocument();
    for (const name of ["Guide de démarrage", "Profils et modules", "Cadre légal", "Questions fréquentes", "Glossaire"]) {
      expect(screen.getByRole("heading", { level: 2, name })).toBeInTheDocument();
    }
    const nav = screen.getByRole("navigation", { name: "Sections de l'aide" });
    expect(within(nav).getAllByRole("link")).toHaveLength(5);
    const legal = screen.getByRole("region", { name: "Cadre légal" });
    expect(within(legal).getByText(/modules actifs envoient des requêtes/)).toBeInTheDocument();
    expect(within(legal).getByText(/J'ai l'autorisation de tester cette cible/)).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Profils et modules" })).getAllByText(/Rapide|Complet|Personnalisé/).length).toBeGreaterThanOrEqual(3);
    expect(screen.getAllByRole("group").length).toBeGreaterThanOrEqual(0);
    expect(screen.getAllByText(/^(Où|Pourquoi|Que|Comment|Le DNS|Le PDF)/).length).toBeGreaterThanOrEqual(8);
    expect(document.title).toBe("Aide · DomainRecon");
  });

  it("filtre le glossaire", async () => {
    const { user } = renderWithProviders(<HelpPage />, { route: "/help", path: "/help" });
    expect(screen.getByText(`${GLOSSARY_KEYS.length} terme(s)`)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Filtrer le glossaire"), "dnssec");
    const section = screen.getByRole("region", { name: "Glossaire" });
    expect(within(section).getByText("DNSSEC")).toBeInTheDocument();
    expect(within(section).queryByText("HSTS")).not.toBeInTheDocument();
    expect(screen.getByText("2 terme(s)")).toBeInTheDocument();
  });

  it("s'affiche en anglais", async () => {
    await act(async () => {
      await setLang("en");
    });
    renderWithProviders(<HelpPage />, { route: "/help", path: "/help" });
    expect(screen.getByRole("heading", { level: 1, name: "Help" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "Legal framework" })).toBeInTheDocument();
  });

  it("le bouton « Relancer la visite guidée » relance la visite guidée", async () => {
    mockFetch({ "/api/history": { total: 0, scans: [] } });
    // Écran Aide seul : les éléments visés manquent, la visite saute leurs étapes et n'affiche que
    // l'explication de l'écran de résultat (déroulé complet : onboarding/Onboarding.test.tsx).
    const { user } = renderWithProviders(
      <>
        <HelpPage />
        <Onboarding waitMs={0} />
      </>,
      { route: "/help", path: "*" },
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Relancer la visite guidée" }));
    const dialog = await screen.findByRole("dialog", { name: "Écran de résultat" });
    expect(within(dialog).getByText("Étape 1 sur 1")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Terminer" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
