import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { mockFetch } from "../../test/fetchMock";
import { makeScan } from "../../test/fixtures";
import { renderWithProviders } from "../../test/render";
import { FindingsList } from "./FindingsList";

const catalog = {
  modules: [
    {
      name: "email_security",
      family: "email",
      category: "passif",
      requires_authorization: false,
      help: {
        title: "Sécurité e-mail",
        checks: "Contrôle les enregistrements SPF, DKIM et DMARC du domaine.",
        why: "Sans DMARC, n'importe qui peut usurper votre domaine.",
      },
    },
  ],
  families: ["email"],
};

describe("constats expliqués", () => {
  it("chaque constat montre sa gravité, puis ce que c'est, pourquoi c'est important et comment corriger", async () => {
    mockFetch({ "GET /api/modules": catalog });
    const scan = makeScan({
      findings: [{ severity: "high", family: "email", module: "email_security", message: "DMARC absent" }],
    });
    const { user } = renderWithProviders(<FindingsList scan={scan} titleId="t" />);
    const item = screen.getByText("DMARC absent").closest("li") as HTMLElement;
    expect(within(item).getByText("Élevée")).toBeInTheDocument();
    const toggle = within(item).getByRole("button", { name: /Comprendre et corriger/ });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(within(item).queryByText("Ce que c'est")).not.toBeInTheDocument();
    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(await within(item).findByText(/Contrôle les enregistrements/)).toBeInTheDocument();
    expect(within(item).getByText("Pourquoi c'est important")).toBeInTheDocument();
    expect(within(item).getByText(/n'importe qui peut usurper/)).toBeInTheDocument();
    // Conseil propre au module.
    expect(within(item).getByText("Comment corriger")).toBeInTheDocument();
    expect(within(item).getByText(/Publiez ou resserrez/)).toBeInTheDocument();
    // Les sigles du texte ont leur infobulle.
    const tips = within(item).getAllByRole("tooltip").map((tip) => tip.textContent);
    expect(tips.some((text) => text?.includes("DMARC"))).toBe(true);
    expect(tips.some((text) => text?.includes("SPF"))).toBe(true);
  });

  it("module inconnu du catalogue : textes par défaut et conseil de la famille", async () => {
    mockFetch({ "GET /api/modules": { modules: [], families: [] } });
    const scan = makeScan({
      findings: [{ severity: "low", family: "leaks", module: "hibp", message: "Compte exposé" }],
    });
    const { user } = renderWithProviders(<FindingsList scan={scan} titleId="t" />);
    await user.click(screen.getByRole("button", { name: /Comprendre et corriger/ }));
    expect(screen.getByText(/Contrôle réalisé par le module/)).toBeInTheDocument();
    expect(screen.getByText(/Changez les identifiants exposés/)).toBeInTheDocument();
  });

  it("anglais : les trois rubriques sont traduites", async () => {
    const { setLang } = await import("../../i18n");
    await setLang("en");
    mockFetch({ "GET /api/modules": { modules: [], families: [] } });
    const scan = makeScan({
      findings: [{ severity: "medium", family: "tls", module: "tls_certificate", message: "Certificate expires soon" }],
    });
    const { user } = renderWithProviders(<FindingsList scan={scan} titleId="t" />);
    await user.click(screen.getByRole("button", { name: /Understand and fix/ }));
    expect(screen.getByText("What it is")).toBeInTheDocument();
    expect(screen.getByText("Why it matters")).toBeInTheDocument();
    expect(screen.getByText("How to fix it")).toBeInTheDocument();
    expect(screen.getByText(/Renew the certificate before it expires/)).toBeInTheDocument();
  });
});
