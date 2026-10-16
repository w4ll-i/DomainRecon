import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { mockFetch } from "../../test/fetchMock";
import { HOSTILE, makeScan } from "../../test/fixtures";
import { renderWithProviders } from "../../test/render";
import { FindingsList } from "./FindingsList";

const NGINX = 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;';
const APACHE = 'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"';

function moduleEntry(extra: Record<string, unknown> = {}) {
  return {
    name: "security_headers",
    family: "web",
    category: "passif",
    requires_authorization: false,
    help: {
      title: "En-têtes de sécurité",
      checks: "Contrôle les en-têtes HTTP de sécurité.",
      why: "Ils limitent les attaques côté navigateur.",
    },
    ...extra,
  };
}

const finding = { severity: "high" as const, family: "web" as const, module: "security_headers", message: "HSTS absent" };

// Ouvre « Comprendre et corriger » du constat et renvoie la rubrique « Comment corriger ».
async function openFix(extra: Record<string, unknown>) {
  mockFetch({ "GET /api/modules": { modules: [moduleEntry(extra)], families: ["web"] } });
  const utils = renderWithProviders(<FindingsList scan={makeScan({ findings: [finding] })} titleId="t" />);
  await utils.user.click(screen.getByRole("button", { name: /Comprendre et corriger|Understand and fix/ }));
  const heading = await screen.findByText(/^(Comment corriger|How to fix it)$/);
  const fix = heading.closest("div") as HTMLElement;
  return { ...utils, fix };
}

describe("« Comment corriger » du catalogue", () => {
  it("étapes en liste numérotée, code en ligne en police de code ; le conseil de famille ne sert plus", async () => {
    // Le catalogue est lu après le premier rendu : les étapes remplacent le repli dès qu'il répond.
    const { fix } = await openFix({
      fix: "Ouvrez la configuration du serveur web.\nAjoutez l'en-tête `Strict-Transport-Security` avec `max-age=63072000`.\nRelancez le scan pour vérifier.",
    });
    const steps = await within(fix).findAllByRole("listitem");
    expect(steps).toHaveLength(3);
    expect(fix.querySelector("ol")).not.toBeNull();
    expect(steps[0]).toHaveTextContent("Ouvrez la configuration du serveur web.");
    const codes = [...steps[1].querySelectorAll("code")].map((code) => code.textContent);
    expect(codes).toEqual(["Strict-Transport-Security", "max-age=63072000"]);
    // Plus de numéro écrit dans le texte : la liste numérote.
    expect(steps[1].textContent).toBe("Ajoutez l'en-tête Strict-Transport-Security avec max-age=63072000.");
    expect(screen.queryByText(/dans la configuration du serveur web/)).not.toBeInTheDocument();
  });

  it("sans conseil dans le catalogue : le conseil de l'interface reste en repli, sans extrait ni lien", async () => {
    const { fix } = await openFix({});
    expect(within(fix).getByText(/Ajoutez Strict-Transport-Security, Content-Security-Policy/)).toBeInTheDocument();
    expect(fix.querySelector("ol")).toBeNull();
    expect(within(fix).queryByRole("button", { name: /Copier/ })).not.toBeInTheDocument();
    expect(within(fix).queryByRole("link")).not.toBeInTheDocument();
  });

  it("un extrait sans variante : un bloc de code et un bouton Copier qui copie le code seul", async () => {
    const { fix, user } = await openFix({ fix: "Ajoutez l'en-tête.", fix_snippet: `\n${NGINX}\n` });
    const code = await within(fix).findByText(NGINX);
    expect(code.tagName).toBe("CODE");
    expect(within(fix).queryByRole("tablist")).not.toBeInTheDocument();
    await user.click(within(fix).getByRole("button", { name: "Copier l'extrait" }));
    expect(await navigator.clipboard.readText()).toBe(NGINX);
    // Retour d'information : « Copié » sur le bouton et annonce pour les lecteurs d'écran.
    await waitFor(() => expect(within(fix).getByRole("button", { name: "Copier l'extrait" })).toHaveTextContent("Copié"));
    expect(within(fix).getByRole("status")).toHaveTextContent("Copié");
  });

  it("l'état « Copié » s'efface de lui-même", async () => {
    const { fix, user } = await openFix({ fix: "Étape.", fix_snippet: NGINX });
    await user.click(await within(fix).findByRole("button", { name: "Copier l'extrait" }));
    expect(within(fix).getByRole("button", { name: "Copier l'extrait" })).toHaveTextContent("Copié");
    await waitFor(() => expect(within(fix).getByRole("button", { name: "Copier l'extrait" })).toHaveTextContent("Copier"), {
      timeout: 4000,
    });
    expect(within(fix).getByRole("button", { name: "Copier l'extrait" })).not.toHaveTextContent("Copié");
  });

  it("plusieurs variantes : onglets par plateforme, le Copier de l'onglet actif copie son code sans l'en-tête", async () => {
    const snippet = `# nginx\n${NGINX}\n\n# Apache\n${APACHE}\n\n# IIS\n<add name="Strict-Transport-Security" value="max-age=63072000" />`;
    const { fix, user } = await openFix({ fix: "Ajoutez l'en-tête.", fix_snippet: snippet });
    const tabs = await within(fix).findByRole("tablist", { name: "Variantes par plateforme" });
    expect(within(tabs).getAllByRole("tab").map((tab) => tab.textContent)).toEqual(["nginx", "Apache", "IIS"]);
    expect(within(tabs).getByRole("tab", { name: "nginx" })).toHaveAttribute("aria-selected", "true");
    // Un seul extrait à la fois, et jamais la ligne « # nginx » dans le code.
    expect(within(fix).getByText(NGINX)).toBeInTheDocument();
    expect(within(fix).queryByText(APACHE)).not.toBeInTheDocument();
    expect(fix.textContent).not.toContain("# nginx");

    await user.click(within(fix).getByRole("button", { name: "Copier l'extrait nginx" }));
    expect(await navigator.clipboard.readText()).toBe(NGINX);

    await user.click(within(tabs).getByRole("tab", { name: "Apache" }));
    expect(within(tabs).getByRole("tab", { name: "Apache" })).toHaveAttribute("aria-selected", "true");
    expect(within(fix).getByText(APACHE)).toBeInTheDocument();
    expect(within(fix).queryByText(NGINX)).not.toBeInTheDocument();
    // Autre onglet : le bouton repart sans « Copié ».
    const copy = within(fix).getByRole("button", { name: "Copier l'extrait Apache" });
    expect(copy).not.toHaveTextContent("Copié");
    await user.click(copy);
    expect(await navigator.clipboard.readText()).toBe(APACHE);

    // Le panneau est relié à l'onglet actif (WAI-ARIA).
    const panel = within(fix).getByRole("tabpanel");
    expect(panel).toHaveAttribute("aria-labelledby", within(tabs).getByRole("tab", { name: "Apache" }).id);
  });

  it("les flèches changent de variante au clavier", async () => {
    const snippet = `# nginx\n${NGINX}\n# Apache\n${APACHE}`;
    const { fix, user } = await openFix({ fix: "Ajoutez l'en-tête.", fix_snippet: snippet });
    const nginx = await within(fix).findByRole("tab", { name: "nginx" });
    nginx.focus();
    await user.keyboard("{ArrowRight}");
    expect(within(fix).getByRole("tab", { name: "Apache" })).toHaveAttribute("aria-selected", "true");
    expect(within(fix).getByText(APACHE)).toBeInTheDocument();
  });

  it("deux constats ouverts ensemble : leurs onglets ne se confondent pas", async () => {
    mockFetch({
      "GET /api/modules": {
        modules: [moduleEntry({ fix: "Étape.", fix_snippet: `# nginx\n${NGINX}\n# Apache\n${APACHE}` })],
        families: ["web"],
      },
    });
    const scan = makeScan({ findings: [finding, { ...finding, message: "HSTS trop court" }] });
    const { user } = renderWithProviders(<FindingsList scan={scan} titleId="t" />);
    for (const toggle of screen.getAllByRole("button", { name: /Comprendre et corriger/ })) await user.click(toggle);
    const lists = await screen.findAllByRole("tablist");
    expect(lists).toHaveLength(2);
    const ids = screen.getAllByRole("tab").map((tab) => tab.id);
    expect(new Set(ids).size).toBe(ids.length);
    await user.click(within(lists[1]).getByRole("tab", { name: "Apache" }));
    expect(within(lists[0]).getByRole("tab", { name: "nginx" })).toHaveAttribute("aria-selected", "true");
  });

  it("documentation officielle : lien https dans un nouvel onglet, sans référent ni accès à la fenêtre", async () => {
    const { fix } = await openFix({
      fix: "Ajoutez l'en-tête.",
      fix_ref: "https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Strict-Transport-Security",
    });
    const link = await within(fix).findByRole("link", { name: /Documentation officielle/ });
    expect(link).toHaveAttribute("href", "https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Strict-Transport-Security");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(within(fix).getByText("developer.mozilla.org")).toBeInTheDocument();
  });

  it.each(["http://example.com/doc", "javascript:alert(1)", "data:text/html,<b>x</b>", "/relatif"])(
    "adresse non https (%s) : pas de lien",
    async (ref) => {
      const { fix } = await openFix({ fix: "Ajoutez l'en-tête.", fix_ref: ref });
      await within(fix).findByRole("list");
      expect(within(fix).queryByRole("link")).not.toBeInTheDocument();
    },
  );

  it("un texte hostile du catalogue reste du texte : aucun élément créé", async () => {
    const { fix } = await openFix({ fix: `${HOSTILE}\nAjoutez \`${HOSTILE}\``, fix_snippet: `# ${HOSTILE}\n${HOSTILE}` });
    await within(fix).findByRole("list");
    expect(fix.querySelector("img")).toBeNull();
    expect(fix.textContent).toContain(HOSTILE);
  });

  it("copie impossible : une notification d'erreur, le bouton ne ment pas", async () => {
    const { fix, user } = await openFix({ fix: "Étape.", fix_snippet: NGINX });
    const button = await within(fix).findByRole("button", { name: "Copier l'extrait" });
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("refusé"));
    await user.click(button);
    expect(await screen.findByText("Copie impossible : sélectionnez le code à la main.")).toBeInTheDocument();
    expect(button).not.toHaveTextContent("Copié");
  });

  it("anglais : rubriques, boutons et lien traduits", async () => {
    const { setLang } = await import("../../i18n");
    await setLang("en");
    const { fix, user } = await openFix({
      fix: "Add the header.",
      fix_snippet: `# nginx\n${NGINX}\n# Apache\n${APACHE}`,
      fix_ref: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    });
    expect(await within(fix).findByRole("tablist", { name: "Variants by platform" })).toBeInTheDocument();
    await user.click(within(fix).getByRole("button", { name: "Copy nginx snippet" }));
    expect(await navigator.clipboard.readText()).toBe(NGINX);
    expect(within(fix).getByRole("link", { name: /Official documentation/ })).toBeInTheDocument();
  });
});
