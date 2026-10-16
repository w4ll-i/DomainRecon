import { act, configure, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { setToken } from "../../../api/client";
import type { FamilyKey, ScanResponse } from "../../../api/types";
import { setLang } from "../../../i18n";
import { FAMILY_KEYS } from "../../../lib/families";
import { jsonResponse, mockFetch } from "../../../test/fetchMock";
import { allOk, makeLegacyScan, makeScan } from "../../../test/fixtures";
import { renderWithProviders } from "../../../test/render";
import { FamilyPage } from "../FamilyPage";
import { FAMILY_TABS } from "../tabs";
import { WhoisModule } from "./identity";
import { ScreenshotModule } from "./Screenshot";

// Sous la charge de la suite complète, findBy* (1 s par défaut) et les tests (5 s) sont trop justes.
configure({ asyncUtilTimeout: 5000 });
vi.setConfig({ testTimeout: 20_000 });

vi.mock("cytoscape", () => ({ default: vi.fn(() => ({ on: vi.fn(), destroy: vi.fn() })) }));

const card = (name: string) => screen.getByRole("region", { name });

// Scan servi par le faux serveur ; PATCH /meta le met à jour comme l'API.
function renderIdentity(initial: ScanResponse = makeScan(), patch?: (body: Record<string, unknown>) => Response) {
  const state = { scan: initial };
  const { calls } = mockFetch({
    "GET /api/scan/42": () => jsonResponse(state.scan),
    "PATCH /api/scan/42/meta": ({ init }) => {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      if (patch) return patch(body);
      state.scan = { ...state.scan, ...body };
      return jsonResponse(state.scan);
    },
  });
  // Notes et tags ont leur onglet dans l'écran de la famille (lien profond).
  const utils = renderWithProviders(<FamilyPage />, { route: "/scans/42/identity/notes", path: "/scans/:id/:family/:module?" });
  return { ...utils, calls };
}

beforeEach(() => {
  // jsdom n'implémente pas les URL blob:.
  URL.createObjectURL = vi.fn(() => "blob:capture");
  URL.revokeObjectURL = vi.fn();
});

describe("WHOIS", () => {
  it("affiche le registre, les statuts EPP nettoyés et les serveurs de noms", () => {
    render(<WhoisModule scan={makeScan()} />);
    const whois = card("WHOIS");
    expect(within(whois).getByText("Registrar").nextElementSibling).toHaveTextContent("RESERVED-Internet Assigned Numbers Authority");
    expect(within(whois).getByText("clientDeleteProhibited")).toBeInTheDocument();
    expect(whois).not.toHaveTextContent("https://icann.org");
    expect(whois).toHaveTextContent("a.iana-servers.net");
  });

  it("liste les serveurs de noms même dupliqués, sans clé React en double", () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const base = makeScan();
    render(<WhoisModule scan={{ ...base, whois_data: { ...base.whois_data, name_servers: ["ns.example.net", "ns.example.net"] } }} />);
    expect(within(card("WHOIS")).getAllByText("ns.example.net")).toHaveLength(2);
    expect(errors).not.toHaveBeenCalled();
  });

  it("signale un WHOIS fait sur la plateforme d'hébergement, ou un domaine non enregistré", () => {
    const base = makeScan();
    const { unmount } = render(
      <WhoisModule scan={{ ...base, domain: "alice.github.io", whois_data: { ...base.whois_data, queried_domain: "github.io" } }} />,
    );
    expect(card("WHOIS")).toHaveTextContent("WHOIS de github.io (domaine racine ou plateforme d'hébergement), pas de alice.github.io");
    unmount();
    render(<WhoisModule scan={makeScan({ whois_data: { measured: true, registered: false } })} />);
    expect(card("WHOIS")).toHaveTextContent("Domaine non enregistré selon le registre WHOIS");
  });
});

describe("capture d'écran", () => {
  it("se charge par fetch avec le jeton d'API et s'affiche en URL blob:", async () => {
    setToken("abc");
    const { calls } = mockFetch({
      "GET /api/screenshot/example_com_1700000000.png": () =>
        ({ ok: true, status: 200, blob: async () => new Blob(["png"], { type: "image/png" }) }) as unknown as Response,
    });
    const { unmount } = render(<ScreenshotModule scan={makeScan({ screenshot_path: "example_com_1700000000.png", module_status: allOk() })} />);
    const image = await screen.findByRole("img", { name: "Capture d'écran de example.com" });
    expect(image).toHaveAttribute("src", "blob:capture");
    expect(new Headers(calls[0].init.headers).get("X-API-Token")).toBe("abc");
    unmount();
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:capture");
  });

  it("capture introuvable : message lisible", async () => {
    mockFetch({
      "GET /api/screenshot/example_com_1700000000.png": () => jsonResponse({ detail: "Capture non trouvée", code: null, params: {} }, 404),
    });
    render(<ScreenshotModule scan={makeScan({ screenshot_path: "example_com_1700000000.png", module_status: allOk() })} />);
    expect(await screen.findByText("Image non disponible : Capture non trouvée")).toBeInTheDocument();
  });

  it("fichier reçu mais illisible comme image : message dédié, pas « introuvable »", async () => {
    mockFetch({
      "GET /api/screenshot/example_com_1700000000.png": () =>
        ({ ok: true, status: 200, blob: async () => new Blob(["pas une image"], { type: "image/png" }) }) as unknown as Response,
    });
    render(<ScreenshotModule scan={makeScan({ screenshot_path: "example_com_1700000000.png", module_status: allOk() })} />);
    fireEvent.error(await screen.findByRole("img", { name: "Capture d'écran de example.com" }));
    const card = await screen.findByRole("region", { name: "Capture d'écran" });
    expect(card).toHaveTextContent("Image non disponible : fichier image illisible");
    expect(card).not.toHaveTextContent("introuvable");
  });

  it("module sans objet (Chromium absent) : raison, aucun appel", () => {
    const { calls } = mockFetch({});
    render(<ScreenshotModule scan={makeScan()} />);
    expect(card("Capture d'écran")).toHaveTextContent("Playwright ou son navigateur Chromium n'est pas installé");
    expect(calls).toHaveLength(0);
  });
});

describe("notes et tags", () => {
  it("ajoute puis retire un tag", async () => {
    const { user, calls } = renderIdentity();
    await user.type(await screen.findByPlaceholderText("Ajouter un tag…"), "e2e");
    await user.click(screen.getByRole("button", { name: "Ajouter" }));
    expect(await screen.findByText("e2e")).toBeInTheDocument();
    const patch = calls.find((call) => call.method === "PATCH");
    expect(JSON.parse(String(patch?.init.body))).toEqual({ tags: ["prod", "e2e"] });
    expect(patch?.url.searchParams.get("lang")).toBe("fr");
    expect(screen.getByPlaceholderText("Ajouter un tag…")).toHaveValue("");
    await user.click(screen.getByRole("button", { name: "Retirer le tag prod" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Retirer le tag prod" })).not.toBeInTheDocument());
  });

  it("refuse un doublon (sans tenir compte de la casse) et un tag trop long, sans appel", async () => {
    const { user, calls } = renderIdentity();
    const input = await screen.findByPlaceholderText("Ajouter un tag…");
    await user.type(input, "PROD");
    await user.click(screen.getByRole("button", { name: "Ajouter" }));
    const duplicate = await screen.findByText("Ce tag existe déjà");
    // Refus lié au champ : aria-invalid et aria-describedby, annoncé une seule fois.
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAttribute("aria-describedby", duplicate.id);
    expect(duplicate).toHaveAttribute("role", "alert");
    await user.type(input, "x");
    expect(input).not.toHaveAttribute("aria-invalid");
    expect(screen.queryByText("Ce tag existe déjà")).not.toBeInTheDocument();
    // Changement direct plutôt que 51 frappes : trop lent sous la charge de la suite complète.
    fireEvent.change(input, { target: { value: "x".repeat(51) } });
    await user.click(screen.getByRole("button", { name: "Ajouter" }));
    expect(await screen.findByText("Tag trop long : 50 caractères au maximum", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(calls.filter((call) => call.method === "PATCH")).toHaveLength(0);
  }, 15_000);

  it("refuse des notes trop longues : message lié au champ, sans appel", async () => {
    const { user, calls } = renderIdentity();
    const notes = await screen.findByLabelText("Notes d'investigation");
    // Changement direct plutôt que 10 000 frappes (ou un collage) : trop lent sous charge.
    fireEvent.change(notes, { target: { value: "n".repeat(10_001) } });
    await user.click(screen.getByRole("button", { name: "Enregistrer les notes" }));
    const error = await screen.findByText(/Notes trop longues : \d+ caractères pour 10000 au maximum/);
    expect(notes).toHaveAttribute("aria-invalid", "true");
    expect(notes).toHaveAttribute("aria-describedby", error.id);
    expect(calls.filter((call) => call.method === "PATCH")).toHaveLength(0);
  });

  it("garde le focus clavier après le retrait d'un tag (voisin, puis précédent, puis champ)", async () => {
    const { user } = renderIdentity(makeScan({ tags: ["prod", "stage", "dev"] }));
    await user.click(await screen.findByRole("button", { name: "Retirer le tag stage" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Retirer le tag dev" })).toHaveFocus());
    await user.click(screen.getByRole("button", { name: "Retirer le tag dev" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Retirer le tag prod" })).toHaveFocus());
    await user.click(screen.getByRole("button", { name: "Retirer le tag prod" }));
    await waitFor(() => expect(screen.getByPlaceholderText("Ajouter un tag…")).toHaveFocus());
  });

  it("refuse un doublon qui ne diffère que par la casse Unicode (ß / SS)", async () => {
    const { user, calls } = renderIdentity(makeScan({ tags: ["Straße"] }));
    await user.type(await screen.findByPlaceholderText("Ajouter un tag…"), "STRASSE");
    await user.click(screen.getByRole("button", { name: "Ajouter" }));
    expect(await screen.findByText("Ce tag existe déjà", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(calls.filter((call) => call.method === "PATCH")).toHaveLength(0);
  }, 15_000);

  it("enregistre les notes", async () => {
    const { user, calls } = renderIdentity();
    const notes = await screen.findByLabelText("Notes d'investigation");
    expect(notes).toHaveValue("Note initiale");
    await user.clear(notes);
    await user.type(notes, "Revoir le DMARC");
    await user.click(screen.getByRole("button", { name: "Enregistrer les notes" }));
    expect(await screen.findByText("Notes enregistrées")).toBeInTheDocument();
    expect(JSON.parse(String(calls.find((call) => call.method === "PATCH")?.init.body))).toEqual({ notes: "Revoir le DMARC" });
  });

  it("garde la saisie et explique un refus du serveur", async () => {
    const { user } = renderIdentity(makeScan(), () =>
      jsonResponse({ detail: "chaque tag doit faire de 1 à 50 caractères", code: null, params: {} }, 422),
    );
    const input = await screen.findByPlaceholderText("Ajouter un tag…");
    await user.type(input, "refusé");
    await user.click(screen.getByRole("button", { name: "Ajouter" }));
    expect(await screen.findByText("Enregistrement impossible : chaque tag doit faire de 1 à 50 caractères")).toBeInTheDocument();
    expect(input).toHaveValue("refusé");
  });

  it("garde le texte des notes quand l'enregistrement est refusé", async () => {
    const { user } = renderIdentity(makeScan(), () => jsonResponse({ detail: "notes refusées par le serveur", code: null, params: {} }, 422));
    const notes = await screen.findByLabelText("Notes d'investigation");
    await user.type(notes, " + ajout");
    await user.click(screen.getByRole("button", { name: "Enregistrer les notes" }));
    expect(await screen.findByText("Enregistrement impossible : notes refusées par le serveur")).toBeInTheDocument();
    expect(screen.queryByText("Notes enregistrées")).not.toBeInTheDocument();
    expect(notes).toHaveValue("Note initiale + ajout");
  });

  it("422 sur les notes (caractères interdits) : le detail du serveur s'affiche tel quel près du champ, la saisie reste", async () => {
    const detail = "Les notes contiennent des caractères interdits (séparateurs de ligne ou marques bidirectionnelles).";
    const { user } = renderIdentity(makeScan(), () =>
      jsonResponse(
        { detail, code: "api.meta_notes_forbidden_chars", params: {}, errors: [{ loc: ["body", "notes"], msg: detail, type: "api.meta_notes_forbidden_chars" }] },
        422,
      ),
    );
    const notes = await screen.findByLabelText("Notes d'investigation");
    await user.type(notes, " + ajout");
    await user.click(screen.getByRole("button", { name: "Enregistrer les notes" }));
    const error = await screen.findByText(`Enregistrement impossible : ${detail}`);
    expect(error).toHaveAttribute("role", "alert");
    expect(notes).toHaveAttribute("aria-invalid", "true");
    expect(notes).toHaveAttribute("aria-describedby", error.id);
    expect(screen.queryByText(/Requête invalide/)).not.toBeInTheDocument();
    expect(notes).toHaveValue("Note initiale + ajout");
    // Le message disparaît dès la saisie suivante.
    await user.type(notes, "!");
    expect(screen.queryByText(`Enregistrement impossible : ${detail}`)).not.toBeInTheDocument();
  });

  it("422 sur un tag (caractères interdits) : detail du serveur près du champ, saisie conservée", async () => {
    const detail = "Un tag contient des caractères interdits.";
    const { user } = renderIdentity(makeScan(), () =>
      jsonResponse({ detail, code: "api.meta_tag_forbidden_chars", params: {}, errors: [] }, 422),
    );
    const input = await screen.findByPlaceholderText("Ajouter un tag…");
    await user.type(input, "ab");
    await user.click(screen.getByRole("button", { name: "Ajouter" }));
    const error = await screen.findByText(`Enregistrement impossible : ${detail}`);
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAttribute("aria-describedby", error.id);
    expect(input).toHaveValue("ab");
  });

  it("garde le brouillon de notes quand on change de langue (la page ne se démonte pas)", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    mockFetch({
      "GET /api/scan/42": async ({ url }) => {
        if (url.searchParams.get("lang") === "en") await gate;
        return jsonResponse(makeScan());
      },
    });
    const { user } = renderWithProviders(<FamilyPage />, { route: "/scans/42/identity/notes", path: "/scans/:id/:family/:module?" });
    await user.type(await screen.findByLabelText("Notes d'investigation"), " + brouillon");
    await act(async () => {
      await setLang("en");
    });
    // Données du scan en cours de relecture : l'ancien contenu reste, avec le brouillon.
    expect(screen.getByLabelText("Investigation notes")).toHaveValue("Note initiale + brouillon");
    release();
    await waitFor(() => expect(screen.getByLabelText("Investigation notes")).toHaveValue("Note initiale + brouillon"));
  });
});

// Chaque onglet de chaque famille (un module à la fois) ; la réputation n'en a pas.
const LEGACY_PAGES = FAMILY_KEYS.flatMap((family): Array<[FamilyKey, string | undefined]> =>
  FAMILY_TABS[family].length ? FAMILY_TABS[family].map((tab) => [family, tab.key]) : [[family, undefined]],
);

describe("anciens scans", () => {
  it.each(LEGACY_PAGES)("la famille %s (onglet %s) s'affiche sans planter", async (family, tab) => {
    mockFetch({ "GET /api/scan/7": makeLegacyScan() });
    renderWithProviders(<FamilyPage />, { route: `/scans/7/${family}${tab ? `/${tab}` : ""}`, path: "/scans/:id/:family/:module?" });
    expect(await screen.findByRole("heading", { level: 1 })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("réseau : ports en entiers nus listés, jamais « Aucun port ouvert »", async () => {
    mockFetch({ "GET /api/scan/7": { ...makeLegacyScan(), open_ports: [80, 443] } });
    renderWithProviders(<FamilyPage />, { route: "/scans/7/network/open_ports", path: "/scans/:id/:family/:module?" });
    const ports = await screen.findByRole("region", { name: "Ports ouverts" });
    expect(within(ports).getAllByRole("listitem")).toHaveLength(2);
    expect(within(ports).getByText("443")).toBeInTheDocument();
    expect(ports).not.toHaveTextContent("Aucun port ouvert");
  });

  it("identité : tags à null et notes à null, ajout d'un premier tag possible", async () => {
    const legacy = { ...makeLegacyScan(), tags: null, notes: null };
    const { calls } = mockFetch({
      "GET /api/scan/7": legacy,
      "PATCH /api/scan/7/meta": ({ init }) => jsonResponse({ ...legacy, ...(JSON.parse(String(init.body)) as object) }),
    });
    const { user } = renderWithProviders(<FamilyPage />, { route: "/scans/7/identity/notes", path: "/scans/:id/:family/:module?" });
    expect(await screen.findByText("Aucun tag")).toBeInTheDocument();
    expect(screen.getByLabelText("Notes d'investigation")).toHaveValue("");
    await user.type(screen.getByPlaceholderText("Ajouter un tag…"), "legacy");
    await user.click(screen.getByRole("button", { name: "Ajouter" }));
    expect(await screen.findByText("legacy")).toBeInTheDocument();
    expect(JSON.parse(String(calls.find((call) => call.method === "PATCH")?.init.body))).toEqual({ tags: ["legacy"] });
  });
});
