import { act, configure, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../../api/client";
import { type StreamOptions, streamJobEvents } from "../../api/sse";
import type { JobEvent, ModuleName, ModuleRunStatus } from "../../api/types";
import { MODULE_FAMILY, MODULE_NAMES } from "../../lib/families";
import { jsonResponse, mockFetch } from "../../test/fetchMock";
import { renderWithProviders } from "../../test/render";
import { LiveScanPage } from "./LiveScanPage";

vi.mock("../../api/sse", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/sse")>();
  return { ...actual, streamJobEvents: vi.fn() };
});

const stream = vi.mocked(streamJobEvents);

// Sous la charge de la suite complète, le délai par défaut de findBy* (1 s) ne suffit pas.
configure({ asyncUtilTimeout: 5000 });

const moduleEvent = (name: ModuleName, status: ModuleRunStatus = "ok", duration = 0.1): JobEvent => ({
  event: "module",
  data: { name, family: MODULE_FAMILY[name], status, duration },
});

// Identifiants de tâche du serveur : 32 caractères hexadécimaux.
const JOB = "0123456789abcdef0123456789abcdef";
const JOB2 = "fedcba9876543210fedcba9876543210";

const job = { id: JOB, domain: "example.com", status: "running", scan_id: null, done: 0, total: 18 };

// Flux contrôlé par le test : `emit` pousse un événement, le flux reste ouvert.
function openStream() {
  const handle: { emit: (event: JobEvent) => void } = { emit: () => undefined };
  stream.mockImplementation((_id: string, options: StreamOptions) => {
    handle.emit = options.onEvent;
    options.onOpen?.();
    return new Promise<"closed">(() => undefined);
  });
  return handle;
}

function renderLive() {
  return renderWithProviders(<LiveScanPage />, { route: `/scans/live/${JOB}`, path: "/scans/live/:jobId" });
}

describe("suivi en direct", { timeout: 20_000 }, () => {
  beforeEach(() => {
    stream.mockReset();
  });

  it("remplit les tuiles au fil des événements puis ouvre le résultat", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: job, "GET /api/history": { total: 0, scans: [] } });
    renderLive();
    expect(await screen.findByRole("heading", { name: "Analyse de example.com" })).toBeInTheDocument();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    act(() => {
      handle.emit(moduleEvent("dns_records"));
      handle.emit(moduleEvent("subdomains"));
      handle.emit({ event: "progress", data: { done: 2, total: 18 } });
    });
    // Le compteur en grand est un visuel masqué aux lecteurs d'écran, qui lisent « n modules sur N ».
    expect(screen.getByText("2 modules sur 18")).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "Avancement de l'analyse" })).toHaveAttribute("value", "2");
    const dnsTile = screen.getByRole("group", { name: "DNS & sous-domaines : 2/4 modules" });
    expect(within(dnsTile).getAllByText("Mesuré")).toHaveLength(2);
    expect(within(dnsTile).getAllByText("En cours")).toHaveLength(2);
    act(() => handle.emit({ event: "done", data: { scan_id: 42 } }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("/scans/42"));
  });

  it("annonce d'emblée le nombre de modules du plan de la tâche, sans passer par 18", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: { ...job, total: 56 } });
    renderLive();
    // Avant tout événement du flux : le total vient de l'état de la tâche.
    expect(await screen.findByText("0 modules sur 56")).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "Avancement de l'analyse" })).toHaveAttribute("max", "56");
    expect(screen.queryByText(/sur 18/)).not.toBeInTheDocument();
    act(() => {
      handle.emit(moduleEvent("dns_records"));
      handle.emit({ event: "progress", data: { done: 1, total: 56 } });
    });
    expect(screen.getByText("1 modules sur 56")).toBeInTheDocument();
  });

  it("annule le scan à la demande", async () => {
    const handle = openStream();
    const { calls } = mockFetch({
      [`GET /api/scans/${JOB}`]: job,
      [`POST /api/scans/${JOB}/cancel`]: () => jsonResponse({ id: JOB, status: "cancelled" }, 202),
    });
    const { user } = renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    act(() => handle.emit(moduleEvent("cors")));
    await user.click(screen.getByRole("button", { name: "Annuler" }));
    expect(calls.some((call) => call.method === "POST" && call.url.pathname === `/api/scans/${JOB}/cancel`)).toBe(true);
    act(() => handle.emit({ event: "cancelled", data: {} }));
    expect(await screen.findByText("Analyse annulée")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Nouveau scan" })).toHaveAttribute("href", "/");
    expect(screen.queryByRole("button", { name: "Annuler" })).not.toBeInTheDocument();
  });

  it("signale l'échec du scan avec le message du serveur", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: job });
    renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    act(() =>
      handle.emit({ event: "failed", data: { code: "scan.internal_error", params: {}, detail: "Erreur interne du scanner" } }),
    );
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("L'analyse a échoué");
    expect(alert).toHaveTextContent("Erreur interne du scanner");
    expect(within(alert).getByRole("button", { name: "Relancer" })).toBeInTheDocument();
  });

  it("tâche introuvable (serveur redémarré) : message et sortie, pas d'écran blanc", async () => {
    stream.mockRejectedValue(new ApiError(404, "Tâche inconnue"));
    mockFetch({ [`GET /api/scans/${JOB}`]: () => jsonResponse({ detail: "Tâche inconnue", code: null, params: {} }, 404) });
    renderLive();
    expect(await screen.findByText("Suivi de l'analyse interrompu")).toBeInTheDocument();
    expect(
      screen.getByText("Tâche introuvable : le serveur a peut-être redémarré. Consultez l'historique ou relancez l'analyse."),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Voir l'historique" })).toHaveAttribute("href", "/history");
  });

  it("se reconnecte seul et ne compte pas deux fois les événements rejoués", async () => {
    stream
      .mockImplementationOnce(async (_id: string, options: StreamOptions) => {
        options.onEvent(moduleEvent("dns_records"));
        options.onEvent(moduleEvent("cors"));
        return "closed";
      })
      .mockImplementationOnce((_id: string, options: StreamOptions) => {
        options.onEvent(moduleEvent("dns_records"));
        options.onEvent(moduleEvent("cors"));
        options.onEvent(moduleEvent("waf"));
        return new Promise<"closed">(() => undefined);
      });
    mockFetch({ [`GET /api/scans/${JOB}`]: job });
    renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalledTimes(2), { timeout: 3000 });
    expect(await screen.findByText("3 modules sur 18")).toBeInTheDocument();
    // Les événements rejoués ne comptent pas deux fois : trois modules mesurés, pas cinq.
    expect(screen.getAllByText("Mesuré")).toHaveLength(3);
  });

  it("Relancer après un échec repart d'un état neuf et recharge l'historique", async () => {
    const handle = openStream();
    const { calls } = mockFetch({
      [`GET /api/scans/${JOB}`]: job,
      [`GET /api/scans/${JOB2}`]: { ...job, id: JOB2 },
      "POST /api/scans": () => jsonResponse({ id: JOB2, status: "queued" }, 202),
    });
    const { user, queryClient } = renderLive();
    queryClient.setQueryData(["history", "list"], { total: 0, scans: [] });
    await waitFor(() => expect(stream).toHaveBeenCalled());
    act(() => {
      handle.emit(moduleEvent("cors"));
      handle.emit({ event: "progress", data: { done: 1, total: 18 } });
      handle.emit({ event: "failed", data: { code: null, params: {}, detail: "Erreur interne du scanner" } });
    });
    await screen.findByRole("alert");
    expect(queryClient.getQueryState(["history", "list"])?.isInvalidated).toBe(true);
    await user.click(screen.getByRole("button", { name: "Relancer" }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent(`/scans/live/${JOB2}`));
    expect(calls.some((call) => call.method === "POST" && call.url.pathname === "/api/scans")).toBe(true);
    await waitFor(() => expect(stream).toHaveBeenLastCalledWith(JOB2, expect.anything()));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByText("0 modules sur 18")).toBeInTheDocument();
    expect(screen.queryByText("Mesuré")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Annuler" })).toBeInTheDocument();
  });

  it("lien profond mal formé : message clair avec un titre de niveau 1, sans appel au serveur", () => {
    const { calls } = mockFetch({});
    renderWithProviders(<LiveScanPage />, { route: "/scans/live/abc", path: "/scans/live/:jobId" });
    expect(screen.getByRole("heading", { level: 1, name: "Tâche introuvable" })).toBeInTheDocument();
    expect(screen.getByText(/l'identifiant de la tâche est mal formé/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Voir l'historique" })).toHaveAttribute("href", "/history");
    expect(screen.getByRole("link", { name: "Nouveau scan" })).toHaveAttribute("href", "/");
    expect(screen.queryByText(/Requête invalide|job_id/)).not.toBeInTheDocument();
    expect(calls).toHaveLength(0);
    expect(stream).not.toHaveBeenCalled();
    expect(document.title).toBe("Tâche introuvable · DomainRecon");
  });

  it("identifiant refusé par le serveur (422) : même message que « tâche introuvable »", async () => {
    stream.mockRejectedValue(new ApiError(422, "Requête invalide (job_id)"));
    mockFetch({ [`GET /api/scans/${JOB}`]: () => jsonResponse({ detail: "Requête invalide (job_id)" }, 422) });
    renderLive();
    expect(await screen.findByText("Suivi de l'analyse interrompu")).toBeInTheDocument();
    expect(screen.getByText(/Tâche introuvable : le serveur a peut-être redémarré/)).toBeInTheDocument();
    expect(screen.queryByText(/Requête invalide/)).not.toBeInTheDocument();
  });

  it("annulation acceptée (202) : le bouton reste désactivé jusqu'à l'événement final", async () => {
    const handle = openStream();
    mockFetch({
      [`GET /api/scans/${JOB}`]: job,
      [`POST /api/scans/${JOB}/cancel`]: () => jsonResponse({ id: JOB, status: "running" }, 202),
    });
    const { user } = renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    await user.click(screen.getByRole("button", { name: "Annuler" }));
    const waiting = await screen.findByRole("button", { name: "Annulation…" });
    expect(waiting).toBeDisabled();
    // Pas de second envoi possible avant l'événement final.
    await user.click(waiting);
    expect(waiting).toBeDisabled();
    act(() => handle.emit({ event: "cancelled", data: {} }));
    expect(await screen.findByText("Analyse annulée")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Annul/ })).not.toBeInTheDocument();
  });

  it("annulation d'une tâche déjà terminée (409) : aucune erreur affichée, l'événement final suit", async () => {
    const handle = openStream();
    const { calls } = mockFetch({
      [`GET /api/scans/${JOB}`]: job,
      [`POST /api/scans/${JOB}/cancel`]: () => jsonResponse({ detail: "Tâche déjà terminée", code: null, params: {} }, 409),
    });
    const { user } = renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    await user.click(screen.getByRole("button", { name: "Annuler" }));
    await waitFor(() => expect(calls.some((call) => call.method === "POST")).toBe(true));
    expect(await screen.findByRole("button", { name: "Annulation…" })).toBeDisabled();
    expect(screen.queryByText(/Annulation impossible/)).not.toBeInTheDocument();
    expect(screen.queryByText("Tâche déjà terminée")).not.toBeInTheDocument();
    act(() => handle.emit({ event: "done", data: { scan_id: 42 } }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("/scans/42"));
  });

  it("une autre erreur d'annulation reste signalée par une notification", async () => {
    openStream();
    mockFetch({
      [`GET /api/scans/${JOB}`]: job,
      [`POST /api/scans/${JOB}/cancel`]: () => jsonResponse({ detail: "Base verrouillée", code: null, params: {} }, 500),
    });
    const { user } = renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    await user.click(screen.getByRole("button", { name: "Annuler" }));
    expect(await screen.findByText("Annulation impossible : Base verrouillée")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Annuler" })).toBeEnabled();
  });

  it("échec connu puis tâche introuvable : jamais « échec » et « suivi interrompu » ensemble", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: () => jsonResponse({ detail: "Tâche inconnue", code: null, params: {} }, 404) });
    renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    act(() => handle.emit({ event: "failed", data: { code: null, params: {}, detail: "Erreur interne du scanner" } }));
    expect(await screen.findByText("L'analyse a échoué")).toBeInTheDocument();
    // Laisse la lecture de l'état de la tâche (404) se terminer.
    await waitFor(() => expect(screen.queryByText("Connexion au suivi de l'analyse…")).not.toBeInTheDocument());
    expect(screen.queryByText("Suivi de l'analyse interrompu")).not.toBeInTheDocument();
    expect(screen.getAllByRole("alert")).toHaveLength(1);
  });

  it("recharge aussi les timelines à la fin de la tâche", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: job });
    const { queryClient } = renderLive();
    queryClient.setQueryData(["timeline", "example.com", "fr"], { domain: "example.com", timeline: [] });
    await waitFor(() => expect(stream).toHaveBeenCalled());
    act(() => handle.emit({ event: "cancelled", data: {} }));
    await screen.findByText("Analyse annulée");
    expect(queryClient.getQueryState(["timeline", "example.com", "fr"])?.isInvalidated).toBe(true);
  });

  it("une seule barre de progression : texte « n modules sur N », module en cours et chronomètre", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: job });
    const { container } = renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    // Avant le premier module : 0 sur 18, attente du premier module, chronomètre à zéro.
    expect(screen.getByText("0 modules sur 18")).toBeInTheDocument();
    expect(screen.getByText("En attente du premier module…")).toBeInTheDocument();
    const clock = screen.getByText("0:00");
    expect(clock.tagName).toBe("TIME");
    expect(clock).toHaveAttribute("datetime", "PT0S");
    // Une seule barre, pas de compteur géant ni de cartes de chiffres.
    expect(screen.getAllByRole("progressbar")).toHaveLength(1);
    expect(container.querySelector("[data-variant]")).toBeNull();

    act(() => {
      handle.emit(moduleEvent("dns_records"));
      handle.emit(moduleEvent("subdomains"));
    });
    expect(screen.getByText("2 modules sur 18")).toBeInTheDocument();
    // Module en cours : le premier module qui n'est pas terminé, puis le nombre de ceux qui suivent.
    const current = container.querySelector("[data-kind]") as HTMLElement;
    expect(current).toHaveAttribute("data-kind", "running");
    expect(current).toHaveTextContent("En cours");
    expect(current).toHaveTextContent("En-têtes de sécurité");
    expect(current).toHaveTextContent("+15");
    expect(screen.queryByText("En attente du premier module…")).not.toBeInTheDocument();
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("le chronomètre avance à la seconde, en m:ss, et s'arrête avec la tâche", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: job });
    // Seules la minuterie et l'horloge sont simulées (les attentes de Testing Library restent réelles).
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    try {
      renderLive();
      expect(screen.getByText("0:00")).toHaveAttribute("datetime", "PT0S");
      act(() => {
        vi.advanceTimersByTime(65_000);
      });
      expect(screen.getByText("1:05")).toHaveAttribute("datetime", "PT1M5S");
      act(() => handle.emit({ event: "cancelled", data: {} }));
      act(() => {
        vi.advanceTimersByTime(30_000);
      });
      // La tâche est terminée : le chronomètre garde sa dernière valeur.
      expect(screen.getByText("1:05")).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("tout est terminé mais l'événement final n'est pas arrivé : « Finalisation… »", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: job });
    renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    act(() => {
      for (const name of MODULE_NAMES) handle.emit(moduleEvent(name));
    });
    expect(screen.getByText("Finalisation…")).toBeInTheDocument();
    expect(screen.getByText("18 modules sur 18")).toBeInTheDocument();
    expect(screen.getAllByText("Mesuré")).toHaveLength(18);
  });

  it("annulée : plus de module en cours ni de bouton, la barre est grisée, ce qui était terminé reste listé", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: job });
    const { container } = renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    act(() => handle.emit(moduleEvent("cors")));
    act(() => handle.emit({ event: "cancelled", data: {} }));
    await screen.findByText("Analyse annulée");
    const current = container.querySelector("[data-kind]") as HTMLElement;
    expect(current).toHaveAttribute("data-kind", "none");
    expect(current).toBeEmptyDOMElement();
    expect(container.querySelector("[data-phase]")).toHaveAttribute("data-phase", "cancelled");
    expect(screen.queryByRole("button", { name: /Annul/ })).not.toBeInTheDocument();
    expect(screen.getAllByText("Mesuré")).toHaveLength(1);
  });

  it("échec : bandeau d'alerte unique, barre grisée", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: job });
    const { container } = renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    act(() => handle.emit({ event: "failed", data: { code: null, params: {}, detail: "Erreur interne du scanner" } }));
    await screen.findByRole("alert");
    expect(container.querySelector("[data-phase]")).toHaveAttribute("data-phase", "failed");
    expect(screen.getAllByRole("alert")).toHaveLength(1);
  });

  it("modules par famille : une ligne par module avec icône, statut en texte et durée", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: job });
    const { container } = renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    // Au départ : tous les modules sont en cours, aucune durée.
    expect(screen.queryByText("Mesuré")).not.toBeInTheDocument();
    expect((await screen.findAllByText(/^(En cours|En attente)$/)).length).toBeGreaterThan(10);

    act(() => {
      handle.emit(moduleEvent("cors", "ok", 0.123));
      handle.emit(moduleEvent("waf", "timeout", 60));
      handle.emit(moduleEvent("whois_data", "skipped", 0.5));
      handle.emit(moduleEvent("dns_records", "failed", 12.34));
    });
    const row = (name: string) => screen.getByText(name).closest("li") as HTMLElement;
    expect(row("CORS")).toHaveAttribute("data-status", "ok");
    expect(within(row("CORS")).getByText("Mesuré")).toBeInTheDocument();
    expect(within(row("CORS")).getByText("0,12 s")).toBeInTheDocument();
    expect(row("WAF / CDN")).toHaveAttribute("data-status", "timeout");
    expect(within(row("WAF / CDN")).getByText("Non mesuré (délai dépassé)")).toBeInTheDocument();
    expect(within(row("WAF / CDN")).getByText("60 s")).toBeInTheDocument();
    expect(row("WHOIS")).toHaveAttribute("data-status", "skipped");
    expect(within(row("WHOIS")).getByText("Sans objet")).toBeInTheDocument();
    expect(within(row("WHOIS")).getByText("0,5 s")).toBeInTheDocument();
    expect(row("Enregistrements DNS")).toHaveAttribute("data-status", "failed");
    expect(within(row("Enregistrements DNS")).getByText("Non mesuré (échec du module)")).toBeInTheDocument();
    expect(within(row("Enregistrements DNS")).getByText("12,3 s")).toBeInTheDocument();
    // Chaque ligne a son icône (décorative) : la couleur ne dit jamais seule le statut.
    expect(row("CORS").querySelector("svg")).toHaveAttribute("aria-hidden", "true");
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("un module inconnu du catalogue compte dans l'avancement", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: job });
    renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    act(() =>
      handle.emit({
        event: "module",
        data: { name: "future_module" as ModuleName, family: "web", status: "ok", duration: 1.5 },
      }),
    );
    // Le module annoncé est listé sous sa famille, sous son nom lisible.
    const row = screen.getByText("Future module").closest("li") as HTMLElement;
    expect(within(row).getByText("1,5 s")).toBeInTheDocument();
    expect(screen.getByText("1 modules sur 18")).toBeInTheDocument();
  });

  it("familles en listes à filets : un titre par famille, sans carte ni cascade", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: job });
    renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    act(() => handle.emit(moduleEvent("cors")));
    const section = screen.getByRole("region", { name: "Avancement par famille" });
    expect(within(section).getByText("Familles")).toBeInTheDocument();
    // La première liste de la section est celle des familles (les suivantes sont celles de leurs modules).
    const list = within(section).getAllByRole("list")[0];
    expect(list.className).not.toMatch(/stagger/);
    expect(list.children).toHaveLength(8);
    // Famille : titre de niveau 3, état dit en texte, identité décorative portée par un attribut.
    const web = within(section).getByRole("group", { name: /^Web : / });
    expect(web).toHaveAttribute("data-family", "web");
    expect(web).toHaveAttribute("data-state", "running");
    expect(within(web).getByRole("heading", { level: 3, name: "Web" })).toBeInTheDocument();
  });

  it("la barre d'avancement porte la même valeur que le texte", async () => {
    const handle = openStream();
    mockFetch({ [`GET /api/scans/${JOB}`]: job });
    renderLive();
    await waitFor(() => expect(stream).toHaveBeenCalled());
    act(() => {
      handle.emit(moduleEvent("dns_records"));
      handle.emit({ event: "progress", data: { done: 1, total: 18 } });
    });
    const bar = screen.getByRole("progressbar", { name: "Avancement de l'analyse" });
    expect(bar).toHaveAttribute("value", "1");
    expect(bar).toHaveAttribute("max", "18");
    expect(bar).toHaveAttribute("aria-valuetext", "1 modules sur 18");
  });
});
