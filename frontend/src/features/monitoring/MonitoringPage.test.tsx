import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { NotificationItem, Watch } from "../../api/ops";
import { jsonResponse, mockFetch } from "../../test/fetchMock";
import { renderWithProviders } from "../../test/render";
import { MonitoringPage } from "./MonitoringPage";

function watch(overrides: Partial<Watch> = {}): Watch {
  return {
    id: 1,
    domain: "example.com",
    profile: "complet",
    selected: null,
    authorized_target: false,
    frequency: "weekly",
    enabled: true,
    next_run_at: "2026-09-25T10:00:00Z",
    last_run_at: "2026-09-18T10:00:00Z",
    last_scan_id: 42,
    last_status: "ok",
    last_error: null,
    rules: { grade_drop: true, new_findings: true, cert_expiry_days: 14, new_port: false, new_subdomain: true },
    channels: ["center"],
    lang: "fr",
    created_at: "2026-09-01T10:00:00Z",
    ...overrides,
  };
}

function notification(overrides: Partial<NotificationItem> = {}): NotificationItem {
  return {
    id: 5,
    created_at: "2026-09-18T11:00:00Z",
    domain: "example.com",
    scan_id: 42,
    watch_id: 1,
    rule: "grade_drop",
    severity: "high",
    message: "La note passe de B à D",
    is_read: false,
    delivery: {},
    ...overrides,
  };
}

const task = { supported: true, platform: "windows", installed: false, command: "domainrecon monitor run-due" };
const catalog = { "GET /api/modules": { modules: [], families: [] } };

function render(route = "/monitoring") {
  return renderWithProviders(<MonitoringPage />, { route, path: "/monitoring" });
}

describe("Surveillance", () => {
  it("sans surveillance : explique quoi faire et propose le formulaire d'ajout", async () => {
    mockFetch({
      ...catalog,
      "GET /api/watches": { watches: [] },
      "GET /api/notifications": { total: 0, unread: 0, items: [] },
      "GET /api/monitor/task": task,
    });
    render();
    expect(await screen.findByText("Aucune surveillance")).toBeInTheDocument();
    expect(screen.getByRole("form", { name: "Ajouter une surveillance" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Surveiller ce domaine" })).toBeDisabled();
  });

  it("liste les surveillances et modifie fréquence, état, règles et canaux", async () => {
    const { calls } = mockFetch({
      ...catalog,
      "GET /api/watches": { watches: [watch()] },
      "PATCH /api/watches/1": () => jsonResponse(watch()),
      "GET /api/notifications": { total: 0, unread: 0, items: [] },
      "GET /api/monitor/task": task,
    });
    const { user } = render();
    const table = await screen.findByRole("table", { name: "Domaines surveillés" });
    expect(within(table).getByText("example.com")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Fréquence de example.com"), "daily");
    await waitFor(() => expect(calls.filter((call) => call.method === "PATCH")).toHaveLength(1));
    expect(JSON.parse(String(calls.find((call) => call.method === "PATCH")?.init.body))).toEqual({ frequency: "daily" });

    await user.click(within(table).getByRole("checkbox", { name: "Active" }));
    await waitFor(() => expect(calls.filter((call) => call.method === "PATCH")).toHaveLength(2));
    expect(JSON.parse(String(calls.filter((call) => call.method === "PATCH")[1].init.body))).toEqual({ enabled: false });

    await user.click(screen.getByRole("button", { name: "Modifier" }));
    const editor = within(table);
    expect(editor.getByRole("checkbox", { name: "Un nouveau port s'ouvre" })).not.toBeChecked();
    await user.click(editor.getByRole("checkbox", { name: "Un nouveau port s'ouvre" }));
    await user.click(editor.getByRole("checkbox", { name: "Slack" }));
    await user.click(editor.getByRole("button", { name: "Enregistrer" }));
    await waitFor(() => expect(calls.filter((call) => call.method === "PATCH")).toHaveLength(3));
    const saved = JSON.parse(String(calls.filter((call) => call.method === "PATCH")[2].init.body));
    expect(saved.rules).toEqual({ grade_drop: true, new_findings: true, cert_expiry_days: 14, new_port: true, new_subdomain: true });
    expect(saved.channels).toEqual(["center", "slack"]);
  });

  it("ajoute une surveillance avec règles, canaux et fréquence", async () => {
    const { calls } = mockFetch({
      ...catalog,
      "GET /api/watches": { watches: [] },
      "POST /api/watches": () => jsonResponse(watch({ domain: "new.example.org" }), 201),
      "GET /api/notifications": { total: 0, unread: 0, items: [] },
      "GET /api/monitor/task": task,
    });
    const { user } = render();
    await screen.findByText("Aucune surveillance");
    await user.type(screen.getByLabelText("Domaine à surveiller"), "new.example.org");
    await user.selectOptions(screen.getByLabelText("Fréquence"), "monthly");
    const form = screen.getByRole("form", { name: "Ajouter une surveillance" });
    await user.click(within(form).getByRole("checkbox", { name: "Un nouveau sous-domaine apparaît" }));
    await user.click(within(form).getByRole("checkbox", { name: "Discord" }));
    await user.click(within(form).getByRole("button", { name: "Surveiller ce domaine" }));
    expect(await screen.findByText("new.example.org est maintenant surveillé")).toBeInTheDocument();
    const post = calls.find((call) => call.method === "POST" && call.url.pathname === "/api/watches");
    expect(JSON.parse(String(post?.init.body))).toEqual({
      domain: "new.example.org",
      frequency: "monthly",
      rules: { grade_drop: true, new_findings: true, cert_expiry_days: 14, new_port: true, new_subdomain: false },
      channels: ["center", "discord"],
      lang: "fr",
      profile: "complet",
    });
  });

  it("installe puis désinstalle la tâche système, ou dit qu'elle n'est pas prise en charge", async () => {
    const { calls } = mockFetch({
      ...catalog,
      "GET /api/watches": { watches: [] },
      "GET /api/notifications": { total: 0, unread: 0, items: [] },
      "GET /api/monitor/task": task,
      "POST /api/monitor/task/install": () => jsonResponse({ ...task, installed: true }),
    });
    const { user } = render();
    expect(await screen.findByText("Non installée")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Installer la tâche" }));
    await waitFor(() => expect(calls.some((call) => call.url.pathname === "/api/monitor/task/install")).toBe(true));
    expect(await screen.findByText("Tâche système installée")).toBeInTheDocument();
  });

  it.each([
    ["install", "Installer la tâche", "Non installée", { ...task, installed: false }],
    ["uninstall", "Désinstaller la tâche", "Installée", { ...task, installed: true }],
  ])(
    "%s depuis une autre machine : le refus 403 est dit comme une règle (avertissement), pas comme une panne",
    async (action, label, state, current) => {
      const refusal = "Action réservée à l'utilisateur de cette machine";
      const { calls } = mockFetch({
        ...catalog,
        "GET /api/watches": { watches: [] },
        "GET /api/notifications": { total: 0, unread: 0, items: [] },
        "GET /api/monitor/task": current,
        [`POST /api/monitor/task/${action}`]: () => jsonResponse({ detail: refusal, code: "api.local_only", params: {} }, 403),
      });
      const { user } = render();
      expect(await screen.findByText(state)).toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: label }));
      const message = await screen.findAllByText(refusal);
      // Notification d'avertissement et rappel dans la carte : aucune alerte d'erreur.
      expect(message.map((node) => node.closest("[data-tone]")?.getAttribute("data-tone"))).toContain("warning");
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
      // Le corps JSON `{}` part toujours (sans lui, le serveur répond 415).
      const post = calls.find((call) => call.method === "POST");
      expect(new Headers(post?.init.headers).get("Content-Type")).toBe("application/json");
      expect(post?.init.body).toBe("{}");
      // L'état de la tâche reste celui d'avant : rien n'a été installé ni retiré.
      expect(screen.getByText(state)).toBeInTheDocument();
    },
  );

  it("tâche système non prise en charge", async () => {
    mockFetch({
      ...catalog,
      "GET /api/watches": { watches: [] },
      "GET /api/notifications": { total: 0, unread: 0, items: [] },
      "GET /api/monitor/task": { supported: false, platform: "other", installed: false, command: null },
    });
    render();
    expect(await screen.findByText(/ne permet pas d'installer la tâche/)).toBeInTheDocument();
  });

  it("centre de notifications : non lues, marquer comme lu, supprimer, vider", async () => {
    const { calls } = mockFetch({
      ...catalog,
      "GET /api/watches": { watches: [] },
      "GET /api/notifications": { total: 2, unread: 1, items: [notification(), notification({ id: 6, is_read: true, message: "Port ouvert", severity: "low" })] },
      "GET /api/monitor/task": task,
      "POST /api/notifications/read": () => jsonResponse({ updated: 1 }),
      "DELETE /api/notifications/6": () => jsonResponse({ id: 6 }),
      "DELETE /api/notifications": () => jsonResponse({ deleted: 2 }),
    });
    const { user } = render("/monitoring?tab=notifications");
    expect(await screen.findByText("1 non lue(s)")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Notifications/ })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText(/La note passe de B à D/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Tout marquer comme lu" }));
    await waitFor(() => expect(calls.some((call) => call.url.pathname === "/api/notifications/read")).toBe(true));
    await user.click(screen.getAllByRole("button", { name: "Supprimer l'alerte de example.com" })[1]);
    await user.click(screen.getByRole("button", { name: "Vider" }));
    await waitFor(() => expect(calls.some((call) => call.method === "DELETE" && call.url.search === "?all=true")).toBe(true));
  });

  it("notifications vides : explique d'où viendront les alertes", async () => {
    mockFetch({
      ...catalog,
      "GET /api/watches": { watches: [] },
      "GET /api/notifications": { total: 0, unread: 0, items: [] },
      "GET /api/monitor/task": task,
    });
    render("/monitoring?tab=notifications");
    expect(await screen.findByText("Aucune notification")).toBeInTheDocument();
  });
});
