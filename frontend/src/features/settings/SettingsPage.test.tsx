import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { setToken } from "../../api/client";
import { jsonResponse, type MockHandler, mockFetch } from "../../test/fetchMock";
import { renderWithProviders } from "../../test/render";
import { SettingsPage } from "./SettingsPage";

const info = { version: "1.0.0", data_dir: "C:\\Users\\alice\\AppData\\Local\\DomainRecon", portable: false, frozen: true };

const settings = {
  api_keys: { shodan_key: "sk-…1234", censys_id: "", censys_secret: "" },
  scan_timeout: 120,
  quick_timeout: 30,
  screenshot_enabled: true,
  proxy_url: "",
};
const modules = {
  modules: [
    {
      name: "shodan",
      family: "network",
      category: "cle_api",
      requires_authorization: false,
      key_tests: [],
      keys: [{ name: "shodan_key", service: "shodan", label: "Shodan", required: false, free_text: false, hidden: false, configured: true }],
      help: { title: "Shodan", checks: "", why: "" },
    },
    {
      name: "censys",
      family: "network",
      category: "cle_api",
      requires_authorization: false,
      key_tests: [],
      keys: [
        { name: "censys_secret", service: "censys", label: "Censys", required: true, free_text: false, hidden: false, configured: false },
        { name: "censys_id", service: "censys", label: "Censys ID", required: false, free_text: true, hidden: false, configured: false },
      ],
      help: { title: "Censys", checks: "", why: "" },
    },
  ],
  families: ["network"],
};
const channels = {
  channels: [
    { name: "discord", enabled: true, configured: true, config: { url: "https://discord.com/…" } },
    { name: "slack", enabled: false, configured: false, config: {} },
    { name: "teams", enabled: false, configured: false, config: {} },
    { name: "webhook", enabled: false, configured: false, config: {} },
    { name: "email", enabled: false, configured: false, config: { security: "starttls", port: 587 } },
    { name: "desktop", enabled: false, configured: true, config: {} },
  ],
};
const vpn = { connected: true, ip: "185.1.2.3", country: "Suède", provider: "Mullvad", mullvad_cli: true, message: "Connecté à Mullvad" };
const extra = {
  "GET /api/settings": settings,
  "GET /api/modules": modules,
  "GET /api/notify/channels": channels,
  "GET /api/system/vpn": vpn,
};

function renderSettings(openStatus = 204, more: Record<string, MockHandler> = {}) {
  const result = mockFetch({
    ...extra,
    ...more,
    "GET /api/system/info": info,
    "POST /api/system/open-data-dir": () =>
      openStatus === 204
        ? new Response(null, { status: 204 })
        : jsonResponse({ detail: "Action réservée à l'utilisateur de cette machine", code: "api.local_only", params: {} }, openStatus),
  });
  return { ...renderWithProviders(<SettingsPage />, { route: "/settings", path: "/settings" }), calls: result.calls };
}

describe("écran Réglages", () => {
  it("change la langue de l'interface et la mémorise", async () => {
    const { user } = renderSettings();
    expect(screen.getByRole("heading", { level: 1, name: "Réglages" })).toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: "English" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Settings" })).toBeInTheDocument();
    expect(window.localStorage.getItem("domainrecon.lang")).toBe("en");
    expect(screen.getByRole("radio", { name: "English" })).toBeChecked();
  });

  it("affiche le dossier des données et l'ouvre", async () => {
    const { user, calls } = renderSettings();
    expect(await screen.findByText(info.data_dir)).toBeInTheDocument();
    expect(screen.getByText("DomainRecon 1.0.0")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Ouvrir" }));
    expect(await screen.findByText("Dossier des données ouvert")).toBeInTheDocument();
    const post = calls.find((call) => call.method === "POST");
    expect(new Headers(post?.init.headers).get("Content-Type")).toBe("application/json");
  });

  it("explique un refus d'ouverture", async () => {
    const { user } = renderSettings(403);
    await screen.findByText(info.data_dir);
    await user.click(screen.getByRole("button", { name: "Ouvrir" }));
    const toast = await screen.findByText("Ouverture impossible : Action réservée à l'utilisateur de cette machine");
    expect(toast).toBeInTheDocument();
    // Une règle de l'application (requête d'une autre machine), pas une panne : avertissement, pas erreur.
    expect(toast.closest("[data-tone]")).toHaveAttribute("data-tone", "warning");
  });

  it("gère le jeton d'API : saisie et oubli", async () => {
    const { user } = renderSettings();
    expect(screen.getByText("Aucun jeton enregistré (nécessaire seulement si le serveur définit API_TOKEN).")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Saisir le jeton" }));
    expect(screen.getByRole("dialog", { name: "Jeton d'API" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    setToken("abc");
    await waitFor(() => expect(screen.getByText("Un jeton est enregistré pour cet onglet.")).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: "Oublier le jeton" }));
    expect(window.sessionStorage.getItem("domainrecon.token")).toBeNull();
    expect(await screen.findByText("Jeton d'API oublié")).toBeInTheDocument();
  });

  // Serveur qui exige le jeton « abc » : sans lui, /api/system/info répond 401.
  function renderGuarded() {
    setToken("abc");
    const result = mockFetch({
      "GET /api/system/info": ({ init }) =>
        new Headers(init.headers).get("X-API-Token") === "abc"
          ? jsonResponse(info)
          : jsonResponse({ detail: "Jeton requis", code: null, params: {} }, 401),
    });
    return { ...renderWithProviders(<SettingsPage />, { route: "/settings", path: "/settings" }), calls: result.calls };
  }

  it("oublier le jeton depuis la page retire les données reçues avec lui", async () => {
    const { user } = renderGuarded();
    expect(await screen.findByText(info.data_dir)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Oublier le jeton" }));
    await waitFor(() => expect(screen.queryByText(info.data_dir)).not.toBeInTheDocument());
    // Relecture sans jeton : le serveur refuse, la saisie du jeton est proposée.
    expect(await screen.findByRole("dialog", { name: "Jeton d'API" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(await screen.findByText(/Informations du serveur indisponibles : Jeton requis/)).toBeInTheDocument();
    expect(screen.queryByText(info.data_dir)).not.toBeInTheDocument();
  });

  it("oublier le jeton depuis la boîte de saisie retire aussi les données reçues avec lui", async () => {
    const { user } = renderGuarded();
    expect(await screen.findByText(info.data_dir)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Saisir le jeton" }));
    await user.click(within(screen.getByRole("dialog", { name: "Jeton d'API" })).getByRole("button", { name: "Oublier le jeton" }));
    await waitFor(() => expect(screen.queryByText(info.data_dir)).not.toBeInTheDocument());
    // clear() ne prévient pas les vues montées : la page relit d'elle-même (le jeton a changé), sans jeton.
    expect(await screen.findByRole("dialog", { name: "Jeton d'API" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(await screen.findByText(/Informations du serveur indisponibles : Jeton requis/)).toBeInTheDocument();
    expect(screen.queryByText(info.data_dir)).not.toBeInTheDocument();
  });

  it("liste les licences des composants", async () => {
    renderSettings();
    const licenses = screen.getByRole("table", { name: "Licences" });
    expect(within(licenses).getByText("d3-geo, topojson-client").closest("tr")).toHaveTextContent("ISC");
    expect(within(licenses).getByText("Inter, JetBrains Mono").closest("tr")).toHaveTextContent("OFL-1.1");
    // Les anciennes polices et la cartographie en ligne (Leaflet, CARTO, OpenStreetMap) ne sont plus listées.
    expect(within(licenses).queryByText(/Hanken|Plex|Leaflet|CARTO|OpenStreetMap/)).not.toBeInTheDocument();
    // Carte du monde embarquée : attribution Natural Earth (domaine public).
    expect(within(licenses).getByText(/Natural Earth 1:110m/).closest("tr")).toHaveTextContent("Public domain");
    // En-têtes de colonnes : le tableau est lisible par un lecteur d'écran.
    expect(within(licenses).getByRole("columnheader", { name: "Composant" })).toBeInTheDocument();
    expect(within(licenses).getByRole("columnheader", { name: "Licence" })).toBeInTheDocument();
    expect(within(licenses).getByRole("rowheader", { name: "d3-geo, topojson-client" })).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "Documentation de l'API" })).toHaveAttribute("href", "/api/docs");
  });

  it("masque le lien de la documentation quand le serveur l'a désactivée (docs_enabled: false)", async () => {
    mockFetch({ "GET /api/system/info": { ...info, docs_enabled: false } });
    renderWithProviders(<SettingsPage />, { route: "/settings", path: "/settings" });
    await screen.findByText("DomainRecon 1.0.0");
    expect(screen.queryByRole("link", { name: "Documentation de l'API" })).not.toBeInTheDocument();
  });

  it("garde le lien quand docs_enabled est vrai", async () => {
    mockFetch({ "GET /api/system/info": { ...info, docs_enabled: true } });
    renderWithProviders(<SettingsPage />, { route: "/settings", path: "/settings" });
    expect(await screen.findByRole("link", { name: "Documentation de l'API" })).toBeInTheDocument();
  });

  it("clés d'API : un champ masqué par service, lu depuis le catalogue, état enregistré ou absent", async () => {
    renderSettings();
    const region = screen.getByRole("region", { name: "Clés API" });
    expect(await within(region).findByLabelText("Shodan")).toBeInTheDocument();
    expect(within(region).getByText("Clé enregistrée")).toBeInTheDocument();
    expect(within(region).getByText("Pas de clé")).toBeInTheDocument();
    const shodan = within(region).getByLabelText("Shodan");
    expect(shodan).toHaveAttribute("type", "password");
    // La valeur enregistrée ne revient que masquée par le serveur, jamais dans le champ.
    expect(shodan).toHaveValue("");
    expect(shodan).toHaveAttribute("placeholder", "sk-…1234");
    expect(within(region).getByLabelText("Censys ID")).toHaveAttribute("type", "password");
    expect(region).toHaveAttribute("data-slot", "api-keys");
  });

  it("clés d'API : enregistre seulement les clés saisies, supprime une clé, teste un service", async () => {
    const { user, calls } = renderSettings(204, {
      "PUT /api/settings": () => jsonResponse(settings),
      "POST /api/settings/test/shodan": () => jsonResponse({ service: "shodan", success: true, message: "Clé valide" }),
      "POST /api/settings/test/censys": () => jsonResponse({ service: "censys", success: false, message: "Clé refusée" }),
    });
    const region = screen.getByRole("region", { name: "Clés API" });
    const save = await within(region).findByRole("button", { name: "Enregistrer les clés" });
    expect(save).toBeDisabled();
    await user.type(within(region).getByLabelText("Censys"), " cs-secret ");
    await user.click(within(region).getAllByRole("button", { name: "Supprimer" })[0]);
    await user.click(save);
    await waitFor(() => expect(calls.some((call) => call.method === "PUT" && call.url.pathname === "/api/settings")).toBe(true));
    const put = calls.find((call) => call.method === "PUT" && call.url.pathname === "/api/settings");
    expect(JSON.parse(String(put?.init.body))).toEqual({ api_keys: { censys_secret: "cs-secret", shodan_key: "" } });
    expect(await screen.findByText("Clés d'API enregistrées")).toBeInTheDocument();
    await user.click(within(region).getAllByRole("button", { name: "Tester" })[0]);
    expect(await within(region).findByText(/Clé refusée/)).toBeInTheDocument();
    await user.click(within(region).getAllByRole("button", { name: "Tester" })[1]);
    expect(await within(region).findByText(/Clé valide/)).toBeInTheDocument();
  });

  it("délais, capture d'écran et proxy : valide les bornes, enregistre, rappelle que le DNS ne passe pas par le proxy", async () => {
    const { user, calls } = renderSettings(204, { "PUT /api/settings": () => jsonResponse(settings) });
    const region = screen.getByRole("region", { name: "Délais, capture et proxy" });
    const scan = await within(region).findByLabelText("Délai du scan complet (s)");
    expect(scan).toHaveValue(120);
    expect(within(region).getByRole("checkbox", { name: "Prendre une capture d'écran du site" })).toBeChecked();
    expect(within(region).getByText(/Le DNS ne passe pas par le proxy/)).toBeInTheDocument();
    await user.clear(scan);
    await user.type(scan, "2");
    expect(within(region).getByRole("button", { name: "Enregistrer" })).toBeDisabled();
    await user.clear(scan);
    await user.type(scan, "200");
    await user.click(within(region).getByRole("checkbox", { name: "Prendre une capture d'écran du site" }));
    await user.type(within(region).getByLabelText("Proxy HTTP ou SOCKS"), "socks5h://127.0.0.1:1080");
    await user.click(within(region).getByRole("button", { name: "Enregistrer" }));
    await waitFor(() => expect(calls.some((call) => call.method === "PUT")).toBe(true));
    expect(JSON.parse(String(calls.find((call) => call.method === "PUT")?.init.body))).toEqual({
      scan_timeout: 200,
      quick_timeout: 30,
      screenshot_enabled: false,
      proxy_url: "socks5h://127.0.0.1:1080",
    });
  });

  it("affiche le statut du VPN Mullvad en lecture seule", async () => {
    renderSettings();
    const region = screen.getByRole("region", { name: "VPN Mullvad" });
    expect(await within(region).findByText(/Connecté à Mullvad/)).toBeInTheDocument();
    expect(within(region).getByText("185.1.2.3 · Suède")).toBeInTheDocument();
    expect(within(region).queryByRole("button")).not.toBeInTheDocument();
  });

  it("canaux d'alerte : webhook masqué, SMTP, essai d'envoi", async () => {
    const { user, calls } = renderSettings(204, {
      "PUT /api/notify/channels/slack": () => jsonResponse(channels.channels[1]),
      "PUT /api/notify/channels/email": () => jsonResponse(channels.channels[4]),
      "POST /api/notify/channels/discord/test": () => jsonResponse({ ok: false, error: "Webhook refusé" }),
    });
    const region = screen.getByRole("region", { name: "Canaux d'alerte" });
    const discordUrl = await within(region).findByLabelText("Adresse du webhook", { selector: "#channel-discord-url" });
    expect(discordUrl).toHaveAttribute("type", "password");
    expect(discordUrl).toHaveAttribute("placeholder", "https://discord.com/…");
    expect(discordUrl).toHaveValue("");
    await user.type(within(region).getByLabelText("Adresse du webhook", { selector: "#channel-slack-url" }), "https://hooks.slack.com/services/T/B/X");
    await user.click(within(region).getByRole("checkbox", { name: "Activer Slack" }));
    await user.click(within(region).getAllByRole("button", { name: "Enregistrer" })[1]);
    await waitFor(() => expect(calls.some((call) => call.url.pathname === "/api/notify/channels/slack")).toBe(true));
    const slack = calls.find((call) => call.url.pathname === "/api/notify/channels/slack");
    expect(JSON.parse(String(slack?.init.body))).toEqual({ enabled: true, config: { url: "https://hooks.slack.com/services/T/B/X" } });

    await user.type(within(region).getByLabelText("Serveur SMTP"), "smtp.example.com");
    await user.type(within(region).getByLabelText("Expéditeur"), "alerts@example.com");
    await user.type(within(region).getByLabelText(/Destinataires/), "me@example.com, you@example.com");
    await user.type(within(region).getByLabelText("Mot de passe"), "s3cret");
    await user.click(within(region).getAllByRole("button", { name: "Enregistrer" })[4]);
    await waitFor(() => expect(calls.some((call) => call.url.pathname === "/api/notify/channels/email")).toBe(true));
    const email = JSON.parse(String(calls.find((call) => call.url.pathname === "/api/notify/channels/email")?.init.body));
    expect(email.config).toEqual({
      host: "smtp.example.com",
      security: "starttls",
      sender: "alerts@example.com",
      recipients: ["me@example.com", "you@example.com"],
      port: 587,
      password: "s3cret",
    });

    await user.click(within(region).getAllByRole("button", { name: "Envoyer un essai" })[0]);
    expect(await within(region).findByText("Webhook refusé")).toBeInTheDocument();
  });

  it("thème, et import d'une ancienne base par un envoi de fichier (plus de commande à recopier)", async () => {
    const { user } = renderSettings();
    await user.click(screen.getByRole("radio", { name: "Clair" }));
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    expect(window.localStorage.getItem("domainrecon.theme")).toBe("light");
    const region = screen.getByRole("region", { name: "Importer une ancienne base" });
    expect(within(region).getByRole("button", { name: "Choisir un fichier" })).toBeEnabled();
    expect(within(region).getByRole("button", { name: "Importer" })).toBeDisabled();
    expect(within(region).queryByText(/domainrecon import/)).not.toBeInTheDocument();
  });

  it("organise l'écran en sections nommées par un titre de niveau 2, sans attribut style", async () => {
    const { container } = renderSettings();
    await screen.findByText(info.data_dir);
    const title = screen.getByRole("heading", { level: 1, name: "Réglages" });
    expect(screen.getByText("Préférences")).toBeInTheDocument();
    expect(title).toBeInTheDocument();
    const names = screen.getAllByRole("heading", { level: 2 }).map((heading) => heading.textContent);
    expect(names).toEqual([
      "Langue de l'interface",
      "Thème",
      "Dossier des données",
      "Version",
      "Jeton d'API",
      "Clés API",
      "Délais, capture et proxy",
      "VPN Mullvad",
      "Canaux d'alerte",
      "Importer une ancienne base",
      "Licences",
      "Désinstaller complètement DomainRecon",
    ]);
    // Chaque section est une région nommée par son titre.
    for (const name of names) expect(screen.getByRole("region", { name })).toBeInTheDocument();
    expect(container.querySelector(".stagger")).toBeNull();
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("traduit les libellés en anglais", async () => {
    const { user } = renderSettings();
    await user.click(screen.getByRole("radio", { name: "English" }));
    expect(await screen.findByRole("heading", { level: 2, name: "API keys" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "Timeouts, screenshot and proxy" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "Alert channels" })).toBeInTheDocument();
    expect(screen.getByText("Preferences")).toBeInTheDocument();
  });
});
