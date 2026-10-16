import { screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { UninstallReport } from "../../api/uninstall";
import { jsonResponse, mockFetch } from "../../test/fetchMock";
import { renderWithProviders } from "../../test/render";
import { UninstallSection } from "./UninstallSection";

const plan: UninstallReport = {
  dry_run: true,
  mode: "windows_installed",
  platform: "windows",
  data_dir: "C:\\Users\\moi\\AppData\\Local\\DomainRecon",
  items: [
    { kind: "database", path: "C:\\Users\\moi\\AppData\\Local\\DomainRecon\\domainrecon.db", status: "planned", size: 2 * 1024 * 1024 },
    { kind: "secret_key", path: "C:\\Users\\moi\\AppData\\Local\\DomainRecon\\.secret_key", status: "planned", size: 32 },
    { kind: "system_task", path: "DomainRecon-Monitor", status: "planned", size: null },
  ],
  total_size: 2 * 1024 * 1024 + 32,
  program_removal: { available: false, paths: [] },
  uninstaller: "C:\\Users\\moi\\AppData\\Local\\Programs\\DomainRecon\\unins000.exe",
  after_exit_scheduled: false,
  remaining: [{ code: "windows_uninstaller", path: "C:\\Users\\moi\\AppData\\Local\\Programs\\DomainRecon\\unins000.exe" }],
  can_exit: true,
};

const done: UninstallReport = {
  ...plan,
  dry_run: false,
  items: [
    { ...plan.items[0], status: "deleted", size: null },
    { ...plan.items[1], status: "deleted", size: null },
    { ...plan.items[2], status: "deleted", size: null },
    { kind: "data_dir", path: plan.data_dir, status: "deleted", size: null },
  ],
  after_exit_scheduled: true,
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function bodyOf(init: RequestInit): unknown {
  return JSON.parse(String(init.body));
}

async function openDialog(user: ReturnType<typeof renderWithProviders>["user"]) {
  await user.click(screen.getByRole("button", { name: "Désinstaller complètement…" }));
  return screen.findByRole("alertdialog", { name: "Désinstaller complètement DomainRecon" });
}

describe("désinstallation complète", () => {
  it("zone de danger : rien n'est demandé au serveur avant l'ouverture de la fenêtre", () => {
    const { calls } = mockFetch({});
    renderWithProviders(<UninstallSection />);
    const region = screen.getByRole("region", { name: "Désinstaller complètement DomainRecon" });
    expect(within(region).getByText("Zone de danger")).toBeInTheDocument();
    expect(calls).toEqual([]);
  });

  it("étape 1 : liste à blanc du serveur, mode détecté et suite annoncée", async () => {
    const { calls } = mockFetch({ "POST /api/system/uninstall": plan });
    const { user } = renderWithProviders(<UninstallSection />);
    const dialog = await openDialog(user);
    expect(await within(dialog).findByText("Installation détectée : installation Windows.")).toBeInTheDocument();
    expect(calls[0].url.pathname).toBe("/api/system/uninstall");
    expect(bodyOf(calls[0].init)).toEqual({ dry_run: true });
    const items = within(dialog).getByTestId("uninstall-items");
    expect(within(items).getByText("Base de données (historique, surveillances, réglages, clés API chiffrées)")).toBeInTheDocument();
    expect(within(items).getByText("Clé de chiffrement des clés API")).toBeInTheDocument();
    expect(within(items).getByText("Tâche planifiée de la surveillance")).toBeInTheDocument();
    expect(within(items).getByText("C:\\Users\\moi\\AppData\\Local\\DomainRecon\\domainrecon.db")).toBeInTheDocument();
    expect(within(dialog).getByText(/Espace libéré : 2 Mio/)).toBeInTheDocument();
    expect(within(dialog).getByText(/le désinstalleur Windows retire le programme/)).toBeInTheDocument();
    expect(within(dialog).getByRole("listitem", { current: "step" })).toHaveTextContent("Ce qui sera supprimé");
  });

  it("clavier : chaque étape reçoit le focus (jamais perdu hors de la fenêtre), la liste défilante est atteignable", async () => {
    mockFetch({
      "POST /api/system/uninstall": ({ init }) => jsonResponse((bodyOf(init) as { dry_run?: boolean }).dry_run ? plan : done),
    });
    const { user } = renderWithProviders(<UninstallSection />);
    const dialog = await openDialog(user);
    const items = await within(dialog).findByTestId("uninstall-items");
    // Étape 1 : « Annuler », le choix sans risque ; la liste qui défile est un arrêt de tabulation.
    expect(within(dialog).getByRole("button", { name: "Annuler" })).toHaveFocus();
    expect(items).toHaveAttribute("tabindex", "0");
    await user.click(within(dialog).getByRole("button", { name: "Continuer" }));
    expect(within(dialog).getByRole("button", { name: "Télécharger une sauvegarde (.db)" })).toHaveFocus();
    await user.click(within(dialog).getByRole("button", { name: "Continuer sans sauvegarde" }));
    const field = within(dialog).getByRole("textbox", { name: "Tapez SUPPRIMER" });
    expect(field).toHaveFocus();
    // Retour à la sauvegarde : le focus suit.
    await user.click(within(dialog).getByRole("button", { name: "Retour" }));
    expect(within(dialog).getByRole("button", { name: "Télécharger une sauvegarde (.db)" })).toHaveFocus();
    await user.click(within(dialog).getByRole("button", { name: "Continuer sans sauvegarde" }));
    await user.type(within(dialog).getByRole("textbox", { name: "Tapez SUPPRIMER" }), "SUPPRIMER{Enter}");
    await within(dialog).findByText("DomainRecon a été désinstallé.");
    expect(within(dialog).getByRole("button", { name: "Fermer DomainRecon" })).toHaveFocus();
  });

  it("parcours complet : sauvegarde téléchargée, mot exigé, résultat puis fermeture", async () => {
    const createObjectURL = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:sauvegarde");
    const { calls } = mockFetch({
      "POST /api/system/uninstall": ({ init }) => jsonResponse((bodyOf(init) as { dry_run?: boolean }).dry_run ? plan : done),
      "POST /api/system/backup": () =>
        new Response(new Blob(["SQLite format 3"]), {
          status: 200,
          headers: { "Content-Disposition": 'attachment; filename="domainrecon-sauvegarde-20261016-101500.db"' },
        }),
      "POST /api/system/uninstall/finish": { exiting: true },
    });
    const { user } = renderWithProviders(<UninstallSection />);
    const dialog = await openDialog(user);
    await within(dialog).findByTestId("uninstall-items");
    await user.click(within(dialog).getByRole("button", { name: "Continuer" }));

    // Étape 2 : sauvegarde proposée.
    expect(within(dialog).getByRole("listitem", { current: "step" })).toHaveTextContent("Sauvegarde");
    await user.click(within(dialog).getByRole("button", { name: "Télécharger une sauvegarde (.db)" }));
    expect(await within(dialog).findByText("Sauvegarde téléchargée : domainrecon-sauvegarde-20261016-101500.db")).toBeInTheDocument();
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    const backup = calls.find((call) => call.url.pathname === "/api/system/backup");
    expect(backup?.init.method).toBe("POST");
    expect(bodyOf(backup!.init)).toEqual({});
    await user.click(within(dialog).getByRole("button", { name: "Continuer" }));

    // Étape 3 : le bouton reste inactif tant que le mot n'est pas tapé.
    const submit = within(dialog).getByRole("button", { name: "Désinstaller définitivement" });
    expect(submit).toBeDisabled();
    const field = within(dialog).getByRole("textbox", { name: "Tapez SUPPRIMER" });
    expect(field).toHaveFocus();
    await user.type(field, "SUPPRIME");
    expect(submit).toBeDisabled();
    await user.type(field, "R");
    expect(submit).toBeEnabled();
    await user.click(submit);

    // Étape 4 : résultat et étapes restantes.
    expect(await within(dialog).findByText("DomainRecon a été désinstallé.")).toBeInTheDocument();
    const uninstall = calls.filter((call) => call.url.pathname === "/api/system/uninstall");
    expect(bodyOf(uninstall[uninstall.length - 1].init)).toEqual({ confirm: "SUPPRIMER", remove_program: false });
    expect(within(dialog).getByText(/Éléments supprimés : 4\./)).toBeInTheDocument();
    expect(within(dialog).getAllByText("Supprimé")).toHaveLength(4);
    expect(within(within(dialog).getByTestId("uninstall-remaining")).getByText(/désinstalleur Windows/)).toBeInTheDocument();
    // Échap ne ferme plus la fenêtre : DomainRecon est désinstallé, il ne reste qu'à le fermer.
    await user.keyboard("{Escape}");
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Fermer DomainRecon" }));
    expect(await within(dialog).findByText("DomainRecon se ferme…")).toBeInTheDocument();
    expect(calls.some((call) => call.url.pathname === "/api/system/uninstall/finish")).toBe(true);
  });

  it("sauvegarde impossible : le message du serveur, et l'on peut continuer sans", async () => {
    mockFetch({
      "POST /api/system/uninstall": plan,
      "POST /api/system/backup": () =>
        jsonResponse(
        { detail: "Aucune base SQLite à sauvegarder", code: "api.backup_unavailable", params: {} },
        409,
      ),
    });
    const { user } = renderWithProviders(<UninstallSection />);
    const dialog = await openDialog(user);
    await within(dialog).findByTestId("uninstall-items");
    await user.click(within(dialog).getByRole("button", { name: "Continuer" }));
    await user.click(within(dialog).getByRole("button", { name: "Télécharger une sauvegarde (.db)" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Sauvegarde impossible : Aucune base SQLite à sauvegarder");
    await user.click(within(dialog).getByRole("button", { name: "Continuer sans sauvegarde" }));
    expect(within(dialog).getByRole("listitem", { current: "step" })).toHaveTextContent("Confirmation");
  });

  it("version portable : la case « supprimer aussi le programme » change la suite et part avec la demande", async () => {
    const portable: UninstallReport = {
      ...plan,
      mode: "portable_onefile",
      uninstaller: null,
      program_removal: { available: true, paths: ["D:\\Outils\\DomainRecon-1.0.0-portable.exe"] },
      remaining: [{ code: "delete_program", path: "D:\\Outils\\DomainRecon-1.0.0-portable.exe" }],
    };
    const { calls } = mockFetch({
      "POST /api/system/uninstall": ({ init }) =>
        jsonResponse((bodyOf(init) as { dry_run?: boolean }).dry_run ? portable : { ...portable, dry_run: false, can_exit: false }),
    });
    const { user } = renderWithProviders(<UninstallSection />);
    const dialog = await openDialog(user);
    expect(await within(dialog).findByText(/Supprimez le programme à la main/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("checkbox", { name: /Supprimer aussi le programme après la fermeture/ }));
    expect(within(dialog).getByText(/Le programme sera supprimé après la fermeture/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Continuer" }));
    await user.click(within(dialog).getByRole("button", { name: "Continuer sans sauvegarde" }));
    await user.type(within(dialog).getByRole("textbox", { name: "Tapez SUPPRIMER" }), "supprimer");
    await user.click(within(dialog).getByRole("button", { name: "Désinstaller définitivement" }));
    await within(dialog).findByText("DomainRecon a été désinstallé.");
    expect(bodyOf(calls[calls.length - 1].init)).toEqual({ confirm: "SUPPRIMER", remove_program: true });
    // Sans fermeture automatique possible : « Terminer » referme la fenêtre.
    await user.click(within(dialog).getByRole("button", { name: "Terminer" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
  });

  it("refus du serveur (autre machine) : le message traduit, rien n'est supprimé", async () => {
    mockFetch({
      "POST /api/system/uninstall": () =>
        jsonResponse(
        { detail: "Action réservée à l'utilisateur de cette machine", code: "api.local_only", params: {} },
        403,
      ),
    });
    const { user } = renderWithProviders(<UninstallSection />);
    const dialog = await openDialog(user);
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Inventaire impossible : Action réservée à l'utilisateur de cette machine",
    );
    expect(within(dialog).getByRole("button", { name: "Continuer" })).toBeDisabled();
    await user.click(within(dialog).getByRole("button", { name: "Annuler" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
  });
});
