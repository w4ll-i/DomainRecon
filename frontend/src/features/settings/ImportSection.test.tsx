import { act, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { setToken } from "../../api/client";
import { FakeXHR, lastXhr, stubXhr } from "../../test/fakeXhr";
import { renderWithProviders } from "../../test/render";
import { ImportSection } from "./ImportSection";

const MIB = 1024 * 1024;

function legacyFile(name = "ancienne_base.db", size = 4 * MIB): File {
  return new File([new Uint8Array(size)], name, { type: "application/octet-stream" });
}

async function choose(user: ReturnType<typeof renderWithProviders>["user"], file: File) {
  await user.upload(screen.getByLabelText("Ancienne base DomainRecon (fichier .db)"), file);
}

const done = { read: 12, imported: 9, ignored: 3, duplicates: 2, unusable: 1, unknown_columns: ["legacy_flag", "old_score"] };

describe("import d'une ancienne base", () => {
  it("n'affiche plus la commande : un bouton pour choisir le fichier, l'import reste inactif sans fichier", () => {
    stubXhr();
    renderWithProviders(<ImportSection />);
    const region = screen.getByRole("region", { name: "Importer une ancienne base" });
    expect(within(region).getByRole("button", { name: "Choisir un fichier" })).toBeInTheDocument();
    expect(within(region).getByText("Aucun fichier choisi")).toBeInTheDocument();
    expect(within(region).getByRole("button", { name: "Importer" })).toBeDisabled();
    expect(region).not.toHaveTextContent("domainrecon import");
  });

  it("envoie le fichier dans le champ « file », suit l'avancement puis montre les six chiffres", async () => {
    stubXhr();
    const { user, queryClient } = renderWithProviders(<ImportSection />);
    const invalidate = vi.spyOn(queryClient, "invalidateQueries");
    await choose(user, legacyFile("ancienne_base.db", 4 * MIB));
    expect(screen.getByText("ancienne_base.db")).toBeInTheDocument();
    expect(screen.getByText(/4 Mio/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Importer" }));

    const request = lastXhr();
    expect(request.method).toBe("POST");
    expect(request.url).toBe("/api/import?lang=fr");
    expect(request.file?.name).toBe("ancienne_base.db");
    expect(request.file?.size).toBe(4 * MIB);
    // Le navigateur pose seul le Content-Type multipart et sa frontière.
    expect(request.headers["Content-Type"]).toBeUndefined();
    expect(request.headers["X-API-Token"]).toBeUndefined();
    // Un seul import à la fois : le bouton est inactif pendant l'envoi.
    expect(screen.getByRole("button", { name: "Importer" })).toBeDisabled();

    act(() => request.progress(1 * MIB, 4 * MIB));
    expect(screen.getByText("Envoi du fichier : 25 %")).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "Importer une ancienne base" })).toHaveAttribute("value", "25");

    act(() => request.progress(4 * MIB, 4 * MIB));
    expect(screen.getByText(/Fichier reçu\. Lecture de la base/)).toBeInTheDocument();
    // Indéterminée : le serveur lit la base, sans avancement mesurable.
    expect(screen.getByRole("progressbar", { name: "Importer une ancienne base" })).not.toHaveAttribute("value");

    act(() => request.respond(200, done));
    const result = await screen.findByTestId("import-result");
    expect(within(result).getByText("9 scan(s) ajouté(s) à l'historique.")).toBeInTheDocument();
    const counts = (label: string) => within(result).getByText(label).nextElementSibling?.textContent;
    expect(counts("Scans lus")).toBe("12");
    expect(counts("Ajoutés à l'historique")).toBe("9");
    expect(counts("Ignorés")).toBe("3");
    expect(counts("Déjà présents")).toBe("2");
    expect(counts("Inutilisables (domaine ou date illisible)")).toBe("1");
    expect(within(result).getByText("Colonnes sans équivalent, non reprises")).toBeInTheDocument();
    expect(within(result).getByText("legacy_flag")).toBeInTheDocument();
    expect(within(result).getByText("old_score")).toBeInTheDocument();
    expect(within(result).getByRole("link", { name: "Voir l'historique" })).toHaveAttribute("href", "/history");
    expect(await screen.findByText("Import terminé : 9 scan(s) ajouté(s).")).toBeInTheDocument();
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
    // Des scans sont arrivés : les écrans qui les montrent se relisent.
    expect(invalidate).toHaveBeenCalled();
  });

  it("le même fichier renvoyé : rien d'ajouté, le texte dit que tout était déjà présent", async () => {
    stubXhr();
    const { user, queryClient } = renderWithProviders(<ImportSection />);
    const invalidate = vi.spyOn(queryClient, "invalidateQueries");
    await choose(user, legacyFile());
    await user.click(screen.getByRole("button", { name: "Importer" }));
    act(() => lastXhr().respond(200, { read: 5, imported: 0, ignored: 5, duplicates: 5, unusable: 0, unknown_columns: [] }));
    const result = await screen.findByTestId("import-result");
    expect(within(result).getByText(/Aucun nouveau scan/)).toBeInTheDocument();
    expect(within(result).queryByRole("link", { name: "Voir l'historique" })).not.toBeInTheDocument();
    expect(within(result).queryByText("Colonnes sans équivalent, non reprises")).not.toBeInTheDocument();
    expect(invalidate).not.toHaveBeenCalled();
  });

  it("une base sans scan exploitable est dite telle quelle", async () => {
    stubXhr();
    const { user } = renderWithProviders(<ImportSection />);
    await choose(user, legacyFile());
    await user.click(screen.getByRole("button", { name: "Importer" }));
    act(() => lastXhr().respond(200, { read: 0, imported: 0, ignored: 0, duplicates: 0, unusable: 0, unknown_columns: [] }));
    expect(await screen.findByText("Ce fichier ne contient aucun scan exploitable.")).toBeInTheDocument();
  });

  it.each([
    [400, "api.import_not_sqlite", "Ce fichier n'est pas une base SQLite lisible."],
    [400, "api.import_not_domainrecon", "Cette base SQLite n'est pas une base DomainRecon."],
    [403, "api.local_only", "Action réservée à l'utilisateur de cette machine"],
    [403, "api.cross_origin", "Requête refusée : origine différente."],
    [409, "api.import_running", "Un import est déjà en cours."],
    [413, "api.import_too_large", "Fichier trop gros (512 Mio au plus)."],
    [500, "api.import_failed", "L'import a échoué. Vous pouvez le relancer : les doublons sont ignorés."],
    [503, "api.database_unavailable", "Base de données occupée, réessayez."],
  ])("erreur %i %s : le texte du serveur s'affiche tel quel, l'import peut être relancé", async (status, code, detail) => {
    stubXhr();
    const { user } = renderWithProviders(<ImportSection />);
    await choose(user, legacyFile());
    await user.click(screen.getByRole("button", { name: "Importer" }));
    act(() => lastXhr().respond(status, { detail, code, params: {} }));
    expect(await screen.findByRole("alert")).toHaveTextContent(detail);
    expect(screen.queryByTestId("import-result")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Importer" })).toBeEnabled();
  });

  it("serveur injoignable : message réseau, import relançable", async () => {
    stubXhr();
    const { user } = renderWithProviders(<ImportSection />);
    await choose(user, legacyFile());
    await user.click(screen.getByRole("button", { name: "Importer" }));
    act(() => lastXhr().fail());
    expect(await screen.findByRole("alert")).toHaveTextContent(/serveur|réseau/i);
    expect(screen.getByRole("button", { name: "Importer" })).toBeEnabled();
  });

  it("réponse 200 illisible : erreur claire, pas de résultat inventé", async () => {
    stubXhr();
    const { user } = renderWithProviders(<ImportSection />);
    await choose(user, legacyFile());
    await user.click(screen.getByRole("button", { name: "Importer" }));
    act(() => lastXhr().respond(200, "<html>pas du JSON</html>"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Réponse illisible du serveur (HTTP 200).");
    expect(screen.queryByTestId("import-result")).not.toBeInTheDocument();
  });

  it("Annuler interrompt l'envoi, sans erreur, et l'import peut être relancé", async () => {
    stubXhr();
    const { user } = renderWithProviders(<ImportSection />);
    await choose(user, legacyFile());
    await user.click(screen.getByRole("button", { name: "Importer" }));
    act(() => lastXhr().progress(MIB, 4 * MIB));
    await user.click(screen.getByRole("button", { name: "Annuler" }));
    expect(lastXhr().aborted).toBe(true);
    expect(await screen.findByText(/Import annulé/)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Annuler" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Importer" })).toBeEnabled();
  });

  it("fichier au-delà de 512 Mio : refusé avant l'envoi, avec la limite", async () => {
    stubXhr();
    const { user } = renderWithProviders(<ImportSection />);
    const huge = legacyFile("enorme.db", 10);
    Object.defineProperty(huge, "size", { value: 600 * MIB });
    await choose(user, huge);
    expect(screen.getByRole("alert")).toHaveTextContent("Ce fichier fait 600 Mio : la limite est de 512 Mio.");
    expect(screen.getByRole("button", { name: "Importer" })).toBeDisabled();
    expect(FakeXHR.instances).toHaveLength(0);
  });

  it("envoie le jeton d'API de l'onglet", async () => {
    stubXhr();
    setToken("secret-token");
    const { user } = renderWithProviders(<ImportSection />);
    await choose(user, legacyFile());
    await user.click(screen.getByRole("button", { name: "Importer" }));
    expect(lastXhr().headers["X-API-Token"]).toBe("secret-token");
  });

  it("langue anglaise : adresse ?lang=en et textes anglais", async () => {
    const { setLang } = await import("../../i18n");
    await setLang("en");
    stubXhr();
    const { user } = renderWithProviders(<ImportSection />);
    await user.upload(screen.getByLabelText("Old DomainRecon database (.db file)"), legacyFile());
    await user.click(screen.getByRole("button", { name: "Import" }));
    expect(lastXhr().url).toBe("/api/import?lang=en");
    act(() => lastXhr().respond(200, done));
    expect(await screen.findByText("9 scan(s) added to the history.")).toBeInTheDocument();
  });

  it("rechoisir un fichier efface le résultat précédent", async () => {
    stubXhr();
    const { user } = renderWithProviders(<ImportSection />);
    await choose(user, legacyFile("une.db"));
    await user.click(screen.getByRole("button", { name: "Importer" }));
    act(() => lastXhr().respond(200, done));
    await screen.findByTestId("import-result");
    await choose(user, legacyFile("autre.db"));
    await waitFor(() => expect(screen.queryByTestId("import-result")).not.toBeInTheDocument());
    expect(screen.getByText("autre.db")).toBeInTheDocument();
  });
});
