import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, getToken, setToken, setTokenPrompt } from "./client";
import { parseImportResult, uploadImport } from "./upload";
import { FakeXHR, lastXhr, stubXhr } from "../test/fakeXhr";

const file = () => new File([new Uint8Array(2048)], "ancienne.db");
const result = { read: 3, imported: 2, ignored: 1, duplicates: 1, unusable: 0, unknown_columns: ["x"] };

afterEach(() => setTokenPrompt(null));

describe("lecture de la réponse d'import", () => {
  it("accepte les six champs", () => {
    expect(parseImportResult(result)).toEqual(result);
  });

  it("colonnes absentes ou mal formées : liste vide, les noms non textuels sont écartés", () => {
    const withoutColumns: Record<string, unknown> = { ...result };
    delete withoutColumns.unknown_columns;
    expect(parseImportResult(withoutColumns)?.unknown_columns).toEqual([]);
    expect(parseImportResult({ ...result, unknown_columns: ["a", 3, null, "b"] })?.unknown_columns).toEqual(["a", "b"]);
    expect(parseImportResult({ ...result, unknown_columns: "a" })?.unknown_columns).toEqual([]);
  });

  it.each([
    ["null", null],
    ["texte", "ok"],
    ["champ manquant", { read: 1, imported: 1, ignored: 0, duplicates: 0 }],
    ["nombre négatif", { ...result, read: -1 }],
    ["texte au lieu d'un nombre", { ...result, imported: "2" }],
    ["NaN", { ...result, duplicates: Number.NaN }],
  ])("refuse une réponse mal formée : %s", (_label, body) => {
    expect(parseImportResult(body)).toBeNull();
  });
});

describe("envoi de l'ancienne base", () => {
  it("poste un formulaire à /api/import avec la langue, et rend le résultat", async () => {
    stubXhr();
    const call = uploadImport(file(), { lang: "en" });
    const request = lastXhr();
    expect(request.method).toBe("POST");
    expect(request.url).toBe("/api/import?lang=en");
    expect(request.body).toBeInstanceOf(FormData);
    expect(request.file?.name).toBe("ancienne.db");
    request.respond(200, result);
    await expect(call).resolves.toEqual(result);
  });

  it("relaie l'avancement de l'envoi, seulement quand la taille est connue", async () => {
    stubXhr();
    const onProgress = vi.fn();
    const call = uploadImport(file(), { onProgress });
    const request = lastXhr();
    request.progress(512, 2048);
    request.upload.onprogress?.({ lengthComputable: false, loaded: 1, total: 0 });
    request.respond(200, result);
    await call;
    expect(onProgress).toHaveBeenCalledTimes(1);
    expect(onProgress).toHaveBeenCalledWith({ loaded: 512, total: 2048 });
  });

  it("erreur du serveur : ApiError avec le statut, le code, les paramètres et le texte traduit", async () => {
    stubXhr();
    const call = uploadImport(file());
    lastXhr().respond(413, { detail: "Fichier trop gros", code: "api.import_too_large", params: { max: 512 } });
    await expect(call).rejects.toMatchObject({ status: 413, code: "api.import_too_large", params: { max: 512 }, detail: "Fichier trop gros" });
  });

  it("erreur sans corps JSON : texte générique du statut", async () => {
    stubXhr();
    const call = uploadImport(file());
    lastXhr().respond(502, "<html>Bad gateway</html>");
    await expect(call).rejects.toMatchObject({ status: 502 });
    await call.catch((error: ApiError) => expect(error.detail).not.toBe(""));
  });

  it("réponse 200 qui n'est pas un résultat d'import : erreur de réponse illisible", async () => {
    stubXhr();
    const call = uploadImport(file());
    lastXhr().respond(200, { ok: true });
    await expect(call).rejects.toMatchObject({ status: 200, detail: "Réponse illisible du serveur (HTTP 200)." });
  });

  it("serveur injoignable : ApiError de statut 0", async () => {
    stubXhr();
    const call = uploadImport(file());
    lastXhr().fail();
    await expect(call).rejects.toMatchObject({ status: 0 });
  });

  it("délai dépassé : même erreur réseau", async () => {
    stubXhr();
    const call = uploadImport(file());
    lastXhr().ontimeout?.();
    await expect(call).rejects.toMatchObject({ status: 0 });
  });

  it("signal d'annulation : la requête est interrompue (AbortError, pas une ApiError)", async () => {
    stubXhr();
    const controller = new AbortController();
    const call = uploadImport(file(), { signal: controller.signal });
    controller.abort();
    expect(lastXhr().aborted).toBe(true);
    await expect(call).rejects.toMatchObject({ name: "AbortError" });
    await call.catch((error: unknown) => expect(error).not.toBeInstanceOf(ApiError));
  });

  it("signal déjà annulé : rien n'est envoyé", async () => {
    stubXhr();
    const controller = new AbortController();
    controller.abort();
    await expect(uploadImport(file(), { signal: controller.signal })).rejects.toMatchObject({ name: "AbortError" });
    expect(FakeXHR.instances).toHaveLength(0);
  });

  it("le jeton d'API part dans X-API-Token ; un jeton qui ne passerait pas en en-tête n'est pas envoyé", async () => {
    stubXhr();
    setToken("abc-123");
    const call = uploadImport(file());
    expect(lastXhr().headers["X-API-Token"]).toBe("abc-123");
    lastXhr().respond(200, result);
    await call;
  });

  it("sur 401 : saisie du jeton puis une seule nouvelle tentative avec le même fichier", async () => {
    stubXhr();
    const prompt = vi.fn(async () => "nouveau");
    setTokenPrompt(prompt);
    const call = uploadImport(file());
    lastXhr().respond(401, { detail: "Authentification requise", code: "api.auth_required" });
    await vi.waitFor(() => expect(FakeXHR.instances).toHaveLength(2));
    expect(prompt).toHaveBeenCalledWith("missing");
    const retry = lastXhr();
    expect(retry.headers["X-API-Token"]).toBe("nouveau");
    expect(retry.file?.name).toBe("ancienne.db");
    retry.respond(200, result);
    await expect(call).resolves.toEqual(result);
    expect(getToken()).toBe("nouveau");
  });

  it("401 sans saisie du jeton : ApiError 401, pas de seconde tentative", async () => {
    stubXhr();
    setTokenPrompt(async () => null);
    const call = uploadImport(file());
    lastXhr().respond(401, { detail: "Authentification requise", code: "api.auth_required" });
    await expect(call).rejects.toMatchObject({ status: 401, code: "api.auth_required" });
    expect(FakeXHR.instances).toHaveLength(1);
  });
});
