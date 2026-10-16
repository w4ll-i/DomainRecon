import { describe, expect, it } from "vitest";
import { jsonResponse, mockFetch } from "../test/fetchMock";
import { fetchExport, filenameFromDisposition } from "./opsQueries";

describe("nom de fichier d'un export", () => {
  it("lit Content-Disposition, sinon utilise le nom par défaut", () => {
    expect(filenameFromDisposition('attachment; filename="rapport_example.com.pdf"', "x.pdf")).toBe("rapport_example.com.pdf");
    expect(filenameFromDisposition("attachment; filename*=UTF-8''rapport%20%C3%A9t%C3%A9.md", "x.md")).toBe("rapport été.md");
    expect(filenameFromDisposition(null, "scan-1.csv")).toBe("scan-1.csv");
    expect(filenameFromDisposition("inline", "scan-1.csv")).toBe("scan-1.csv");
  });
});

describe("export serveur", () => {
  it("demande le format et la langue de l'interface, renvoie le fichier", async () => {
    const { calls } = mockFetch({
      "GET /api/scan/7/export": () =>
        new Response("a,b", { status: 200, headers: { "Content-Disposition": 'attachment; filename="scan-7.csv"' } }),
    });
    const { blob, filename } = await fetchExport(7, "csv", "en");
    expect(filename).toBe("scan-7.csv");
    expect(await blob.text()).toBe("a,b");
    expect(calls[0].url.search).toBe("?format=csv&lang=en");
  });

  it("transmet le refus du serveur (PDF indisponible)", async () => {
    mockFetch({ "GET /api/scan/7/export": () => jsonResponse({ detail: "PDF indisponible" }, 503) });
    await expect(fetchExport(7, "pdf", "fr")).rejects.toMatchObject({ status: 503, detail: "PDF indisponible" });
  });
});
