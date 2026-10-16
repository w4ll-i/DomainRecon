import { act, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { setLang } from "../../i18n";
import { jsonResponse, mockFetch } from "../../test/fetchMock";
import { makeScan } from "../../test/fixtures";
import { renderWithProviders } from "../../test/render";
import { ResultPage } from "./ResultPage";

// Chart.js dessine dans un canvas (absent de jsdom) : le radar est remplacé par un témoin.
vi.mock("react-chartjs-2", async () => (await import("../../test/chartStub")).chartStub);

describe("exports et changement de langue", () => {
  it("l'export attend le scan à jour : jamais un document mêlant deux langues", async () => {
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
    renderWithProviders(<ResultPage />, { route: "/scans/42", path: "/scans/:id" });
    const exporter = await screen.findByRole("button", { name: /Exporter/ });
    expect(exporter).toBeEnabled();
    await act(async () => {
      await setLang("en");
    });
    // Relecture en anglais en cours : le scan affiché est encore celui du français.
    expect(screen.getByRole("button", { name: /Exporter|Export/ })).toBeDisabled();
    release();
    await waitFor(() => expect(screen.getByRole("button", { name: /Export/ })).toBeEnabled());
  });
});
