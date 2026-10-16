import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { setLang } from "../../../i18n";
import { jsonResponse, mockFetch } from "../../../test/fetchMock";
import { allOk, makeScan } from "../../../test/fixtures";
import { ScreenshotModule } from "./Screenshot";

describe("capture d'écran : langue des erreurs du serveur", () => {
  it("la requête porte la langue de l'interface, pas celle du système", async () => {
    await setLang("en");
    const { calls } = mockFetch({
      "GET /api/screenshot/shot.png": () => jsonResponse({ detail: "Screenshot not found", code: null, params: {} }, 404),
    });
    render(<ScreenshotModule scan={makeScan({ screenshot_path: "shot.png", module_status: allOk() })} />);
    expect(await screen.findByText("Image unavailable: Screenshot not found")).toBeInTheDocument();
    expect(calls[0].url.searchParams.get("lang")).toBe("en");
  });
});
