import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { useEffect, useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { ApiError, apiFetch } from "../api/client";
import { jsonResponse, type MockHandler, mockFetch } from "../test/fetchMock";
import { renderWithProviders } from "../test/render";
import { useConfirm } from "./ConfirmDialog";
import { useToast } from "./Toasts";
import { useTokenDialog } from "./TokenDialog";

function ToastHarness() {
  const toast = useToast();
  return (
    <button type="button" onClick={() => toast.show("Rapport PDF généré", "success")}>
      Notifier
    </button>
  );
}

function ConfirmHarness() {
  const confirm = useConfirm();
  const [answer, setAnswer] = useState("aucune");
  return (
    <>
      <button
        type="button"
        onClick={async () =>
          setAnswer(String(await confirm({ title: "Supprimer ce scan ?", message: "Définitif.", confirmLabel: "Supprimer", danger: true })))
        }
      >
        Supprimer
      </button>
      <p>Réponse : {answer}</p>
    </>
  );
}

function TokenHarness() {
  const dialog = useTokenDialog();
  return (
    <button type="button" onClick={dialog.open}>
      Saisir le jeton
    </button>
  );
}

const needsToken =
  (counter: { accepted: number }): MockHandler =>
  ({ init }) => {
    if (new Headers(init.headers).get("X-API-Token") === "s3cret") {
      counter.accepted += 1;
      return jsonResponse({ ok: true });
    }
    return jsonResponse({ detail: "Authentification requise : jeton d'API absent ou invalide." }, 401);
  };

describe("notifications", () => {
  it("affiche un message dans la zone annoncée et le ferme sur demande", async () => {
    const { user } = renderWithProviders(<ToastHarness />);
    await user.click(screen.getByRole("button", { name: "Notifier" }));
    const region = screen.getByRole("region", { name: "Notifications" });
    expect(within(region).getByText("Rapport PDF généré")).toBeInTheDocument();
    await user.click(within(region).getByRole("button", { name: "Fermer la notification" }));
    expect(within(region).queryByText("Rapport PDF généré")).not.toBeInTheDocument();
  });

  describe("disparition automatique (WCAG 2.2.1 : durée ajustable)", () => {
    function Pair() {
      const toast = useToast();
      return (
        <>
          <button type="button" onClick={() => toast.show("Premier message", "success")}>
            Un
          </button>
          <button type="button" onClick={() => toast.show("Second message", "success")}>
            Deux
          </button>
        </>
      );
    }
    const present = (text: string) => screen.queryByText(text) !== null;

    it("disparaît seule après 3,5 s (succès) et 6 s (erreur ou avertissement)", () => {
      vi.useFakeTimers();
      try {
        renderWithProviders(<ToastHarness />);
        fireEvent.click(screen.getByRole("button", { name: "Notifier" }));
        act(() => void vi.advanceTimersByTime(3400));
        expect(present("Rapport PDF généré")).toBe(true);
        act(() => void vi.advanceTimersByTime(200));
        expect(present("Rapport PDF généré")).toBe(false);
      } finally {
        vi.useRealTimers();
      }
    });

    it("le survol suspend la disparition ; à la sortie le temps restant reprend (au moins 1,5 s)", () => {
      vi.useFakeTimers();
      try {
        renderWithProviders(<ToastHarness />);
        fireEvent.click(screen.getByRole("button", { name: "Notifier" }));
        const item = screen.getByText("Rapport PDF généré").closest("li") as HTMLElement;
        act(() => void vi.advanceTimersByTime(3000));
        fireEvent.mouseEnter(item);
        act(() => void vi.advanceTimersByTime(60_000));
        expect(present("Rapport PDF généré")).toBe(true);
        fireEvent.mouseLeave(item);
        act(() => void vi.advanceTimersByTime(1400));
        expect(present("Rapport PDF généré")).toBe(true);
        act(() => void vi.advanceTimersByTime(200));
        expect(present("Rapport PDF généré")).toBe(false);
      } finally {
        vi.useRealTimers();
      }
    });

    it("le focus clavier sur la notification la suspend aussi", () => {
      vi.useFakeTimers();
      try {
        renderWithProviders(<ToastHarness />);
        fireEvent.click(screen.getByRole("button", { name: "Notifier" }));
        const close = screen.getByRole("button", { name: "Fermer la notification" });
        act(() => close.focus());
        act(() => void vi.advanceTimersByTime(60_000));
        expect(present("Rapport PDF généré")).toBe(true);
        act(() => close.blur());
        act(() => void vi.advanceTimersByTime(4000));
        expect(present("Rapport PDF généré")).toBe(false);
      } finally {
        vi.useRealTimers();
      }
    });

    it("une notification fermée sous la souris ne laisse pas les autres en pause", () => {
      vi.useFakeTimers();
      try {
        renderWithProviders(<Pair />);
        fireEvent.click(screen.getByRole("button", { name: "Un" }));
        fireEvent.click(screen.getByRole("button", { name: "Deux" }));
        const first = screen.getByText("Premier message").closest("li") as HTMLElement;
        fireEvent.mouseEnter(first);
        // Pas de « mouseleave » : l'élément disparaît sous le pointeur.
        fireEvent.click(within(first).getByRole("button", { name: "Fermer la notification" }));
        expect(present("Premier message")).toBe(false);
        act(() => void vi.advanceTimersByTime(4000));
        expect(present("Second message")).toBe(false);
      } finally {
        vi.useRealTimers();
      }
    });

    it("une notification évincée sous la souris (rafale) ne laisse pas les autres en pause", () => {
      function Burst() {
        const toast = useToast();
        const count = useRef(0);
        return (
          <button type="button" onClick={() => toast.show(`Message ${++count.current}`, "success")}>
            Rafale
          </button>
        );
      }
      vi.useFakeTimers();
      try {
        renderWithProviders(<Burst />);
        const burst = screen.getByRole("button", { name: "Rafale" });
        fireEvent.click(burst);
        fireEvent.mouseEnter(screen.getByText("Message 1").closest("li") as HTMLElement);
        // Cinq arrivées : la première est évincée (5 au plus), sans « mouseleave ».
        for (let i = 0; i < 5; i += 1) fireEvent.click(burst);
        expect(present("Message 1")).toBe(false);
        expect(present("Message 6")).toBe(true);
        act(() => void vi.advanceTimersByTime(4000));
        for (let i = 2; i <= 6; i += 1) expect(present(`Message ${i}`)).toBe(false);
      } finally {
        vi.useRealTimers();
      }
    });

    it("une notification émise au montage d'un écran disparaît aussi seule", () => {
      function OnMount() {
        const toast = useToast();
        useEffect(() => toast.show("Au montage", "success"), [toast]);
        return null;
      }
      vi.useFakeTimers();
      try {
        renderWithProviders(<OnMount />);
        expect(present("Au montage")).toBe(true);
        act(() => void vi.advanceTimersByTime(4000));
        expect(present("Au montage")).toBe(false);
      } finally {
        vi.useRealTimers();
      }
    });
  });
});

describe("confirmation", () => {
  it("renvoie true sur confirmation", async () => {
    const { user } = renderWithProviders(<ConfirmHarness />);
    await user.click(screen.getByRole("button", { name: "Supprimer" }));
    const dialog = screen.getByRole("alertdialog", { name: "Supprimer ce scan ?" });
    expect(within(dialog).getByRole("button", { name: "Annuler" })).toHaveFocus();
    await user.click(within(dialog).getByRole("button", { name: "Supprimer" }));
    expect(await screen.findByText("Réponse : true")).toBeInTheDocument();
  });

  it("Échap annule et rend le focus au déclencheur", async () => {
    const { user } = renderWithProviders(<ConfirmHarness />);
    const trigger = screen.getByRole("button", { name: "Supprimer" });
    await user.click(trigger);
    await user.keyboard("{Escape}");
    expect(await screen.findByText("Réponse : false")).toBeInTheDocument();
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });
});

describe("fenêtre modale : piège à focus", () => {
  async function openConfirm() {
    const { user } = renderWithProviders(<ConfirmHarness />);
    const trigger = screen.getByRole("button", { name: "Supprimer" });
    await user.click(trigger);
    const dialog = screen.getByRole("alertdialog", { name: "Supprimer ce scan ?" });
    return {
      user,
      trigger,
      dialog,
      cancel: within(dialog).getByRole("button", { name: "Annuler" }),
      confirm: within(dialog).getByRole("button", { name: "Supprimer" }),
    };
  }

  it("Tab et Maj+Tab bouclent entre les boutons de la fenêtre", async () => {
    const { user, dialog, cancel, confirm } = await openConfirm();
    expect(cancel).toHaveFocus();
    await user.tab();
    expect(confirm).toHaveFocus();
    await user.tab();
    expect(cancel).toHaveFocus();
    await user.tab({ shift: true });
    expect(confirm).toHaveFocus();
    expect(dialog).toContainElement(document.activeElement as HTMLElement);
  });

  it("garde le focus dans la fenêtre quand le panneau lui-même l'a (clic sur le texte)", async () => {
    const { user, dialog, cancel, confirm } = await openConfirm();
    await user.click(within(dialog).getByText("Définitif."));
    expect(dialog).toHaveFocus();
    await user.tab({ shift: true });
    expect(confirm).toHaveFocus();
    await user.click(within(dialog).getByText("Définitif."));
    expect(dialog).toHaveFocus();
    await user.tab();
    expect(cancel).toHaveFocus();
  });

  it("ramène dans la fenêtre un focus resté hors du panneau", async () => {
    const { trigger: behind, dialog, cancel, confirm } = await openConfirm();
    // Le déclencheur, sous le fond, reçoit le focus ; la frappe est tout de même captée par la fenêtre.
    expect(dialog).not.toContainElement(behind);
    behind.focus();
    fireEvent.keyDown(dialog, { key: "Tab", shiftKey: true });
    expect(confirm).toHaveFocus();
    behind.focus();
    fireEvent.keyDown(dialog, { key: "Tab" });
    expect(cancel).toHaveFocus();
  });
});

describe("jeton d'API", () => {
  it("une seule saisie pour des 401 simultanés, puis les deux appels sont rejoués", async () => {
    const counter = { accepted: 0 };
    mockFetch({ "/api/scan/1": needsToken(counter), "/api/scan/2": needsToken(counter) });
    const { user } = renderWithProviders(<p>page</p>);
    const first = apiFetch("/scan/1");
    const second = apiFetch("/scan/2");
    const dialog = await screen.findByRole("dialog", { name: "Jeton d'API" });
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    await user.type(within(dialog).getByLabelText("Jeton d'API"), "s3cret");
    await user.click(within(dialog).getByRole("button", { name: "Valider" }));
    await expect(Promise.all([first, second])).resolves.toEqual([{ ok: true }, { ok: true }]);
    expect(counter.accepted).toBe(2);
    expect(window.sessionStorage.getItem("domainrecon.token")).toBe("s3cret");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("refuse un jeton non ASCII ; Échap abandonne et l'appel échoue en 401", async () => {
    mockFetch({ "/api/scan/1": needsToken({ accepted: 0 }) });
    const { user } = renderWithProviders(<p>page</p>);
    const call = apiFetch("/scan/1").catch((error: unknown) => error);
    const dialog = await screen.findByRole("dialog", { name: "Jeton d'API" });
    await user.type(within(dialog).getByLabelText("Jeton d'API"), "clé");
    await user.click(within(dialog).getByRole("button", { name: "Valider" }));
    expect(within(dialog).getByRole("alert")).toHaveTextContent(
      "Le jeton ne peut contenir que des caractères ASCII imprimables.",
    );
    await user.keyboard("{Escape}");
    const error = await call;
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(401);
  });

  it("saisie spontanée : le jeton est enregistré et annoncé", async () => {
    const { user } = renderWithProviders(<TokenHarness />);
    await user.click(screen.getByRole("button", { name: "Saisir le jeton" }));
    const dialog = screen.getByRole("dialog", { name: "Jeton d'API" });
    await user.type(within(dialog).getByLabelText("Jeton d'API"), "abc123");
    await user.click(within(dialog).getByRole("button", { name: "Valider" }));
    expect(window.sessionStorage.getItem("domainrecon.token")).toBe("abc123");
    expect(await screen.findByText("Jeton d'API enregistré pour cet onglet")).toBeInTheDocument();
  });

  it("démontée avec une saisie en attente, la boîte libère l'appel (401, sans jeton) au lieu de le laisser suspendu", async () => {
    mockFetch({ "/api/scan/1": needsToken({ accepted: 0 }) });
    const { unmount } = renderWithProviders(<p>page</p>);
    const call = apiFetch("/scan/1").catch((error: unknown) => error);
    await screen.findByRole("dialog", { name: "Jeton d'API" });
    unmount();
    const error = await call;
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(401);
  });
});
