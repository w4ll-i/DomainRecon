import { useEffect, useReducer } from "react";
import { ApiError } from "../../api/client";
import { streamJobEvents } from "../../api/sse";
import i18n, { useLang } from "../../i18n";
import { initialLiveState, type LiveState, liveReducer } from "./liveReducer";

const MAX_RECONNECTS = 5;
const TERMINAL_EVENTS = new Set(["done", "failed", "cancelled"]);

function wait(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = window.setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        window.clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}

// Abonnement au flux de la tâche. Coupure sans événement final : nouvelle
// connexion (le serveur rejoue tout, le réducteur est idempotent). Une 4xx
// (tâche inconnue après redémarrage du serveur, jeton refusé) arrête le suivi.
export function useJobEvents(jobId: string): LiveState {
  const lang = useLang();
  const [state, dispatch] = useReducer(liveReducer, initialLiveState);

  useEffect(() => {
    const controller = new AbortController();
    let attempts = 0;

    const run = async () => {
      for (;;) {
        let terminal = false;
        try {
          await streamJobEvents(jobId, {
            lang,
            signal: controller.signal,
            onEvent: (event) => {
              // Remis à zéro au premier événement reçu, pas à l'ouverture : un
              // flux ouvert puis fermé sans rien émettre compte comme un échec.
              attempts = 0;
              if (TERMINAL_EVENTS.has(event.event)) terminal = true;
              dispatch({ type: "event", event });
            },
          });
        } catch (error) {
          if (controller.signal.aborted) return;
          if (error instanceof ApiError && error.status >= 400 && error.status < 500) {
            // 404 (tâche inconnue) et 422 (identifiant refusé) : même message, clair.
            const unknown = error.status === 404 || error.status === 422;
            dispatch({ type: "lost", detail: unknown ? i18n.t("live.jobNotFound") : error.detail });
            return;
          }
        }
        if (terminal || controller.signal.aborted) return;
        attempts += 1;
        if (attempts > MAX_RECONNECTS) {
          dispatch({ type: "lost", detail: i18n.t("live.connectionLost") });
          return;
        }
        await wait(Math.min(500 * attempts, 5000), controller.signal);
        if (controller.signal.aborted) return;
      }
    };

    void run();
    return () => controller.abort();
  }, [jobId, lang]);

  return state;
}
