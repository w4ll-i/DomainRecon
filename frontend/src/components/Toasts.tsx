import { CircleAlert, CircleCheck, Info, TriangleAlert, X } from "lucide-react";
import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import styles from "./Toasts.module.css";

export type ToastTone = "success" | "error" | "warning" | "info";

interface ToastItem {
  id: number;
  message: string;
  tone: ToastTone;
}

interface ToastApi {
  show: (message: string, tone?: ToastTone) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

const ICONS = { success: CircleCheck, error: CircleAlert, warning: TriangleAlert, info: Info };

// Minuterie d'une notification : le temps restant est gardé pour la reprise.
interface ToastTimer {
  handle: number | undefined;
  remaining: number;
  startedAt: number;
}

// Temps minimal laissé à une notification quand la pause se termine.
const MIN_RESUME_MS = 1500;

// Notification discrète ; erreurs et avertissements restent plus longtemps.
// Le survol et le focus clavier suspendent la disparition (WCAG 2.2.1) : le
// temps restant reprend à la sortie.
export function ToastProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(1);
  const timers = useRef(new Map<number, ToastTimer>());
  // Notifications survolées (par identifiant : une notification retirée sous la
  // souris ne laisse pas la pause en place) et focus dans la liste.
  const hovered = useRef(new Set<number>());
  const focused = useRef(false);
  // Identifiants affichés au dernier rendu (voir l'effet sur items).
  const displayed = useRef(new Set<number>());
  const list = useRef<HTMLUListElement>(null);

  const dismiss = useCallback((id: number) => {
    setItems((current) => current.filter((item) => item.id !== id));
    const timer = timers.current.get(id);
    if (timer?.handle !== undefined) window.clearTimeout(timer.handle);
    timers.current.delete(id);
    hovered.current.delete(id);
  }, []);

  const start = useCallback(
    (id: number, timer: ToastTimer) => {
      timer.startedAt = Date.now();
      timer.handle = window.setTimeout(() => dismiss(id), timer.remaining);
    },
    [dismiss],
  );

  // Suspend les minuteries tant que la souris survole ou que le focus est dans
  // une notification, les relance sinon.
  const sync = useCallback(() => {
    const paused = hovered.current.size > 0 || focused.current;
    timers.current.forEach((timer, id) => {
      if (paused && timer.handle !== undefined) {
        window.clearTimeout(timer.handle);
        timer.handle = undefined;
        timer.remaining = Math.max(0, timer.remaining - (Date.now() - timer.startedAt));
      } else if (!paused && timer.handle === undefined) {
        timer.remaining = Math.max(timer.remaining, MIN_RESUME_MS);
        start(id, timer);
      }
    });
  }, [start]);

  const show = useCallback(
    (message: string, tone: ToastTone = "info") => {
      const id = nextId.current++;
      setItems((current) => [...current.slice(-4), { id, message, tone }]);
      const timer: ToastTimer = {
        handle: undefined,
        remaining: tone === "error" || tone === "warning" ? 6000 : 3500,
        startedAt: 0,
      };
      timers.current.set(id, timer);
      // Arrivée pendant une pause : la minuterie démarre à la reprise (sync).
      sync();
    },
    [sync],
  );

  // Notification retirée alors qu'elle avait le focus : le navigateur n'envoie
  // pas toujours « blur », l'état est relu sur le DOM. Une notification évincée
  // par une nouvelle (5 au plus) n'envoie pas non plus « mouseleave » : son
  // survol et sa minuterie sont oubliés, sinon la pause resterait en place.
  // Seules les notifications déjà affichées sont concernées : une minuterie
  // créée par show peut précéder le rendu de sa notification.
  useEffect(() => {
    const present = new Set(items.map((item) => item.id));
    displayed.current.forEach((id) => {
      if (present.has(id)) return;
      hovered.current.delete(id);
      const timer = timers.current.get(id);
      if (timer?.handle !== undefined) window.clearTimeout(timer.handle);
      timers.current.delete(id);
    });
    displayed.current = present;
    focused.current = list.current?.contains(document.activeElement) ?? false;
    sync();
  }, [items, sync]);

  useEffect(() => {
    const pending = timers.current;
    return () =>
      pending.forEach((timer) => {
        if (timer.handle !== undefined) window.clearTimeout(timer.handle);
      });
  }, []);

  const api = useMemo(() => ({ show }), [show]);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className={styles.region} role="region" aria-label={t("toast.region")}>
        <ul
          ref={list}
          className={styles.list}
          aria-live="polite"
          onFocus={() => {
            focused.current = true;
            sync();
          }}
          onBlur={(event) => {
            if (event.currentTarget.contains(event.relatedTarget)) return;
            focused.current = false;
            sync();
          }}
        >
          {items.map((item) => {
            const Icon = ICONS[item.tone];
            return (
              <li
                key={item.id}
                className={styles.toast}
                data-tone={item.tone}
                onMouseEnter={() => {
                  hovered.current.add(item.id);
                  sync();
                }}
                onMouseLeave={() => {
                  hovered.current.delete(item.id);
                  sync();
                }}
              >
                <Icon aria-hidden className={styles.icon} />
                <span className={styles.message}>{item.message}</span>
                <button
                  type="button"
                  className={styles.close}
                  onClick={() => dismiss(item.id)}
                  aria-label={t("toast.close")}
                >
                  <X aria-hidden />
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const api = useContext(ToastContext);
  if (!api) throw new Error("useToast doit être utilisé sous ToastProvider");
  return api;
}
