import { type KeyboardEvent, useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import { useLocation, useNavigate } from "react-router";
import { type Box, computePlacement, cutout } from "./placement";
import { findTarget, type TourStep } from "./steps";
import styles from "./GuidedTour.module.css";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])';
// Intervalle de recherche d'un élément pas encore affiché (écran chargé à la demande).
const POLL_MS = 50;
const SAME_SCREEN_WAIT_MS = 400;

interface GuidedTourProps {
  steps: readonly TourStep[];
  onClose: () => void;
  // Attente maximale d'un élément sur un écran ouvert par la visite, avant de sauter l'étape.
  waitMs?: number;
}

const sameBox = (a: Box | null, b: Box | null) =>
  a === b || (!!a && !!b && a.top === b.top && a.left === b.left && a.width === b.width && a.height === b.height);

const viewport = () => ({
  width: document.documentElement.clientWidth || window.innerWidth,
  height: document.documentElement.clientHeight || window.innerHeight,
});

const reducedMotion = () =>
  typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// Fait défiler jusqu'à l'élément s'il n'est pas entièrement visible (sans animation si
// l'utilisateur a demandé à réduire les mouvements).
function revealTarget(element: HTMLElement) {
  if (typeof element.scrollIntoView !== "function") return;
  const rect = element.getBoundingClientRect();
  const view = viewport();
  if (rect.top >= 0 && rect.left >= 0 && rect.bottom <= view.height && rect.right <= view.width) return;
  // Élément plus haut que la moitié de l'écran : son début en haut, la bulle trouve place dessous.
  const block = rect.height > view.height / 2 ? "start" : "center";
  element.scrollIntoView({ block, inline: "nearest", behavior: reducedMotion() ? "auto" : "smooth" });
}

// Visite guidée : un voile sombre couvre l'interface, découpé autour de l'élément expliqué, et
// une bulle placée à côté (jamais hors de l'écran, replacée au redimensionnement et au
// défilement). Clavier : flèches gauche et droite, Entrée pour avancer, Échap pour quitter ;
// le focus reste dans la bulle et revient où il était à la fin. Une étape dont l'élément manque
// est sautée.
export function GuidedTour({ steps, onClose, waitMs = 3000 }: GuidedTourProps) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const pathRef = useRef(pathname);
  const [skipped, setSkipped] = useState<ReadonlySet<string>>(() => new Set());
  const [index, setIndex] = useState(0);
  const direction = useRef<1 | -1>(1);
  const [found, setFound] = useState<{ key: string; element: HTMLElement | null } | null>(null);
  const [box, setBox] = useState<Box | null>(null);
  const bubble = useRef<HTMLDivElement>(null);
  const primary = useRef<HTMLButtonElement>(null);
  const [previousFocus] = useState(() => (document.activeElement instanceof HTMLElement ? document.activeElement : null));
  const titleId = useId();
  const textId = useId();

  useEffect(() => {
    pathRef.current = pathname;
  }, [pathname]);

  const visible = useMemo(() => steps.filter((step) => !skipped.has(step.key)), [steps, skipped]);
  const step = visible[index] as TourStep | undefined;
  const current = found && step && found.key === step.key ? found : null;
  const last = index >= visible.length - 1;

  // Plus d'étape (fin de liste, ou dernières étapes sautées) : la visite se termine.
  useEffect(() => {
    if (!step) onClose();
  }, [step, onClose]);

  // Ouvre l'écran de l'étape, puis attend son élément ; introuvable, l'étape est sautée dans le
  // sens du parcours (en arrière avec « Précédent »).
  useEffect(() => {
    if (!step) return undefined;
    const navigated = !!step.route && pathRef.current !== step.route;
    if (navigated && step.route) navigate(step.route);
    const selector = step.target;
    if (!selector) {
      setFound({ key: step.key, element: null });
      return undefined;
    }
    // Écran ouvert à l'instant : on attend son chargement. Déjà ouvert : courte attente (données
    // en cours de chargement). Élément de la coquille : présent ou absent tout de suite.
    const deadline = Date.now() + (navigated ? waitMs : step.route ? Math.min(waitMs, SAME_SCREEN_WAIT_MS) : 0);
    let timer: number | undefined;
    const attempt = () => {
      const element = findTarget(selector);
      if (element) {
        revealTarget(element);
        setFound({ key: step.key, element });
        return;
      }
      if (Date.now() < deadline) {
        timer = window.setTimeout(attempt, POLL_MS);
        return;
      }
      setSkipped((previous) => new Set(previous).add(step.key));
      if (direction.current === -1) setIndex((value) => Math.max(0, value - 1));
    };
    attempt();
    return () => window.clearTimeout(timer);
  }, [step, navigate, waitMs]);

  // Position de l'élément suivie au défilement (de la page ou d'un conteneur) et au
  // redimensionnement ; elle fixe la découpe du voile.
  // Élément remplacé par un nouveau rendu de l'écran (même ancrage, autre nœud) : retrouvé.
  const element = current?.element ?? null;
  const currentKey = current?.key;
  const selector = step?.target ?? null;
  useEffect(() => {
    const measure = () => {
      if (element && !element.isConnected && selector && currentKey) {
        const again = findTarget(selector);
        if (again) {
          setFound({ key: currentKey, element: again });
          return;
        }
      }
      const next = element && element.isConnected ? cutout(element.getBoundingClientRect(), viewport()) : null;
      setBox((previous) => (sameBox(previous, next) ? previous : next));
    };
    measure();
    window.addEventListener("resize", measure);
    window.addEventListener("scroll", measure, true);
    const observer = typeof ResizeObserver === "function" && element ? new ResizeObserver(measure) : null;
    if (element) observer?.observe(element);
    return () => {
      window.removeEventListener("resize", measure);
      window.removeEventListener("scroll", measure, true);
      observer?.disconnect();
    };
  }, [element, selector, currentKey]);

  // Bulle placée d'après sa taille réelle : propriétés CSSOM (permises par la CSP stricte, qui
  // interdit l'attribut style écrit dans le HTML) et côté dans data-side pour la flèche.
  const place = useCallback(() => {
    const node = bubble.current;
    if (!node) return;
    const rect = element ? element.getBoundingClientRect() : null;
    const placement = computePlacement(rect, { width: node.offsetWidth, height: node.offsetHeight }, viewport());
    node.style.setProperty("top", `${Math.round(placement.top)}px`);
    node.style.setProperty("left", `${Math.round(placement.left)}px`);
    node.style.setProperty("--tour-arrow", `${Math.round(placement.arrow)}px`);
    node.dataset.side = placement.side;
    node.dataset.placed = "true";
  }, [element]);

  useLayoutEffect(() => {
    if (current) place();
  });

  useEffect(() => {
    if (!current) return undefined;
    const node = bubble.current;
    const observer = typeof ResizeObserver === "function" && node ? new ResizeObserver(place) : null;
    if (node) observer?.observe(node);
    return () => observer?.disconnect();
  }, [current, place]);

  // Chaque nouvelle étape met le focus sur son bouton principal.
  useEffect(() => {
    if (currentKey) primary.current?.focus();
  }, [currentKey]);

  // Focus piégé : un élément de la page qui le prendrait (champ autoFocus d'un écran ouvert par
  // la visite, clic) le rend aussitôt à la bulle.
  useEffect(() => {
    const onFocusIn = (event: FocusEvent) => {
      const node = bubble.current;
      if (node && event.target instanceof Node && !node.contains(event.target)) primary.current?.focus();
    };
    document.addEventListener("focusin", onFocusIn);
    return () => document.removeEventListener("focusin", onFocusIn);
  }, []);

  // Fin de la visite : le focus revient à l'élément actif au départ, ou au contenu principal.
  useEffect(
    () => () => {
      const target = previousFocus && previousFocus.isConnected ? previousFocus : document.getElementById("main");
      target?.focus();
    },
    [previousFocus],
  );

  const next = () => {
    direction.current = 1;
    if (last) onClose();
    else setIndex(index + 1);
  };
  const previous = () => {
    direction.current = -1;
    setIndex(Math.max(0, index - 1));
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    // La palette (Ctrl+K) ne s'ouvre pas par-dessus la visite.
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      event.stopPropagation();
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
    } else if (event.key === "ArrowRight") {
      event.preventDefault();
      next();
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      if (index > 0) previous();
    } else if (event.key === "Enter" && !(event.target instanceof HTMLButtonElement || event.target instanceof HTMLAnchorElement)) {
      event.preventDefault();
      next();
    } else if (event.key === "Tab" && bubble.current) {
      const items = [...bubble.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
      if (!items.length) return;
      const first = items[0];
      const end = items[items.length - 1];
      const active = document.activeElement;
      if (event.shiftKey && (active === first || active === bubble.current)) {
        event.preventDefault();
        end.focus();
      } else if (!event.shiftKey && active === end) {
        event.preventDefault();
        first.focus();
      }
    }
  };

  const key = current?.key;
  const title = key ? t(`onboarding.steps.${key}.title`) : "";
  const counter = t("onboarding.tour.step", { current: index + 1, total: visible.length });
  const points = step?.points ?? 0;

  return createPortal(
    <div className={styles.root} data-testid="guided-tour">
      {/* Voile : il bloque les clics sur l'interface sans prendre le focus à la bulle. */}
      <svg
        className={styles.shade}
        width="100%"
        height="100%"
        aria-hidden="true"
        focusable="false"
        onMouseDown={(event) => event.preventDefault()}
      >
        <defs>
          <mask id="guided-tour-mask">
            <rect width="100%" height="100%" fill="white" />
            {box && <rect x={box.left} y={box.top} width={box.width} height={box.height} rx="8" fill="black" />}
          </mask>
        </defs>
        <rect className={styles.veil} width="100%" height="100%" mask="url(#guided-tour-mask)" />
        {box && <rect className={styles.ring} x={box.left} y={box.top} width={box.width} height={box.height} rx="8" />}
      </svg>
      <p className="visually-hidden" aria-live="polite">
        {key ? t("onboarding.tour.announce", { step: counter, title }) : ""}
      </p>
      {key && (
        <div
          ref={bubble}
          className={styles.bubble}
          role="dialog"
          aria-modal="true"
          aria-labelledby={titleId}
          aria-describedby={textId}
          tabIndex={-1}
          onKeyDown={onKeyDown}
          data-step={key}
        >
          <span className={styles.arrow} aria-hidden="true" />
          <div className={styles.content}>
            <p className={styles.counter}>{counter}</p>
            <h2 id={titleId} className={styles.title}>
              {title}
            </h2>
            <p id={textId} className={styles.text}>
              {t(`onboarding.steps.${key}.text`)}
            </p>
            {points > 0 && (
              <ul className={styles.points}>
                {Array.from({ length: points }, (_, point) => (
                  <li key={point}>{t(`onboarding.steps.${key}.point${point + 1}`)}</li>
                ))}
              </ul>
            )}
            <div className={styles.actions}>
              {!last && (
                <button type="button" className="btn" data-variant="ghost" onClick={onClose}>
                  {t("onboarding.tour.skip")}
                </button>
              )}
              <span className={styles.spacer} />
              {index > 0 && (
                <button type="button" className="btn" onClick={previous}>
                  {t("onboarding.tour.previous")}
                </button>
              )}
              <button ref={primary} type="button" className="btn" data-variant="primary" onClick={next}>
                {t(last ? "onboarding.tour.finish" : "onboarding.tour.next")}
              </button>
            </div>
            <p className={styles.keys}>{t("onboarding.tour.keys")}</p>
          </div>
        </div>
      )}
    </div>,
    document.body,
  );
}
