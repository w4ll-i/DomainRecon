import { ChevronDown, ChevronLeft, ChevronRight } from "lucide-react";
import { type KeyboardEvent, useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { tabId, tabPanelId } from "../lib/tabs";
import type { Tone } from "../lib/tones";
import { CountBadge } from "./CountBadge";
import styles from "./Tabs.module.css";

export interface TabItem {
  key: string;
  label: string;
  // Compte affiché dans une pastille après le libellé.
  count?: number;
  // Ton de la pastille (voir CountBadge).
  tone?: Tone;
}

interface TabsProps {
  tabs: readonly TabItem[];
  activeKey: string;
  onChange: (key: string) => void;
  // Nom accessible de la liste d'onglets.
  label?: string;
  // Préfixe des identifiants (voir lib/tabs.ts) ; généré sinon.
  idPrefix?: string;
}

// Onglet visé par une touche de navigation (en boucle), null pour toute autre touche.
// `previous` / `next` : les touches qui reculent et avancent (gauche / droite pour la
// rangée, haut / bas pour la liste de tous les onglets).
function targetIndex(key: string, index: number, last: number, previous = "ArrowLeft", next = "ArrowRight"): number | null {
  switch (key) {
    case next:
      return index === last ? 0 : index + 1;
    case previous:
      return index === 0 ? last : index - 1;
    case "Home":
      return 0;
    case "End":
      return last;
    default:
      return null;
  }
}

// Ce que la rangée laisse voir : déborde-t-elle, et reste-t-il des onglets cachés au
// début ou à la fin ?
interface Edges {
  overflow: boolean;
  start: boolean;
  end: boolean;
}

const NO_EDGES: Edges = { overflow: false, start: false, end: false };
// Marge gardée autour de l'onglet actif quand la rangée le ramène à l'écran : il ne
// reste pas sous le fondu du bord.
const REVEAL_MARGIN = 40;

const sameEdges = (a: Edges, b: Edges) => a.overflow === b.overflow && a.start === b.start && a.end === b.end;

function measureEdges(element: HTMLElement): Edges {
  const max = element.scrollWidth - element.clientWidth;
  if (max <= 1) return NO_EDGES;
  return { overflow: true, start: element.scrollLeft > 1, end: element.scrollLeft < max - 1 };
}

// Défilement de la rangée : doux, sauf si l'utilisateur réduit les animations ou pour
// le placement initial.
function scrollRow(element: HTMLElement, left: number, smooth: boolean) {
  const target = Math.max(0, Math.min(left, element.scrollWidth - element.clientWidth));
  const reduce = typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (typeof element.scrollTo === "function") element.scrollTo({ left: target, behavior: smooth && !reduce ? "smooth" : "auto" });
  else element.scrollLeft = target;
}

// Onglets soulignés d'un trait d'accent (modèle WAI-ARIA, activation automatique) :
// flèches gauche et droite (en boucle), Début et Fin déplacent le focus et
// l'onglet actif ; un seul onglet est atteignable à la tabulation (tabindex
// itinérant). Le panneau est celui de l'appelant (voir lib/tabs.ts pour ses id).
// Quand la rangée ne tient pas, elle défile sans barre native : fondus aux bords,
// boutons précédent / suivant, défilement automatique vers l'onglet actif, et un
// menu « Tous les onglets » qui les liste en entier.
export function Tabs({ tabs, activeKey, onChange, label, idPrefix }: TabsProps) {
  const generated = useId();
  const prefix = idPrefix ?? generated;
  const buttons = useRef<Array<HTMLButtonElement | null>>([]);
  const row = useRef<HTMLDivElement>(null);
  const placed = useRef(false);
  const [edges, setEdges] = useState<Edges>(NO_EDGES);
  const found = tabs.findIndex((tab) => tab.key === activeKey);
  // Clé active inconnue : le premier onglet reste atteignable au clavier.
  const tabbable = found >= 0 ? found : 0;

  const measure = useCallback(() => {
    const element = row.current;
    if (!element) return;
    const next = measureEdges(element);
    setEdges((previous) => (sameEdges(previous, next) ? previous : next));
  }, []);

  // Défilement, taille de la fenêtre, chargement des polices : la rangée se remesure.
  useEffect(() => {
    const element = row.current;
    if (!element) return undefined;
    element.addEventListener("scroll", measure, { passive: true });
    void document.fonts?.ready.then(() => {
      measure();
      revealRef.current(false);
    });
    // Molette verticale sur une rangée qui déborde : elle défile à l'horizontale tant
    // qu'il reste des onglets dans ce sens, puis rend la main à la page.
    const onWheel = (event: WheelEvent) => {
      if (Math.abs(event.deltaY) <= Math.abs(event.deltaX)) return;
      const max = element.scrollWidth - element.clientWidth;
      if (max <= 1) return;
      const canScroll = event.deltaY > 0 ? element.scrollLeft < max - 1 : element.scrollLeft > 1;
      if (!canScroll) return;
      event.preventDefault();
      element.scrollLeft += event.deltaY;
    };
    element.addEventListener("wheel", onWheel, { passive: false });
    return () => {
      element.removeEventListener("scroll", measure);
      element.removeEventListener("wheel", onWheel);
    };
  }, [measure]);

  // Taille de la rangée ou d'un onglet changée (fenêtre, polices chargées après le
  // placement) : remesure, et l'onglet actif est ramené à l'écran s'il en est sorti.
  useEffect(() => {
    const element = row.current;
    if (!element || typeof ResizeObserver === "undefined") return undefined;
    const observer = new ResizeObserver(() => {
      measure();
      revealRef.current(false);
    });
    observer.observe(element);
    for (const button of buttons.current) if (button) observer.observe(button);
    return () => observer.disconnect();
  }, [tabs, measure]);

  // Libellés changés (langue, comptes) : la largeur du contenu change, pas celle de la rangée.
  useLayoutEffect(measure, [tabs, measure]);

  // L'onglet actif reste visible : à l'ouverture (lien profond vers le 20e onglet),
  // après un choix au clavier ou dans le menu.
  const reveal = useCallback(
    (smooth: boolean) => {
      const element = row.current;
      const tab = found >= 0 ? buttons.current[found] : null;
      if (!element || !tab || element.scrollWidth - element.clientWidth <= 1) return;
      const left = tab.offsetLeft;
      const right = left + tab.offsetWidth;
      // Onglet plus large que la rangée (libellé long sur mobile) : son début reste lisible.
      const room = element.clientWidth - tab.offsetWidth;
      if (room <= 0) {
        if (Math.abs(element.scrollLeft - left) > 1) scrollRow(element, left, smooth);
        return;
      }
      // Rangée étroite : la marge se partage de part et d'autre de l'onglet.
      const margin = Math.min(REVEAL_MARGIN, room / 2);
      if (left - margin < element.scrollLeft) scrollRow(element, left - margin, smooth);
      else if (right + margin > element.scrollLeft + element.clientWidth) {
        scrollRow(element, right + margin - element.clientWidth, smooth);
      }
    },
    [found],
  );
  // Dernière version de reveal, lue par l'observateur de taille et le chargement des polices.
  const revealRef = useRef(reveal);
  useLayoutEffect(() => {
    revealRef.current = reveal;
  }, [reveal]);

  useLayoutEffect(() => {
    if (!edges.overflow) return;
    const smooth = placed.current;
    placed.current = true;
    reveal(smooth);
  }, [reveal, edges.overflow]);

  const move = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const target = targetIndex(event.key, index, tabs.length - 1);
    if (target === null) return;
    event.preventDefault();
    buttons.current[target]?.focus();
    if (tabs[target].key !== activeKey) onChange(tabs[target].key);
  };

  // Les boutons précédent / suivant avancent d'environ une largeur de rangée.
  const page = (direction: -1 | 1) => {
    const element = row.current;
    if (!element) return;
    scrollRow(element, element.scrollLeft + direction * element.clientWidth * 0.8, true);
  };

  // Choix dans le menu : l'onglet devient actif et reprend le focus.
  const pick = (key: string) => {
    const index = tabs.findIndex((tab) => tab.key === key);
    buttons.current[index]?.focus();
    if (key !== activeKey) onChange(key);
  };

  return (
    <div
      className={styles.root}
      data-overflow={edges.overflow || undefined}
      data-start={edges.start || undefined}
      data-end={edges.end || undefined}
    >
      {edges.overflow && <ScrollButton direction={-1} disabled={!edges.start} onClick={() => page(-1)} />}
      <div ref={row} className={styles.list} role="tablist" aria-label={label}>
        {tabs.map((tab, index) => (
          <button
            key={tab.key}
            ref={(element) => {
              buttons.current[index] = element;
            }}
            type="button"
            role="tab"
            id={tabId(prefix, tab.key)}
            className={styles.tab}
            aria-selected={index === found}
            aria-controls={tabPanelId(prefix)}
            tabIndex={index === tabbable ? 0 : -1}
            onClick={() => onChange(tab.key)}
            onKeyDown={(event) => move(event, index)}
          >
            <span className={styles.label}>{tab.label}</span>
            {tab.count !== undefined && (
              <>
                {/* Espace entre libellé et compte : le nom accessible se lit « Web 3 ». */}{" "}
                <CountBadge count={tab.count} tone={tab.tone} />
              </>
            )}
          </button>
        ))}
      </div>
      {edges.overflow && <ScrollButton direction={1} disabled={!edges.end} onClick={() => page(1)} />}
      {edges.overflow && <AllTabsMenu tabs={tabs} activeKey={activeKey} label={label} onPick={pick} />}
    </div>
  );
}

// Bouton de défilement d'un bord. Hors de la tabulation : au clavier, les flèches
// parcourent déjà les onglets et la rangée suit l'onglet actif.
function ScrollButton({ direction, disabled, onClick }: { direction: -1 | 1; disabled: boolean; onClick: () => void }) {
  const { t } = useTranslation();
  const Icon = direction < 0 ? ChevronLeft : ChevronRight;
  return (
    <button
      type="button"
      className={styles.scroll}
      data-side={direction < 0 ? "start" : "end"}
      tabIndex={-1}
      disabled={disabled}
      aria-label={t(direction < 0 ? "tabsNav.previous" : "tabsNav.next")}
      onClick={onClick}
    >
      <Icon aria-hidden />
    </button>
  );
}

interface AllTabsMenuProps {
  tabs: readonly TabItem[];
  activeKey: string;
  label?: string;
  onPick: (key: string) => void;
}

// Menu « Tous les onglets » : chaque onglet en toutes lettres, avec sa pastille, sur
// plusieurs colonnes ; l'onglet actif est coché. Flèches haut / bas, Début, Fin,
// Échap (retour au bouton) ; un clic ailleurs ou la tabulation le referme.
function AllTabsMenu({ tabs, activeKey, label, onPick }: AllTabsMenuProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const items = useRef<Array<HTMLButtonElement | null>>([]);
  const menuId = useId();
  const active = tabs.findIndex((tab) => tab.key === activeKey);

  useEffect(() => {
    if (!open) return undefined;
    items.current[active >= 0 ? active : 0]?.focus();
    const onPointer = (event: MouseEvent) => {
      if (root.current && !root.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onPointer);
    return () => document.removeEventListener("mousedown", onPointer);
    // Le focus se pose à l'ouverture seulement, pas à chaque changement d'onglet.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const close = () => {
    setOpen(false);
    trigger.current?.focus();
  };

  const onTriggerKey = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      setOpen(true);
    } else if (event.key === "Escape" && open) {
      event.preventDefault();
      setOpen(false);
    }
  };

  const onItemKey = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    if (event.key === "Escape") {
      event.preventDefault();
      close();
      return;
    }
    if (event.key === "Tab") {
      setOpen(false);
      return;
    }
    const target = targetIndex(event.key, index, tabs.length - 1, "ArrowUp", "ArrowDown");
    if (target === null) return;
    event.preventDefault();
    items.current[target]?.focus();
  };

  return (
    <div className={styles.more} ref={root}>
      <button
        ref={trigger}
        type="button"
        className={styles.moreButton}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((value) => !value)}
        onKeyDown={onTriggerKey}
      >
        {/* Nom accessible : « Tous les onglets 35 » ; à l'écran, « Tous » et le compte. */}
        <span>{t("tabsNav.all")}</span> <span className="visually-hidden">{t("tabsNav.allHidden")}</span>{" "}
        <CountBadge count={tabs.length} />
        <ChevronDown aria-hidden className={styles.chevron} />
      </button>
      {open && (
        <ul className={styles.menu} role="menu" id={menuId} aria-label={label ? t("tabsNav.menuOf", { label }) : t("tabsNav.menu")}>
          {tabs.map((tab, index) => (
            <li key={tab.key} role="none">
              <button
                ref={(element) => {
                  items.current[index] = element;
                }}
                type="button"
                role="menuitemradio"
                aria-checked={index === active}
                tabIndex={-1}
                className={styles.item}
                onClick={() => {
                  setOpen(false);
                  onPick(tab.key);
                }}
                onKeyDown={(event) => onItemKey(event, index)}
              >
                <span className={styles.itemLabel}>{tab.label}</span>
                {tab.count !== undefined && (
                  <>
                    {" "}
                    <CountBadge count={tab.count} tone={tab.tone} />
                  </>
                )}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
