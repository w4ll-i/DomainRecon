import { Activity, LoaderCircle, Moon, Search, ServerOff, Sun, TriangleAlert } from "lucide-react";
import { Suspense, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, NavLink, Outlet, useLocation } from "react-router";
import { type HealthState, useHealth, useHeartbeat } from "../api/queries";
import { Loading } from "../components/PageState";
import { Onboarding } from "../features/onboarding/Onboarding";
import { useTheme } from "../lib/theme";
import logoUrl from "../assets/favicon.svg";
import styles from "./AppShell.module.css";
import { CommandPalette } from "./CommandPalette";
import { NAV_PAGES } from "./pages";

const navClass = ({ isActive }: { isActive: boolean }) => (isActive ? `${styles.link} ${styles.active}` : styles.link);

// Bascule clair / sombre : le bouton dit l'action (« Passer au thème clair »), son
// icône montre le thème vers lequel il mène. Le choix est mémorisé (lib/theme.ts).
// La langue se règle à un seul endroit : l'écran Réglages.
function ThemeToggle() {
  const { t } = useTranslation();
  const { theme, toggle } = useTheme();
  const Icon = theme === "dark" ? Sun : Moon;
  return (
    <button type="button" className={`${styles.link} ${styles.themeToggle}`} onClick={toggle}>
      <Icon aria-hidden />
      <span className={styles.linkText}>{t(theme === "dark" ? "shell.theme.toLight" : "shell.theme.toDark")}</span>
    </button>
  );
}

// État du serveur : une icône et le texte qui le dit.
const SERVER_ICONS = { online: Activity, degraded: TriangleAlert, offline: ServerOff } as const;

function ServerStatus() {
  const { t } = useTranslation();
  const health = useHealth();
  const state: HealthState | undefined = health.data?.state;
  const Icon = state ? SERVER_ICONS[state] : LoaderCircle;
  return (
    <p className={styles.server} data-state={state ?? "checking"} role="status">
      <Icon aria-hidden className={state ? undefined : "spin"} />
      <span>{t(state ? `server.${state}` : "server.checking")}</span>
    </p>
  );
}

export function AppShell() {
  const { t } = useTranslation();
  const location = useLocation();
  const main = useRef<HTMLElement>(null);
  const previousPath = useRef(location.pathname);
  const [paletteOpen, setPaletteOpen] = useState(false);
  // Onglet ouvert : signalé au serveur (arrêt automatique du mode navigateur).
  // Serveur qui ne répond plus après avoir répondu : arrêté, à relancer.
  const serverStopped = useHeartbeat();

  // Ctrl+K (Cmd+K sur Mac) ouvre ou ferme la palette de commandes, de n'importe où.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  // Changement d'écran : le focus passe au contenu (clavier, lecteurs d'écran).
  useEffect(() => {
    if (previousPath.current === location.pathname) return;
    previousPath.current = location.pathname;
    // Ce effet s'exécute après ceux de l'écran : un champ de saisie qui a pris
    // le focus à son montage (autoFocus de « Nouveau scan ») le garde, et un onglet
    // choisi au clavier (l'adresse change avec lui) aussi.
    const active = document.activeElement;
    // Une fenêtre modale ouverte (palette de commandes…) garde le focus : l'écran suivant, chargé à la
    // demande, peut s'afficher après l'ouverture de la palette et ne doit pas le lui prendre.
    if (active instanceof HTMLElement && active.closest("[aria-modal='true']")) return;
    if (
      active instanceof HTMLElement &&
      main.current?.contains(active) &&
      active.matches("input, textarea, select, [contenteditable], [role=tab]")
    ) {
      return;
    }
    main.current?.focus();
  }, [location.pathname]);

  return (
    <div className={styles.shell}>
      <a href="#main" className={styles.skip}>
        {t("nav.skip")}
      </a>
      <aside className={styles.sidebar}>
        <Link to="/" className={styles.brand}>
          <img src={logoUrl} alt="" aria-hidden className={styles.brandMark} />
          <span className={styles.brandName}>DomainRecon</span>
        </Link>
        <nav className={styles.nav} aria-label={t("nav.label")} data-tour="nav">
          <ul className={styles.navList}>
            {NAV_PAGES.map((page) => {
              const Icon = page.icon;
              return (
                <li key={page.key}>
                  <NavLink to={page.to} end={page.end} className={navClass} data-tour={`nav-${page.key}`}>
                    <Icon aria-hidden />
                    <span className={styles.linkText}>{t(page.labelKey)}</span>
                  </NavLink>
                </li>
              );
            })}
          </ul>
        </nav>
        <div className={styles.footer}>
          <ThemeToggle />
        </div>
      </aside>
      <div className={styles.content}>
        <header className="app-header">
          <button
            type="button"
            className={styles.paletteButton}
            data-tour="palette"
            onClick={() => setPaletteOpen(true)}
            aria-label={t("palette.open")}
            aria-haspopup="dialog"
          >
            <Search aria-hidden />
            <span className={styles.paletteText}>{t("palette.placeholder")}</span>
            <kbd className={styles.kbd}>{t("palette.shortcut")}</kbd>
          </button>
          <ServerStatus />
        </header>
        <main id="main" ref={main} tabIndex={-1} className={styles.main}>
          {serverStopped && (
            <p className={styles.stopped} role="alert">
              {t("server.stopped")}
            </p>
          )}
          {/* Les écrans sont chargés à la demande (router.tsx) : état de chargement sobre, coquille en place. */}
          <Suspense fallback={<Loading />}>
            <Outlet />
          </Suspense>
        </main>
      </div>
      <Onboarding />
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  );
}
