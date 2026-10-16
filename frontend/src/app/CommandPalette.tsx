import { Compass, type LucideIcon, Radar, ShieldCheck } from "lucide-react";
import { type KeyboardEvent, useId, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { useRecentScans } from "../api/queries";
import type { ScanSummary } from "../api/types";
import { Modal } from "../components/Modal";
import { startGuidedTour } from "../features/onboarding/onboardingEvents";
import { useLaunchScan } from "../features/newscan/useLaunchScan";
import { looksLikeDomain } from "./looksLikeDomain";
import { NAV_PAGES } from "./pages";
import styles from "./CommandPalette.module.css";

interface Command {
  id: string;
  group: "actions" | "pages" | "recent";
  label: string;
  icon: LucideIcon;
  run: () => void;
}

const GROUPS = ["actions", "pages", "recent"] as const;
// Référence stable tant que les scans récents ne sont pas arrivés (clé de useMemo).
const NO_SCANS: ScanSummary[] = [];

// Palette de commandes (Ctrl+K) : scanner un domaine, aller à une page, rouvrir un scan
// récent. Le champ est un combobox ; les flèches choisissent, Entrée valide, Échap ferme.
// La fenêtre n'existe que tant qu'elle est ouverte : chaque ouverture repart d'une saisie vide
// (la dernière recherche ne masque pas les scans récents). Les scans récents sont lus dès le
// chargement de l'écran pour être prêts à l'ouverture, et le lancement d'un scan reste ici : la
// fenêtre se ferme avant que le serveur ait répondu, l'ouverture du suivi en direct ne doit pas
// disparaître avec elle.
export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const recent = useRecentScans(5);
  const { launch } = useLaunchScan("toast");
  if (!open) return null;
  return <PaletteDialog scans={recent.data?.scans ?? NO_SCANS} launch={launch} onClose={onClose} />;
}

function PaletteDialog({
  scans,
  launch,
  onClose,
}: {
  scans: ScanSummary[];
  launch: (domain: string) => boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const titleId = useId();
  const listId = useId();

  const commands = useMemo(() => {
    const text = query.trim();
    const needle = text.toLowerCase();
    const go = (to: string) => () => {
      onClose();
      navigate(to);
    };
    const list: Command[] = [];
    if (text.length > 0 && looksLikeDomain(text)) {
      list.push({
        id: "scan",
        group: "actions",
        label: t("palette.scanDomain", { domain: text }),
        icon: Radar,
        run: () => {
          onClose();
          launch(text);
        },
      });
    }
    // Relance de la visite guidée : proposée dès que la saisie correspond à son nom ou à l'un de
    // ses mots-clés (« visite », « tutoriel », « guide »…), pour ne pas allonger la liste par défaut.
    const tourLabel = t("onboarding.palette.label");
    const tourWords = `${tourLabel} ${t("onboarding.palette.keywords")}`.toLowerCase().split(/\s+/);
    if (needle !== "" && (tourLabel.toLowerCase().includes(needle) || tourWords.some((word) => word.startsWith(needle)))) {
      list.push({
        id: "tour",
        group: "actions",
        label: tourLabel,
        icon: Compass,
        run: () => {
          onClose();
          startGuidedTour();
        },
      });
    }
    for (const page of NAV_PAGES) {
      const label = t(page.labelKey);
      if (needle === "" || label.toLowerCase().includes(needle)) {
        list.push({ id: `page-${page.key}`, group: "pages", label, icon: page.icon, run: go(page.to) });
      }
    }
    for (const scan of scans) {
      if (needle === "" || scan.domain.toLowerCase().includes(needle)) {
        list.push({
          id: `scan-${scan.id}`,
          group: "recent",
          label: t("palette.openScan", { domain: scan.domain }),
          icon: ShieldCheck,
          run: go(`/scans/${scan.id}`),
        });
      }
    }
    return list;
    // `launch` change à chaque rendu (fermeture sur l'état du hook) : la liste se
    // recalcule donc avec lui, sans coût sensible (une vingtaine d'entrées).
  }, [query, scans, t, navigate, onClose, launch]);

  const current = Math.min(active, Math.max(0, commands.length - 1));

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (commands.length === 0) return;
      const step = event.key === "ArrowDown" ? 1 : -1;
      setActive((current + step + commands.length) % commands.length);
    } else if (event.key === "Enter") {
      event.preventDefault();
      commands[current]?.run();
    }
  };

  return (
    <Modal open labelledBy={titleId} onCancel={onClose} variant="palette">
      <div className={styles.palette}>
        <h2 id={titleId} className="visually-hidden">
          {t("palette.title")}
        </h2>
        <input
          className={styles.input}
          type="text"
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={commands[current] ? `${listId}-${commands[current].id}` : undefined}
          aria-label={t("palette.placeholder")}
          placeholder={t("palette.placeholder")}
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setActive(0);
          }}
          onKeyDown={onKeyDown}
          autoComplete="off"
          spellCheck={false}
        />
        <div id={listId} role="listbox" aria-label={t("palette.results")} className={styles.list}>
          {commands.length === 0 && <p className={styles.empty}>{t("palette.empty")}</p>}
          {GROUPS.map((group) => {
            const items = commands.filter((command) => command.group === group);
            if (items.length === 0) return null;
            return (
              <div key={group} role="presentation">
                <p className={styles.group} role="presentation">
                  {t(`palette.groups.${group}`)}
                </p>
                {items.map((command) => {
                  const Icon = command.icon;
                  const selected = commands[current]?.id === command.id;
                  return (
                    <div
                      key={command.id}
                      id={`${listId}-${command.id}`}
                      role="option"
                      aria-selected={selected}
                      className={styles.option}
                      onMouseMove={() => setActive(commands.indexOf(command))}
                      onClick={command.run}
                    >
                      <Icon aria-hidden />
                      <span>{command.label}</span>
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>
        <p className={styles.hint}>{t("palette.hint")}</p>
      </div>
    </Modal>
  );
}
