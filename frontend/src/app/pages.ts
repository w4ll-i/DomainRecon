import {
  Activity,
  CircleHelp,
  Files,
  GitCompare,
  History,
  LayoutDashboard,
  type LucideIcon,
  Search,
  Settings,
} from "lucide-react";

// Écrans du menu latéral et de la palette de commandes, dans l'ordre d'affichage.
export interface NavPage {
  key: string;
  to: string;
  labelKey: string;
  icon: LucideIcon;
  // Correspondance exacte du chemin (« / » ne doit pas rester actif sur les autres écrans).
  end?: boolean;
}

export const NAV_PAGES: readonly NavPage[] = [
  { key: "scan", to: "/", labelKey: "nav.scan", icon: Search, end: true },
  { key: "dashboard", to: "/dashboard", labelKey: "nav.dashboard", icon: LayoutDashboard },
  { key: "history", to: "/history", labelKey: "nav.history", icon: History },
  { key: "batch", to: "/batch", labelKey: "nav.batch", icon: Files },
  { key: "compare", to: "/compare", labelKey: "nav.compare", icon: GitCompare },
  { key: "monitoring", to: "/monitoring", labelKey: "nav.monitoring", icon: Activity },
  { key: "help", to: "/help", labelKey: "nav.help", icon: CircleHelp },
  { key: "settings", to: "/settings", labelKey: "nav.settings", icon: Settings },
];
