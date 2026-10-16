import { type ComponentType, lazy } from "react";
import type { RouteObject } from "react-router";
import { AppShell } from "./app/AppShell";
import { NotFoundPage } from "./app/NotFoundPage";
import { RouteError } from "./app/RouteError";
import { NewScanPage } from "./features/newscan/NewScanPage";

// Chaque écran (hors l'accueil, premier écran affiché) est chargé à la demande : son code, et les
// bibliothèques lourdes qu'il est seul à utiliser (graphes, cartes), ne pèsent pas sur le premier
// chargement. La coquille (AppShell) montre un état de chargement sobre le temps du chargement ;
// un échec de chargement (réseau coupé, interface mise à jour) est une erreur de rendu, attrapée
// par la route (message et rechargement).
function screen<Module extends Record<string, unknown>>(load: () => Promise<Module>, name: keyof Module & string) {
  return lazy(async () => ({ default: (await load())[name] as ComponentType }));
}

const LiveScanPage = screen(() => import("./features/live/LiveScanPage"), "LiveScanPage");
const ResultPage = screen(() => import("./features/result/ResultPage"), "ResultPage");
const FamilyPage = screen(() => import("./features/family/FamilyPage"), "FamilyPage");
const HistoryPage = screen(() => import("./features/history/HistoryPage"), "HistoryPage");
const TimelinePage = screen(() => import("./features/timeline/TimelinePage"), "TimelinePage");
const SettingsPage = screen(() => import("./features/settings/SettingsPage"), "SettingsPage");
const DashboardPage = screen(() => import("./features/dashboard/DashboardPage"), "DashboardPage");
const BatchPage = screen(() => import("./features/batch/BatchPage"), "BatchPage");
const ComparePage = screen(() => import("./features/compare/ComparePage"), "ComparePage");
const MonitoringPage = screen(() => import("./features/monitoring/MonitoringPage"), "MonitoringPage");
const HelpPage = screen(() => import("./features/help/HelpPage"), "HelpPage");

// Routes de la spec §6.2. « scans/live/:jobId » (segment fixe) l'emporte sur
// « scans/:id/:family ». Le module est facultatif : « scans/:id/:family » ouvre le
// premier onglet de la famille, « scans/:id/:family/:module » (lien profond) celui du module.
// Une erreur de rendu d'un écran est interceptée par la route sans chemin qui
// englobe les écrans : la coquille (menu, langue, contenu) reste en place et
// l'erreur ne remplace que le contenu. L'errorElement de la racine n'est qu'un
// dernier recours, si la coquille elle-même plante.
export const routes: RouteObject[] = [
  {
    path: "/",
    element: <AppShell />,
    errorElement: <RouteError />,
    children: [
      {
        errorElement: <RouteError />,
        children: [
          { index: true, element: <NewScanPage /> },
          { path: "scans/live/:jobId", element: <LiveScanPage /> },
          { path: "scans/:id", element: <ResultPage /> },
          { path: "scans/:id/:family/:module?", element: <FamilyPage /> },
          { path: "history", element: <HistoryPage /> },
          { path: "history/:domain", element: <TimelinePage /> },
          { path: "settings", element: <SettingsPage /> },
          { path: "dashboard", element: <DashboardPage /> },
          { path: "batch", element: <BatchPage /> },
          { path: "compare", element: <ComparePage /> },
          { path: "monitoring", element: <MonitoringPage /> },
          { path: "help", element: <HelpPage /> },
          { path: "*", element: <NotFoundPage /> },
        ],
      },
    ],
  },
];
