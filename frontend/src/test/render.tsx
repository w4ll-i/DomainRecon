import { QueryClient } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { AppProviders } from "../app/Providers";

// Fichier de test : le rechargement à chaud ne s'applique pas.
// eslint-disable-next-line react-refresh/only-export-components
function LocationDisplay() {
  const location = useLocation();
  return (
    <span hidden data-testid="location">
      {location.pathname}
      {location.search}
    </span>
  );
}

interface RenderOptions {
  route?: string;
  path?: string;
  queryClient?: QueryClient;
}

// Écran rendu avec les mêmes fournisseurs que l'application, dans un routeur
// en mémoire ; le chemin courant se lit dans data-testid="location".
export function renderWithProviders(ui: ReactElement, { route = "/", path = "*", queryClient }: RenderOptions = {}) {
  const client =
    queryClient ??
    new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } } });
  const user = userEvent.setup();
  const result = render(
    <AppProviders queryClient={client}>
      <MemoryRouter initialEntries={[route]}>
        <Routes>
          <Route path={path} element={ui} />
          {path !== "*" && <Route path="*" element={null} />}
        </Routes>
        <LocationDisplay />
      </MemoryRouter>
    </AppProviders>,
  );
  return { ...result, user, queryClient: client };
}
