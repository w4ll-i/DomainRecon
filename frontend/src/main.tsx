import "./styles/fonts.css";
import "./styles/tokens.css";
import "./styles/global.css";
import "./i18n";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter } from "react-router";
import { RouterProvider } from "react-router/dom";
import { AppProviders } from "./app/Providers";
import { initTheme } from "./lib/theme";
import { routes } from "./router";

// Thème choisi (ou préférence du système) posé avant le premier rendu.
initTheme();

const router = createBrowserRouter(routes);

createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    <AppProviders>
      <RouterProvider router={router} />
    </AppProviders>
  </StrictMode>,
);
