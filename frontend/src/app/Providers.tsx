import { type QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { type ReactNode, useState } from "react";
import { createQueryClient } from "../api/queries";
import { ConfirmProvider } from "../components/ConfirmDialog";
import { ToastProvider } from "../components/Toasts";
import { TokenProvider } from "../components/TokenDialog";

export function AppProviders({ children, queryClient }: { children: ReactNode; queryClient?: QueryClient }) {
  const [client] = useState(() => queryClient ?? createQueryClient());
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>
        <ConfirmProvider>
          <TokenProvider>{children}</TokenProvider>
        </ConfirmProvider>
      </ToastProvider>
    </QueryClientProvider>
  );
}
