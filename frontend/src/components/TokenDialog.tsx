import { useQueryClient } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";
import {
  createContext,
  type FormEvent,
  type ReactNode,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import { useTranslation } from "react-i18next";
import { getToken, isPrintableAscii, setToken, setTokenPrompt, subscribeToken, type TokenPrompt } from "../api/client";
import { Modal } from "./Modal";
import styles from "./Modal.module.css";
import { useToast } from "./Toasts";

interface TokenDialogApi {
  open: () => void;
}

const TokenDialogContext = createContext<TokenDialogApi | null>(null);

export function TokenProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState("");
  const [error, setError] = useState("");
  const resolver = useRef<((token: string | null) => void) | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const hasToken = useSyncExternalStore(subscribeToken, () => getToken() !== "");

  useEffect(() => {
    const prompt: TokenPrompt = (reason) =>
      new Promise((resolve) => {
        resolver.current = resolve;
        setValue("");
        setError(reason === "rejected" ? t("token.rejected") : "");
        setOpen(true);
      });
    setTokenPrompt(prompt);
    return () => setTokenPrompt(null);
  }, [t]);

  // Démontage avec une saisie en attente : l'appel qui l'attend est libéré
  // (sans jeton) au lieu de rester suspendu pour toujours.
  useEffect(
    () => () => {
      const resolve = resolver.current;
      resolver.current = null;
      resolve?.(null);
    },
    [],
  );

  // Réponse à un appel en attente, ou saisie spontanée (Réglages).
  const finish = (token: string | null) => {
    setOpen(false);
    const resolve = resolver.current;
    resolver.current = null;
    if (resolve) {
      resolve(token);
    } else if (token) {
      setToken(token);
      toast.show(t("token.saved"), "success");
      void queryClient.invalidateQueries();
    }
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const token = value.trim();
    if (!token) {
      setError(t("token.required"));
      return;
    }
    if (!isPrintableAscii(token)) {
      setError(t("token.ascii"));
      return;
    }
    finish(token);
  };

  // Oublie le jeton et retire les données obtenues avec lui.
  const forget = () => {
    setToken("");
    finish(null);
    queryClient.clear();
    toast.show(t("token.forgotten"), "info");
  };

  const api = useMemo<TokenDialogApi>(
    () => ({
      open: () => {
        setValue("");
        setError("");
        setOpen(true);
      },
    }),
    [],
  );

  return (
    <TokenDialogContext.Provider value={api}>
      {children}
      <Modal open={open} labelledBy="token-title" describedBy="token-text" onCancel={() => finish(null)} initialFocus={inputRef}>
        <form onSubmit={submit} autoComplete="off" noValidate>
          <h2 id="token-title" className={styles.title}>
            <KeyRound aria-hidden /> {t("token.title")}
          </h2>
          <p id="token-text" className={styles.text}>
            {t("token.text")}
          </p>
          <label htmlFor="token-input" className="visually-hidden">
            {t("token.label")}
          </label>
          <input
            id="token-input"
            ref={inputRef}
            type="password"
            className={styles.input}
            value={value}
            onChange={(event) => setValue(event.target.value)}
            placeholder={t("token.label")}
            spellCheck={false}
            autoComplete="off"
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? "token-error" : undefined}
          />
          {error && (
            <p id="token-error" role="alert" className={styles.error}>
              {error}
            </p>
          )}
          <div className={styles.actions}>
            {hasToken && (
              <button type="button" className="btn" data-variant="ghost" onClick={forget}>
                {t("token.forget")}
              </button>
            )}
            <button type="button" className="btn" onClick={() => finish(null)}>
              {t("common.cancel")}
            </button>
            <button type="submit" className="btn" data-variant="primary">
              {t("token.submit")}
            </button>
          </div>
        </form>
      </Modal>
    </TokenDialogContext.Provider>
  );
}

export function useTokenDialog(): TokenDialogApi {
  const api = useContext(TokenDialogContext);
  if (!api) throw new Error("useTokenDialog doit être utilisé sous TokenProvider");
  return api;
}
