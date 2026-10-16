import { createContext, type ReactNode, useCallback, useContext, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Modal } from "./Modal";
import styles from "./Modal.module.css";

export interface ConfirmOptions {
  title: string;
  message: string;
  confirmLabel: string;
  danger?: boolean;
}

type ConfirmFn = (options: ConfirmOptions) => Promise<boolean>;

const ConfirmContext = createContext<ConfirmFn | null>(null);

// Confirmation d'une action irréversible ; le focus part sur « Annuler ».
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const [options, setOptions] = useState<ConfirmOptions | null>(null);
  const resolver = useRef<((value: boolean) => void) | null>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  const confirm = useCallback<ConfirmFn>((next) => {
    resolver.current?.(false);
    return new Promise<boolean>((resolve) => {
      resolver.current = resolve;
      setOptions(next);
    });
  }, []);

  const close = useCallback((value: boolean) => {
    const resolve = resolver.current;
    resolver.current = null;
    setOptions(null);
    resolve?.(value);
  }, []);

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <Modal
        open={options !== null}
        role="alertdialog"
        labelledBy="confirm-title"
        describedBy="confirm-text"
        onCancel={() => close(false)}
        initialFocus={cancelRef}
      >
        {options && (
          <>
            <h2 id="confirm-title" className={styles.title}>
              {options.title}
            </h2>
            <p id="confirm-text" className={styles.text}>
              {options.message}
            </p>
            <div className={styles.actions}>
              <button ref={cancelRef} type="button" className="btn" onClick={() => close(false)}>
                {t("common.cancel")}
              </button>
              <button
                type="button"
                className="btn"
                data-variant={options.danger ? "danger" : "primary"}
                onClick={() => close(true)}
              >
                {options.confirmLabel}
              </button>
            </div>
          </>
        )}
      </Modal>
    </ConfirmContext.Provider>
  );
}

export function useConfirm(): ConfirmFn {
  const confirm = useContext(ConfirmContext);
  if (!confirm) throw new Error("useConfirm doit être utilisé sous ConfirmProvider");
  return confirm;
}
