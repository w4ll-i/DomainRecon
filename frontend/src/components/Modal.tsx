import { type KeyboardEvent, type ReactNode, type RefObject, useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import styles from "./Modal.module.css";

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

interface ModalProps {
  open: boolean;
  labelledBy: string;
  describedBy?: string;
  role?: "dialog" | "alertdialog";
  onCancel: () => void;
  initialFocus?: RefObject<HTMLElement | null>;
  // « palette » : fenêtre large, collée en haut, sans marge intérieure (palette de commandes).
  variant?: "palette";
  children: ReactNode;
}

// Fenêtre modale : focus piégé, Échap ou clic hors de la fenêtre = annulation,
// focus rendu à l'élément actif avant l'ouverture.
export function Modal({ open, labelledBy, describedBy, role = "dialog", onCancel, initialFocus, variant, children }: ModalProps) {
  const panel = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return undefined;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const target = initialFocus?.current ?? panel.current?.querySelector<HTMLElement>(FOCUSABLE) ?? panel.current;
    target?.focus();
    return () => {
      if (previous && document.contains(previous)) previous.focus();
    };
  }, [open, initialFocus]);

  if (!open) return null;

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      onCancel();
      return;
    }
    if (event.key !== "Tab" || !panel.current) return;
    const items = [...panel.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
    if (!items.length) {
      // Rien à atteindre : le focus reste sur le panneau.
      event.preventDefault();
      panel.current.focus();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    // Panneau lui-même (clic sur le texte) ou élément hors de la fenêtre : on
    // repart d'une extrémité, sinon le focus s'échapperait sous le fond.
    const outside = active === panel.current || !panel.current.contains(active);
    if (event.shiftKey) {
      if (outside || active === first) {
        event.preventDefault();
        last.focus();
      }
    } else if (outside || active === last) {
      event.preventDefault();
      first.focus();
    }
  };

  return createPortal(
    <div
      className={variant === "palette" ? `${styles.backdrop} ${styles.top}` : styles.backdrop}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <div
        ref={panel}
        className={variant === "palette" ? `${styles.panel} ${styles.wide}` : styles.panel}
        role={role}
        aria-modal="true"
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        tabIndex={-1}
        onKeyDown={onKeyDown}
      >
        {children}
      </div>
    </div>,
    document.body,
  );
}
