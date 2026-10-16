import { ChevronDown, Download, LoaderCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorDetail } from "../../api/client";
import { EXPORT_FORMATS, type ExportFormat, fetchExport } from "../../api/opsQueries";
import { useToast } from "../../components/Toasts";
import { useLang } from "../../i18n";
import { downloadBlob } from "../../lib/download";
import styles from "./ExportMenu.module.css";

// Export du rapport par le serveur (GET /api/scan/{id}/export) : PDF, HTML, Markdown,
// CSV, JSON et SARIF, dans la langue de l'interface. `disabled` : le scan affiché vient
// de l'autre langue, l'export attend le texte à jour.
export function ExportMenu({ scanId, disabled = false }: { scanId: number; disabled?: boolean }) {
  const { t } = useTranslation();
  const lang = useLang();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<ExportFormat | null>(null);
  const root = useRef<HTMLDivElement>(null);

  // Clic ailleurs ou Échap : le menu se referme.
  useEffect(() => {
    if (!open) return undefined;
    const onPointer = (event: MouseEvent) => {
      if (root.current && !root.current.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const run = async (format: ExportFormat) => {
    setOpen(false);
    setBusy(format);
    try {
      const { blob, filename } = await fetchExport(scanId, format, lang);
      downloadBlob(blob, filename);
      toast.show(t("export.done", { format: t(`export.formats.${format}`) }), "success");
    } catch (error) {
      toast.show(t("export.error", { format: t(`export.formats.${format}`), detail: errorDetail(error) }), "error");
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className={styles.root} ref={root}>
      <button
        type="button"
        className="btn"
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={disabled || busy !== null}
        onClick={() => setOpen((value) => !value)}
      >
        {busy ? <LoaderCircle aria-hidden className="spin" /> : <Download aria-hidden />}
        {t("export.button")}
        <ChevronDown aria-hidden />
      </button>
      {open && (
        <ul className={styles.menu} role="menu" aria-label={t("export.menu")}>
          {EXPORT_FORMATS.map((format) => (
            <li key={format} role="none">
              <button type="button" role="menuitem" className={styles.item} onClick={() => void run(format)}>
                <span className={styles.name}>{t(`export.formats.${format}`)}</span>
                <span className={styles.hint}>{t(`export.hints.${format}`)}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
