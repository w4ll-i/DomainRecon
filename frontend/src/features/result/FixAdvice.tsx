import { Check, Copy, ExternalLink } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { CatalogModule } from "../../api/types";
import { Tabs } from "../../components/Tabs";
import { GlossaryText } from "../../components/Term";
import { useToast } from "../../components/Toasts";
import { copyText } from "../../lib/clipboard";
import { fixSteps, safeHttpsUrl, type SnippetVariant, snippetVariants, splitInlineCode } from "../../lib/fix";
import { tabId, tabPanelId } from "../../lib/tabs";
import styles from "./FixAdvice.module.css";

// Durée d'affichage de « Copié » sur le bouton.
const COPIED_MS = 2000;

// Une étape : texte courant (sigles du glossaire expliqués) et code en ligne.
function Step({ line }: { line: string }) {
  return (
    <li>
      {splitInlineCode(line).map((segment, index) =>
        segment.code ? (
          <code key={index} className={styles.inline}>
            {segment.text}
          </code>
        ) : (
          <GlossaryText key={index} text={segment.text} />
        ),
      )}
    </li>
  );
}

// Bloc de code et son bouton Copier : le code seul est copié, sans la ligne d'en-tête de variante.
function CodeBlock({ code, label }: { code: string; label: string | null }) {
  const { t } = useTranslation();
  const toast = useToast();
  const [copied, setCopied] = useState(false);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const copy = async () => {
    if (await copyText(code)) {
      setCopied(true);
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(false), COPIED_MS);
    } else {
      toast.show(t("understand.copyError"), "error");
    }
  };

  const name = label ? t("understand.copyVariant", { variant: label }) : t("understand.copyCode");
  const Icon = copied ? Check : Copy;
  return (
    <div className={styles.codeBox}>
      {/* Barre au-dessus du code : le bouton ne recouvre jamais une ligne, même défilée. */}
      <div className={styles.bar}>
        <button type="button" className={`btn ${styles.copy}`} data-variant="ghost" aria-label={name} onClick={() => void copy()}>
          <Icon aria-hidden />
          <span aria-hidden>{t(copied ? "understand.copied" : "understand.copy")}</span>
        </button>
        {/* Annonce pour les lecteurs d'écran : le bouton garde son nom, l'état se dit à part. */}
        <span role="status" className="visually-hidden">
          {copied ? t("understand.copied") : ""}
        </span>
      </div>
      {/* tabIndex : un bloc qui défile à l'horizontale se parcourt au clavier. */}
      <pre className={styles.pre} tabIndex={0}>
        <code>{code}</code>
      </pre>
    </div>
  );
}

// Extrait prêt à copier : un bloc, ou des onglets sobres quand il a plusieurs variantes par plateforme.
function Snippet({ variants, id }: { variants: SnippetVariant[]; id: string }) {
  const { t } = useTranslation();
  const [active, setActive] = useState(0);
  const current = variants[Math.min(active, variants.length - 1)];
  if (variants.length === 1) return <CodeBlock code={current.code} label={current.label} />;
  const keys = variants.map((_, index) => String(index));
  const prefix = `${id}-snippet`;
  return (
    <div className={styles.variants}>
      <Tabs
        tabs={variants.map((variant, index) => ({ key: keys[index], label: variant.label ?? t("understand.variantDefault", { number: index + 1 }) }))}
        activeKey={keys[Math.min(active, variants.length - 1)]}
        onChange={(key) => setActive(Number(key))}
        label={t("understand.platforms")}
        idPrefix={prefix}
      />
      <div role="tabpanel" id={tabPanelId(prefix)} aria-labelledby={tabId(prefix, keys[Math.min(active, variants.length - 1)])}>
        {/* key : changer de variante repart d'un bouton « Copier » neuf. */}
        <CodeBlock key={active} code={current.code} label={current.label} />
      </div>
    </div>
  );
}

// Lien vers la documentation officielle : nouvel onglet, sans référent ni accès à la fenêtre d'origine.
function Reference({ url }: { url: URL }) {
  const { t } = useTranslation();
  return (
    <p className={styles.reference}>
      <a href={url.href} target="_blank" rel="noopener noreferrer">
        {t("understand.reference")}
        <ExternalLink aria-hidden />
        <span className="visually-hidden"> {t("understand.newTab")}</span>
      </a>
      <span className={`${styles.host} mono`}>{url.hostname}</span>
    </p>
  );
}

// « Comment corriger » d'un constat : les étapes du catalogue (liste numérotée), l'extrait prêt à
// copier et le lien vers la documentation officielle. Sans étapes dans le catalogue, `fallback`
// (le conseil de l'interface, par module puis par famille) tient lieu d'étapes.
export function FixAdvice({ info, fallback, id }: { info: CatalogModule | undefined; fallback: string; id: string }) {
  const steps = fixSteps(info?.fix);
  const variants = snippetVariants(info?.fix_snippet);
  const reference = safeHttpsUrl(info?.fix_ref);
  return (
    <div className={styles.advice}>
      {steps.length > 0 ? (
        <ol className={styles.steps}>
          {steps.map((line, index) => (
            <Step key={index} line={line} />
          ))}
        </ol>
      ) : (
        <p className={styles.fallback}>
          <GlossaryText text={fallback} />
        </p>
      )}
      {variants.length > 0 && <Snippet variants={variants} id={id} />}
      {reference && <Reference url={reference} />}
    </div>
  );
}
