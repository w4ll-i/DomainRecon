import { Eye, KeyRound, ShieldAlert, Zap, type LucideIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { Tone } from "../lib/tones";
import { Pill } from "./Pills";

// Catégories d'un module du catalogue : passif, actif, clé d'API, sensible. L'icône et le
// texte disent la catégorie ; la couleur ne la porte jamais seule.
const CATEGORIES: Record<string, { tone: Tone; icon: LucideIcon }> = {
  passif: { tone: "neutral", icon: Eye },
  actif: { tone: "warning", icon: Zap },
  cle_api: { tone: "accent", icon: KeyRound },
  sensible: { tone: "critical", icon: ShieldAlert },
};

export function CategoryBadge({ category }: { category: string }) {
  const { t } = useTranslation();
  const known = Object.hasOwn(CATEGORIES, category);
  const { tone, icon: Icon } = known ? CATEGORIES[category] : CATEGORIES.passif;
  return (
    <Pill tone={tone}>
      <Icon aria-hidden />
      {t(`category.${known ? category : "passif"}`)}
    </Pill>
  );
}
