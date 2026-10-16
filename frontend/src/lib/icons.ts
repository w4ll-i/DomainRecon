import {
  CircleCheck,
  CircleMinus,
  CircleQuestionMark,
  CircleX,
  Globe,
  IdCard,
  Info,
  KeyRound,
  Lock,
  type LucideIcon,
  Mail,
  Network,
  Server,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import type { FamilyKey, FamilyState } from "../api/types";

export const FAMILY_ICONS: Readonly<Record<FamilyKey, LucideIcon>> = {
  web: Globe,
  tls: Lock,
  email: Mail,
  dns: Network,
  network: Server,
  identity: IdCard,
  reputation: ShieldCheck,
  leaks: KeyRound,
};

// Icône d'état : second indice, en plus de la couleur.
export const STATE_ICONS: Readonly<Record<FamilyState, LucideIcon>> = {
  ok: CircleCheck,
  warning: TriangleAlert,
  critical: CircleX,
  unmeasured: CircleQuestionMark,
  skipped: CircleMinus,
  info: Info,
};
