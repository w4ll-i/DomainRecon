import { useEffect, useState } from "react";

// Secondes écoulées depuis l'ouverture de l'écran (chronomètre). Le décompte avance
// une fois par seconde tant que `active` est vrai ; il s'arrête, valeur conservée, dès
// que la tâche est terminée.
export function useElapsedSeconds(active: boolean): number {
  const [start] = useState(() => Date.now());
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return undefined;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [active]);
  return Math.max(0, Math.round((now - start) / 1000));
}
