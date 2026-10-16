import { useId } from "react";
import { useTranslation } from "react-i18next";
import { MAP_HEIGHT, MAP_WIDTH, projectPoint, worldLandPath, worldOutlinePath } from "../../../lib/worldMap";
import styles from "./modules.module.css";

// Carte du monde monochrome, vectorielle et embarquée (Natural Earth 1:110m, domaine
// public) : les terres en gris, un seul point à l'emplacement de la cible. Aucune tuile,
// aucune requête : elle fonctionne hors ligne. Le lieu est écrit sous la carte (la
// position ne se lit jamais par le seul dessin).
export function GeoMap({ lat, lon, title, subtitle }: { lat: number; lon: number; title: string; subtitle: string }) {
  const { t } = useTranslation();
  const titleId = useId();
  const point = projectPoint(lat, lon);
  if (!point) {
    return (
      <p className={styles.note} data-tone="warning" role="status">
        {t("network.map.failed")}
      </p>
    );
  }
  const label = t("network.map.aria", { place: title });
  return (
    <figure className={styles.mapFigure}>
      <svg
        className={styles.worldMap}
        viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`}
        role="img"
        aria-labelledby={titleId}
        focusable="false"
      >
        <title id={titleId}>{label}</title>
        <path className={styles.mapOutline} d={worldOutlinePath()} />
        <path className={styles.mapLand} d={worldLandPath()} />
        <circle className={styles.mapPointHalo} cx={point[0]} cy={point[1]} r={9} />
        <circle className={styles.mapPoint} cx={point[0]} cy={point[1]} r={4} />
      </svg>
      <figcaption className={styles.mapCaption}>
        <strong>{title}</strong>
        {subtitle && <span>{subtitle}</span>}
      </figcaption>
    </figure>
  );
}
