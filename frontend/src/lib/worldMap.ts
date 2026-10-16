import { geoNaturalEarth1, geoPath } from "d3-geo";
import type { GeoPermissibleObjects } from "d3-geo";
import type { GeometryCollection, Topology } from "topojson-specification";
import { feature } from "topojson-client";
import land110m from "world-atlas/land-110m.json";
import { isValidCoordinate } from "./geo";

// Carte du monde vectorielle embarquée, hors ligne : Natural Earth 1:110m (domaine
// public), via le paquet npm world-atlas, projetée par d3-geo (Natural Earth) en un
// tracé SVG. Aucune tuile ni ressource externe : la CSP stricte reste intacte.
export const MAP_WIDTH = 800;
export const MAP_HEIGHT = 400;

const projection = geoNaturalEarth1().fitExtent(
  [
    [4, 4],
    [MAP_WIDTH - 4, MAP_HEIGHT - 4],
  ],
  { type: "Sphere" },
);
const path = geoPath(projection);

let landPath: string | null = null;

// Tracé SVG (attribut d) des terres émergées, calculé une fois.
export function worldLandPath(): string {
  if (landPath === null) {
    const topology = land110m as unknown as Topology<{ land: GeometryCollection }>;
    landPath = path(feature(topology, topology.objects.land) as GeoPermissibleObjects) ?? "";
  }
  return landPath;
}

// Contour de la sphère (le « cadre » arrondi de la projection).
export function worldOutlinePath(): string {
  return path({ type: "Sphere" }) ?? "";
}

// Position d'un point (latitude, longitude) dans le viewBox de la carte ; null si les
// coordonnées sont invalides ou hors de la projection.
export function projectPoint(lat: number, lon: number): [number, number] | null {
  if (!isValidCoordinate(lat, lon)) return null;
  const point = projection([lon, lat]);
  return point && Number.isFinite(point[0]) && Number.isFinite(point[1]) ? [point[0], point[1]] : null;
}
