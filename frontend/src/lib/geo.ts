// Coordonnées géographiques valides (une API de géolocalisation peut renvoyer
// n'importe quoi) : nombres finis, latitude dans [-90, 90], longitude dans [-180, 180].
export function isValidCoordinate(lat: number, lon: number): boolean {
  return Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180;
}
