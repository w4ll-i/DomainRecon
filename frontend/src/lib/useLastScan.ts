import { useEffect } from "react";
import { ApiError } from "../api/client";
import type { ScanResponse } from "../api/types";
import { getLastScanId, setLastScanId } from "./storage";

// Dernier scan consulté (entrée « Résultat » du menu) : mémorisé à la lecture,
// oublié quand le serveur répond 404 (scan supprimé) pour que le menu n'y mène plus.
export function useRememberLastScan(scan: ScanResponse | undefined, error: unknown, id: number | null): void {
  useEffect(() => {
    if (scan) setLastScanId(scan.id);
  }, [scan]);

  useEffect(() => {
    if (error instanceof ApiError && error.status === 404 && getLastScanId() === id) setLastScanId(null);
  }, [error, id]);
}
