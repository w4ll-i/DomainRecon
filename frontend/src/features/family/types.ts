import type { FamilyKey, ScanResponse } from "../../api/types";

export interface FamilyViewProps {
  scan: ScanResponse;
  family: FamilyKey;
}
