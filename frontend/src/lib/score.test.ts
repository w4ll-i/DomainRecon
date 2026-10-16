import { describe, expect, it } from "vitest";
import type { SecurityScore } from "../api/types";
import {
  criterionKind,
  displayGrade,
  findingsEmptyKey,
  lowCoverage,
  penaltyTotal,
  scoreIndicative,
  scoreUnavailable,
  scoreView,
  timelineScoreView,
} from "./score";

describe("score et note", () => {
  it("n'affiche une note que si le score est mesurable et la couverture suffisante", () => {
    expect(scoreUnavailable({ score: 78, grade: "B", coverage: 90 })).toBe(false);
    expect(scoreUnavailable({ score: null, grade: "N/A" })).toBe(true);
    expect(scoreUnavailable({ score: 40, grade: "N/A", coverage: 40 })).toBe(true);
    expect(scoreUnavailable({ score: 0, grade: "F", coverage: 0 })).toBe(true);
    expect(scoreUnavailable({ score: 60, grade: "C", coverage: 45 })).toBe(true);
    expect(scoreUnavailable(undefined)).toBe(true);
    expect(lowCoverage({ coverage: 49 })).toBe(true);
    expect(lowCoverage({})).toBe(false);
  });

  it("affiche N/A pour tout score sans note (dont les anciens scans notés sous 50 %)", () => {
    expect(displayGrade({ score: 78, grade: "B", coverage: 90 })).toBe("B");
    expect(displayGrade({ score: 60, grade: "C", coverage: 45 })).toBe("N/A");
    expect(displayGrade({})).toBe("N/A");
    // Score non numérique : ni « NaN/100 », ni la note enregistrée.
    expect(displayGrade({ score: "abc", grade: "B" } as unknown as SecurityScore)).toBe("N/A");
  });

  it("garde un score indicatif quand la couverture est insuffisante", () => {
    expect(scoreIndicative({ score: 60, grade: "N/A", coverage: 45, measured_max: 40 })).toBe(60);
    expect(scoreIndicative({ score: 0, grade: "N/A", coverage: 0, measured_max: 0 })).toBeNull();
    expect(scoreIndicative({ score: 78, grade: "B", coverage: 90, measured_max: 90 })).toBeNull();
  });

  it("une seule règle d'affichage du score : score, indicatif ou rien", () => {
    expect(scoreView({ score: 78, grade: "B", coverage: 90, measured_max: 90 })).toEqual({ kind: "score", value: 78 });
    expect(scoreView({ score: 60, grade: "N/A", coverage: 45, measured_max: 40 })).toEqual({ kind: "indicative", value: 60 });
    expect(scoreView({ score: 0, grade: "N/A", coverage: 0, measured_max: 0 })).toEqual({ kind: "none", value: null });
    expect(scoreView(undefined)).toEqual({ kind: "none", value: null });
  });

  it("relevé de la timeline tel que le serveur l'envoie : exactement l'affichage de l'Historique", () => {
    // Relevé construit comme history._timeline_entry : valeurs non numériques
    // écartées (_number), score transmis seulement s'il est affiché (note
    // valable, ou indicatif sur des critères comptés).
    const serverEntry = (ss: SecurityScore) => {
      const num = (value: unknown) => (typeof value === "number" && Number.isFinite(value) ? value : null);
      const coverage = num(ss.coverage);
      const measuredMax = num(ss.measured_max);
      const low = coverage !== null && coverage < 50;
      const kept = coverage !== 0 && ((ss.grade !== "N/A" && !low) || (measuredMax !== null && measuredMax > 0));
      return {
        security_score: kept ? num(ss.score) : null,
        grade: typeof ss.grade === "string" ? ss.grade : null,
        coverage,
        measured_max: measuredMax,
      };
    };
    const cases: Array<[SecurityScore, ReturnType<typeof scoreView>]> = [
      // Note normale.
      [{ score: 78, grade: "B", coverage: 90, measured_max: 90 }, { kind: "score", value: 78 }],
      // Note N/A sous 50 %, critères comptés : « 60/100 (indicatif) » des deux côtés.
      [{ score: 60, grade: "N/A", coverage: 40, measured_max: 40 }, { kind: "indicative", value: 60 }],
      // Aucune mesure.
      [{ score: 0, grade: "N/A", coverage: 0, measured_max: 0 }, { kind: "none", value: null }],
      // Seul le bonus WAF mesuré : rien de noté.
      [{ score: 0, grade: "N/A", coverage: 10, measured_max: 0 }, { kind: "none", value: null }],
      // Scan noté avant la règle des 50 %, avec measured_max : indicatif.
      [{ score: 71, grade: "C", coverage: 45, measured_max: 40 }, { kind: "indicative", value: 71 }],
      // Anciens scans sans measured_max.
      [{ score: 71, grade: "C", coverage: 45 }, { kind: "none", value: null }],
      [{ score: 40, grade: "N/A", coverage: 30 }, { kind: "none", value: null }],
      [{ score: 81, grade: "B" }, { kind: "score", value: 81 }],
      // Valeurs non numériques (JSON brut de l'Historique) : jamais un score.
      [{ score: "78", grade: "B", coverage: 90 } as unknown as SecurityScore, { kind: "none", value: null }],
      [{ score: "abc", grade: "B" } as unknown as SecurityScore, { kind: "none", value: null }],
      [{ score: true, grade: "B", coverage: 90 } as unknown as SecurityScore, { kind: "none", value: null }],
      [{ score: Number.NaN, grade: "B", coverage: 90 }, { kind: "none", value: null }],
      [{ score: 60, grade: "N/A", coverage: 40, measured_max: "40" } as unknown as SecurityScore, { kind: "none", value: null }],
      [{ score: 60, grade: "N/A", coverage: 40, measured_max: true } as unknown as SecurityScore, { kind: "none", value: null }],
    ];
    for (const [ss, expected] of cases) {
      expect(scoreView(ss), JSON.stringify(ss)).toEqual(expected);
      expect(timelineScoreView(serverEntry(ss)), JSON.stringify(ss)).toEqual(expected);
    }
    expect(timelineScoreView({ security_score: null, grade: null, coverage: null, measured_max: null })).toEqual({
      kind: "none",
      value: null,
    });
  });

  it("classe chaque critère : points, bonus, non mesuré, sans objet", () => {
    expect(criterionKind({ score: 20, max: 20, measured: true, counted: true })).toBe("points");
    expect(criterionKind({ score: 0, max: 10, measured: true, counted: false })).toBe("bonus");
    expect(criterionKind({ score: 0, max: 5, measured: false, applicable: true })).toBe("notMeasured");
    expect(criterionKind({ score: 0, max: 15, measured: false, applicable: false })).toBe("notApplicable");
    expect(criterionKind({ score: 0, max: 15, measured: false, detail: "Non applicable (cible IP)" })).toBe(
      "notApplicable",
    );
  });

  it("totalise les pénalités", () => {
    expect(penaltyTotal({ penalties: [{ label: "a", points: 10 }, { label: "b", points: 5 }] })).toBe(15);
    expect(penaltyTotal({})).toBe(0);
  });

  it("choisit un message honnête quand il n'y a rien à corriger", () => {
    expect(findingsEmptyKey({ status: "error", security_score: {} })).toBe("findings.noneError");
    expect(findingsEmptyKey({ status: "partial", security_score: { score: 50, grade: "N/A", coverage: 30 } })).toBe(
      "findings.noneLowCoverage",
    );
    expect(findingsEmptyKey({ status: "success", security_score: { score: 95, grade: "A", coverage: 100 } })).toBe(
      "findings.none",
    );
  });
});
