import { describe, expect, it } from "vitest";
import type { Finding, Severity } from "../api/types";
import { postureOf, scanSummary } from "./summary";

const finding = (severity: Severity): Finding => ({ severity, family: "web", module: "security_headers", message: "m" });
const scan = (grade: string, findings: Finding[], status = "success", coverage = 90) => ({
  status,
  findings,
  security_score: { score: 80, grade, coverage, measured_max: 40 },
});

describe("phrase de résumé", () => {
  it("déduit la posture de la note", () => {
    expect(["A", "B", "C", "D", "F"].map(postureOf)).toEqual(["good", "good", "fair", "poor", "poor"]);
  });

  it("aucun constat : posture seule", () => {
    expect(scanSummary(scan("A", []))).toEqual({ key: "result.summary.good.clean", params: { count: 0 } });
    expect(scanSummary(scan("C", []))).toEqual({ key: "result.summary.fair.clean", params: { count: 0 } });
  });

  it("constats légers : leur nombre", () => {
    expect(scanSummary(scan("B", [finding("medium"), finding("low")]))).toEqual({
      key: "result.summary.good.minor",
      params: { count: 2 },
    });
  });

  it("constats sérieux (critique ou élevé) : seul leur nombre compte", () => {
    const result = scanSummary(scan("F", [finding("critical"), finding("high"), finding("low")]));
    expect(result).toEqual({ key: "result.summary.poor.severe", params: { count: 2 } });
  });

  it("scan en échec : aucune conclusion, même avec une note reçue", () => {
    expect(scanSummary(scan("A", [], "error")).key).toBe("result.summary.error");
  });

  it("couverture insuffisante : pas de posture inventée", () => {
    expect(scanSummary(scan("A", [finding("low")], "partial", 30))).toEqual({
      key: "result.summary.noGrade",
      params: { count: 1 },
    });
  });
});
