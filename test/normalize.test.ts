import { describe, expect, it } from "vitest";
import { vulnerabilitiesToCsv } from "../src/csv";
import { safeHttpUrl, toConfigAuditReport, toExposedSecretReport, toVulnerabilityReport } from "../src/normalize";

describe("safeHttpUrl", () => {
  it("keeps absolute http(s) links", () => {
    expect(safeHttpUrl("https://avd.aquasec.com/nvd/cve-2026-1")).toBe("https://avd.aquasec.com/nvd/cve-2026-1");
    expect(safeHttpUrl("http://example.com/a")).toBe("http://example.com/a");
  });

  it("drops script, data and relative links", () => {
    expect(safeHttpUrl("javascript:alert(document.cookie)")).toBeUndefined();
    expect(safeHttpUrl(" JavaScript:alert(1)")).toBeUndefined();
    expect(safeHttpUrl("data:text/html,<script>alert(1)</script>")).toBeUndefined();
    expect(safeHttpUrl("//evil.example/x")).toBeUndefined();
    expect(safeHttpUrl("/api/v1/session")).toBeUndefined();
    expect(safeHttpUrl(42)).toBeUndefined();
  });
});

describe("toVulnerabilityReport", () => {
  it("strips unsafe links and wrong types from a hostile report", () => {
    const report = toVulnerabilityReport({
      metadata: { name: "r", labels: { "trivy-operator.container.name": "app", bogus: 1 } },
      report: {
        summary: { criticalCount: "9", highCount: 2 },
        vulnerabilities: [
          { vulnerabilityID: "CVE-1", severity: { x: 1 }, score: "9.8", primaryLink: "javascript:alert(1)", title: 7 },
          "not an object",
        ],
      },
    });
    expect(report.metadata.labels).toEqual({ "trivy-operator.container.name": "app" });
    expect(report.report.summary).toMatchObject({ criticalCount: undefined, highCount: 2 });
    const [first, second] = report.report.vulnerabilities ?? [];
    expect(first).toMatchObject({ vulnerabilityID: "CVE-1", severity: "UNKNOWN", score: undefined, title: undefined });
    expect(first?.primaryLink).toBeUndefined();
    expect(second).toMatchObject({ vulnerabilityID: "", severity: "UNKNOWN" });
  });

  it("tolerates missing or non-object input", () => {
    expect(toVulnerabilityReport(null).report.vulnerabilities).toEqual([]);
    expect(toVulnerabilityReport({ report: { vulnerabilities: "x" } }).report.vulnerabilities).toEqual([]);
  });
});

describe("toConfigAuditReport and toExposedSecretReport", () => {
  it("keeps only well-typed fields", () => {
    const audit = toConfigAuditReport({
      metadata: { name: "a" },
      report: { checks: [{ checkID: "KSV1", severity: "HIGH", success: "yes", messages: ["ok", 3] }] },
    });
    expect(audit.report.checks).toEqual([
      expect.objectContaining({ checkID: "KSV1", severity: "HIGH", success: false, messages: ["ok"] }),
    ]);

    const secrets = toExposedSecretReport({ report: { secrets: [{ ruleID: "aws", match: { a: 1 } }] } });
    expect(secrets.report.secrets).toEqual([expect.objectContaining({ ruleID: "aws", match: undefined })]);
  });
});

describe("CSV export", () => {
  it("neutralises spreadsheet formulas in report fields", () => {
    const csv = vulnerabilitiesToCsv([
      { vulnerabilityID: "CVE-1", severity: "HIGH", title: '=HYPERLINK("http://evil","x")', resource: "@SUM(1)" },
      { vulnerabilityID: "CVE-2", severity: "LOW", title: "+1", resource: "-2", installedVersion: "1.0", score: -1 },
    ]);
    const [, first, second] = csv.split("\r\n");
    expect(first).toBe(`HIGH,CVE-1,'@SUM(1),,,,"'=HYPERLINK(""http://evil"",""x"")",`);
    expect(second).toBe("LOW,CVE-2,'-2,1.0,,-1,'+1,");
  });
});
