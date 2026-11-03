import { describe, expect, it } from "vitest";
import { formatAge } from "../src/components/common";
import { vulnerabilitiesToCsv } from "../src/csv";
import {
  Vulnerability,
  VulnerabilityReport,
  countBySeverity,
  countsFromSummary,
  dedupeVulnerabilities,
  filterVulnerabilities,
  imageRef,
  normalizeSeverity,
  sortVulnerabilities,
  uniqueKeys,
} from "../src/reports";

const v = (id: string, severity: string, extra: Partial<Vulnerability> = {}): Vulnerability => ({
  vulnerabilityID: id,
  severity,
  resource: "openssl",
  installedVersion: "3.0.0",
  ...extra,
});

const list = [
  v("CVE-2026-0003", "LOW", { score: 3.1, fixedVersion: "3.0.1" }),
  v("CVE-2026-0001", "CRITICAL", { score: 9.1, resource: "zlib" }),
  v("CVE-2026-0002", "HIGH", { score: 7.0, title: "Heap overflow in parser", fixedVersion: "3.0.2" }),
  v("CVE-2026-0010", "HIGH", { score: 8.2 }),
  v("GHSA-xxxx-yyyy", "weird"),
];

describe("severity helpers", () => {
  it("normalizes unexpected values to UNKNOWN", () => {
    expect(normalizeSeverity("high")).toBe("HIGH");
    expect(normalizeSeverity("weird")).toBe("UNKNOWN");
    expect(normalizeSeverity(undefined)).toBe("UNKNOWN");
  });

  it("counts by severity", () => {
    expect(countBySeverity(list)).toEqual({ CRITICAL: 1, HIGH: 2, MEDIUM: 0, LOW: 1, UNKNOWN: 1 });
  });

  it("reads report summaries with missing fields", () => {
    expect(countsFromSummary({ criticalCount: 2, highCount: 5 })).toEqual({
      CRITICAL: 2,
      HIGH: 5,
      MEDIUM: 0,
      LOW: 0,
      UNKNOWN: 0,
    });
    expect(countsFromSummary(undefined).CRITICAL).toBe(0);
  });
});

describe("filterVulnerabilities", () => {
  const all = { query: "", severities: new Set<never>(), fixableOnly: false };

  it("returns everything without filters", () => {
    expect(filterVulnerabilities(list, all)).toHaveLength(list.length);
  });

  it("filters by severity, fixability and text", () => {
    expect(filterVulnerabilities(list, { ...all, severities: new Set(["HIGH"] as const) })).toHaveLength(2);
    expect(filterVulnerabilities(list, { ...all, fixableOnly: true }).map((x) => x.vulnerabilityID)).toEqual([
      "CVE-2026-0003",
      "CVE-2026-0002",
    ]);
    expect(filterVulnerabilities(list, { ...all, query: "  heap " })).toHaveLength(1);
    expect(filterVulnerabilities(list, { ...all, query: "zlib" })).toHaveLength(1);
  });
});

describe("sortVulnerabilities", () => {
  const ids = (xs: Vulnerability[]) => xs.map((x) => x.vulnerabilityID);

  it("puts the most severe first, then the highest score", () => {
    expect(ids(sortVulnerabilities(list, "severity", "asc"))).toEqual([
      "CVE-2026-0001",
      "CVE-2026-0010",
      "CVE-2026-0002",
      "CVE-2026-0003",
      "GHSA-xxxx-yyyy",
    ]);
  });

  it("sorts by score and id in both directions without mutating input", () => {
    const copy = [...list];
    expect(ids(sortVulnerabilities(list, "score", "desc"))[0]).toBe("CVE-2026-0001");
    expect(ids(sortVulnerabilities(list, "id", "asc"))[0]).toBe("CVE-2026-0001");
    expect(ids(sortVulnerabilities(list, "id", "desc"))[0]).toBe("GHSA-xxxx-yyyy");
    expect(list).toEqual(copy);
  });
});

describe("dedupeVulnerabilities", () => {
  it("collapses the same advisory reported for several files", () => {
    const dupes = [
      v("CVE-1", "HIGH", { target: "/bin/a" }),
      v("CVE-1", "HIGH", { target: "/bin/b" }),
      v("CVE-1", "HIGH", { installedVersion: "3.0.1" }),
    ];
    expect(dedupeVulnerabilities(dupes)).toHaveLength(2);
  });
});

describe("imageRef", () => {
  const report = (
    registry: string | undefined,
    artifact: VulnerabilityReport["report"]["artifact"],
  ): VulnerabilityReport => ({
    metadata: { name: "r" },
    report: { registry: registry ? { server: registry } : undefined, artifact },
  });

  it("formats registry, repository and tag", () => {
    expect(imageRef(report("quay.io", { repository: "argoproj/argocd", tag: "v3.5.7" }))).toBe(
      "quay.io/argoproj/argocd:v3.5.7",
    );
  });

  it("omits Docker Hub and falls back to the digest", () => {
    expect(imageRef(report("index.docker.io", { repository: "library/redis", digest: "sha256:abc" }))).toBe(
      "library/redis@sha256:abc",
    );
    expect(imageRef(report(undefined, undefined))).toBe("");
  });
});

describe("vulnerabilitiesToCsv", () => {
  it("escapes commas, quotes and newlines", () => {
    const csv = vulnerabilitiesToCsv([v("CVE-1", "HIGH", { title: 'Say "hi", then\nleave', score: 7.5 })]);
    const [header, row] = csv.split("\r\n");
    expect(header).toBe("Severity,ID,Package,Installed,Fixed,Score,Title,Link");
    expect(row).toBe('HIGH,CVE-1,openssl,3.0.0,,7.5,"Say ""hi"", then\nleave",');
  });
});

describe("formatAge", () => {
  const now = Date.parse("2026-11-03T12:00:00Z");

  it("formats relative times", () => {
    expect(formatAge("2026-11-03T11:59:30Z", now)).toBe("just now");
    expect(formatAge("2026-11-03T11:15:00Z", now)).toBe("45m ago");
    expect(formatAge("2026-11-03T07:00:00Z", now)).toBe("5h ago");
    expect(formatAge("2026-10-31T12:00:00Z", now)).toBe("3d ago");
  });

  it("handles missing or invalid input", () => {
    expect(formatAge(undefined, now)).toBe("");
    expect(formatAge("not a date", now)).toBe("");
  });
});

describe("uniqueKeys", () => {
  it("numbers repeated keys and leaves unique ones alone", () => {
    expect(uniqueKeys(["KSV0125|a", "KSV0011", "KSV0125|a", "KSV0125|a"])).toEqual([
      "KSV0125|a",
      "KSV0011",
      "KSV0125|a#1",
      "KSV0125|a#2",
    ]);
  });
});
