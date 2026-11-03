import type { ObjectMeta } from "./types/argocd";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export const SEVERITIES: readonly Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export type SeverityCounts = Record<Severity, number>;

export interface ReportSummary {
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  unknownCount?: number;
}

export interface Scanner {
  name?: string;
  version?: string;
}

export interface Vulnerability {
  vulnerabilityID: string;
  severity: string;
  title?: string;
  resource?: string;
  installedVersion?: string;
  fixedVersion?: string;
  score?: number;
  primaryLink?: string;
  publishedDate?: string;
  target?: string;
}

export interface VulnerabilityReport {
  metadata: ObjectMeta;
  report: {
    artifact?: { repository?: string; tag?: string; digest?: string };
    registry?: { server?: string };
    os?: { family?: string; name?: string };
    scanner?: Scanner;
    summary?: ReportSummary;
    updateTimestamp?: string;
    vulnerabilities?: Vulnerability[];
  };
}

export interface ConfigAuditCheck {
  checkID: string;
  title?: string;
  description?: string;
  severity: string;
  category?: string;
  messages?: string[];
  remediation?: string;
  success: boolean;
}

export interface ConfigAuditReport {
  metadata: ObjectMeta;
  report: {
    scanner?: Scanner;
    summary?: ReportSummary;
    updateTimestamp?: string;
    checks?: ConfigAuditCheck[];
  };
}

export interface ExposedSecret {
  ruleID: string;
  title?: string;
  category?: string;
  severity: string;
  target?: string;
  match?: string;
}

export interface ExposedSecretReport {
  metadata: ObjectMeta;
  report: {
    artifact?: { repository?: string; tag?: string; digest?: string };
    registry?: { server?: string };
    scanner?: Scanner;
    summary?: ReportSummary;
    updateTimestamp?: string;
    secrets?: ExposedSecret[];
  };
}

export function normalizeSeverity(value: string | undefined): Severity {
  const upper = (value ?? "").toUpperCase();
  return (SEVERITIES as readonly string[]).includes(upper) ? (upper as Severity) : "UNKNOWN";
}

export function severityRank(value: string | undefined): number {
  return SEVERITIES.indexOf(normalizeSeverity(value));
}

export function emptyCounts(): SeverityCounts {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
}

export function countBySeverity(items: readonly { severity: string }[]): SeverityCounts {
  const counts = emptyCounts();
  for (const item of items) counts[normalizeSeverity(item.severity)]++;
  return counts;
}

export function countsFromSummary(summary: ReportSummary | undefined): SeverityCounts {
  return {
    CRITICAL: summary?.criticalCount ?? 0,
    HIGH: summary?.highCount ?? 0,
    MEDIUM: summary?.mediumCount ?? 0,
    LOW: summary?.lowCount ?? 0,
    UNKNOWN: summary?.unknownCount ?? 0,
  };
}

export function addCounts(a: SeverityCounts, b: SeverityCounts): SeverityCounts {
  const sum = emptyCounts();
  for (const s of SEVERITIES) sum[s] = a[s] + b[s];
  return sum;
}

export function totalCount(counts: SeverityCounts): number {
  return SEVERITIES.reduce((n, s) => n + counts[s], 0);
}

export function imageRef(report: VulnerabilityReport | ExposedSecretReport): string {
  const { artifact, registry } = report.report;
  if (!artifact?.repository) return "";
  const host = registry?.server && registry.server !== "index.docker.io" ? `${registry.server}/` : "";
  const suffix = artifact.tag ? `:${artifact.tag}` : artifact.digest ? `@${artifact.digest}` : "";
  return `${host}${artifact.repository}${suffix}`;
}

export function containerName(report: { metadata: ObjectMeta }): string {
  return report.metadata.labels?.["trivy-operator.container.name"] ?? "";
}

/**
 * Trivy reports the same advisory once per affected file, which mostly adds
 * noise for Go binaries that vendor the same module several times.
 */
export function dedupeVulnerabilities(list: readonly Vulnerability[]): Vulnerability[] {
  const seen = new Set<string>();
  return list.filter((v) => {
    const key = `${v.vulnerabilityID}|${v.resource ?? ""}|${v.installedVersion ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Makes React keys unique by numbering repeats. trivy-operator reports one
 * check per container, so the same check ID can legitimately appear twice.
 */
export function uniqueKeys(keys: readonly string[]): string[] {
  const seen = new Map<string, number>();
  return keys.map((key) => {
    const count = seen.get(key) ?? 0;
    seen.set(key, count + 1);
    return count === 0 ? key : `${key}#${String(count)}`;
  });
}

export interface VulnerabilityFilter {
  query: string;
  severities: ReadonlySet<Severity>;
  fixableOnly: boolean;
}

export function filterVulnerabilities(list: readonly Vulnerability[], filter: VulnerabilityFilter): Vulnerability[] {
  const query = filter.query.trim().toLowerCase();
  return list.filter((v) => {
    if (filter.severities.size > 0 && !filter.severities.has(normalizeSeverity(v.severity))) return false;
    if (filter.fixableOnly && !v.fixedVersion) return false;
    if (!query) return true;
    return [v.vulnerabilityID, v.resource, v.title, v.installedVersion, v.fixedVersion].some((field) =>
      field?.toLowerCase().includes(query),
    );
  });
}

export type SortKey = "severity" | "id" | "package" | "score";
export type SortDirection = "asc" | "desc";

const compareText = (a = "", b = "") => a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });

/** Ascending severity means most severe first; ascending score means lowest first. */
export function sortVulnerabilities(
  list: readonly Vulnerability[],
  key: SortKey,
  direction: SortDirection,
): Vulnerability[] {
  const bySeverity = (a: Vulnerability, b: Vulnerability) =>
    severityRank(a.severity) - severityRank(b.severity) || (b.score ?? -1) - (a.score ?? -1);

  const comparators: Record<SortKey, (a: Vulnerability, b: Vulnerability) => number> = {
    severity: bySeverity,
    id: (a, b) => compareText(a.vulnerabilityID, b.vulnerabilityID),
    package: (a, b) => compareText(a.resource, b.resource) || bySeverity(a, b),
    score: (a, b) => (a.score ?? -1) - (b.score ?? -1) || compareText(a.vulnerabilityID, b.vulnerabilityID),
  };
  const compare = comparators[key];
  const sign = direction === "asc" ? 1 : -1;
  return [...list].sort((a, b) => sign * compare(a, b));
}
