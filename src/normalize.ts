// Trivy reports are ordinary custom resources: anyone allowed to write them in
// a namespace controls their content. Everything read from a manifest goes
// through here, so the UI only ever sees well-typed values and safe links.
import type {
  ConfigAuditCheck,
  ConfigAuditReport,
  ExposedSecret,
  ExposedSecretReport,
  ReportSummary,
  Scanner,
  Vulnerability,
  VulnerabilityReport,
} from "./reports";
import type { ObjectMeta } from "./types/argocd";

type Obj = Record<string, unknown>;

const obj = (value: unknown): Obj =>
  typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Obj) : {};
const arr = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
const str = (value: unknown): string | undefined => (typeof value === "string" ? value : undefined);
const num = (value: unknown): number | undefined =>
  typeof value === "number" && Number.isFinite(value) ? value : undefined;

/** Returns the URL only if it is an absolute http(s) link, so `javascript:` and friends never reach an href. */
export function safeHttpUrl(value: unknown): string | undefined {
  const text = str(value);
  if (!text) return undefined;
  try {
    const url = new URL(text);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : undefined;
  } catch {
    return undefined;
  }
}

function metadata(value: unknown): ObjectMeta {
  const m = obj(value);
  const labels: Record<string, string> = {};
  for (const [key, label] of Object.entries(obj(m.labels))) {
    if (typeof label === "string") labels[key] = label;
  }
  return {
    name: str(m.name) ?? "",
    namespace: str(m.namespace),
    uid: str(m.uid),
    resourceVersion: str(m.resourceVersion),
    labels,
  };
}

function summary(value: unknown): ReportSummary {
  const s = obj(value);
  return {
    criticalCount: num(s.criticalCount),
    highCount: num(s.highCount),
    mediumCount: num(s.mediumCount),
    lowCount: num(s.lowCount),
    unknownCount: num(s.unknownCount),
  };
}

function scanner(value: unknown): Scanner {
  const s = obj(value);
  return { name: str(s.name), version: str(s.version) };
}

function artifact(value: unknown) {
  const a = obj(value);
  return { repository: str(a.repository), tag: str(a.tag), digest: str(a.digest) };
}

function vulnerability(value: unknown): Vulnerability {
  const v = obj(value);
  return {
    vulnerabilityID: str(v.vulnerabilityID) ?? "",
    severity: str(v.severity) ?? "UNKNOWN",
    title: str(v.title),
    resource: str(v.resource),
    installedVersion: str(v.installedVersion),
    fixedVersion: str(v.fixedVersion),
    score: num(v.score),
    primaryLink: safeHttpUrl(v.primaryLink),
    publishedDate: str(v.publishedDate),
    target: str(v.target),
  };
}

function check(value: unknown): ConfigAuditCheck {
  const c = obj(value);
  return {
    checkID: str(c.checkID) ?? "",
    title: str(c.title),
    description: str(c.description),
    severity: str(c.severity) ?? "UNKNOWN",
    category: str(c.category),
    messages: arr(c.messages).filter((m): m is string => typeof m === "string"),
    remediation: str(c.remediation),
    success: c.success === true,
  };
}

function secret(value: unknown): ExposedSecret {
  const s = obj(value);
  return {
    ruleID: str(s.ruleID) ?? "",
    title: str(s.title),
    category: str(s.category),
    severity: str(s.severity) ?? "UNKNOWN",
    target: str(s.target),
    match: str(s.match),
  };
}

export function toVulnerabilityReport(raw: unknown): VulnerabilityReport {
  const m = obj(raw);
  const r = obj(m.report);
  const os = obj(r.os);
  return {
    metadata: metadata(m.metadata),
    report: {
      artifact: artifact(r.artifact),
      registry: { server: str(obj(r.registry).server) },
      os: { family: str(os.family), name: str(os.name) },
      scanner: scanner(r.scanner),
      summary: summary(r.summary),
      updateTimestamp: str(r.updateTimestamp),
      vulnerabilities: arr(r.vulnerabilities).map(vulnerability),
    },
  };
}

export function toConfigAuditReport(raw: unknown): ConfigAuditReport {
  const m = obj(raw);
  const r = obj(m.report);
  return {
    metadata: metadata(m.metadata),
    report: {
      scanner: scanner(r.scanner),
      summary: summary(r.summary),
      updateTimestamp: str(r.updateTimestamp),
      checks: arr(r.checks).map(check),
    },
  };
}

export function toExposedSecretReport(raw: unknown): ExposedSecretReport {
  const m = obj(raw);
  const r = obj(m.report);
  return {
    metadata: metadata(m.metadata),
    report: {
      artifact: artifact(r.artifact),
      registry: { server: str(obj(r.registry).server) },
      scanner: scanner(r.scanner),
      summary: summary(r.summary),
      updateTimestamp: str(r.updateTimestamp),
      secrets: arr(r.secrets).map(secret),
    },
  };
}
