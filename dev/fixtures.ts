// Synthetic data for the local preview. Shapes match trivy-operator 0.2x and
// the Argo CD v1 API; the findings themselves are made up.
import type { Application, ApplicationTree, ResourceNode } from "../src/types/argocd";
import type { ConfigAuditReport, ExposedSecretReport, Vulnerability, VulnerabilityReport } from "../src/reports";

const NS = "storefront";
const TRIVY = "aquasecurity.github.io";

export const application: Application = {
  metadata: { name: "storefront", namespace: "argocd" },
  spec: { project: "default" },
};

const node = (n: Partial<ResourceNode> & Pick<ResourceNode, "kind" | "name" | "uid">): ResourceNode => ({
  namespace: NS,
  resourceVersion: "1",
  ...n,
});

const ref = (n: ResourceNode) => ({ group: n.group, kind: n.kind, namespace: n.namespace, name: n.name, uid: n.uid });

const deploy = node({ group: "apps", kind: "Deployment", name: "web", uid: "deploy-web" });
const rsOld = node({
  group: "apps",
  kind: "ReplicaSet",
  name: "web-6b9f7c5d84",
  uid: "rs-old",
  createdAt: "2026-10-01T08:00:00Z",
  parentRefs: [ref(deploy)],
});
const rsNew = node({
  group: "apps",
  kind: "ReplicaSet",
  name: "web-7d4b9c8f6",
  uid: "rs-new",
  createdAt: "2026-10-28T09:30:00Z",
  parentRefs: [ref(deploy)],
});
const pod = node({ kind: "Pod", name: "web-7d4b9c8f6-x2kqp", uid: "pod-web", parentRefs: [ref(rsNew)] });
const sts = node({ group: "apps", kind: "StatefulSet", name: "postgres", uid: "sts-pg" });
const svc = node({ kind: "Service", name: "web", uid: "svc-web" });

const report = (kind: string, name: string, owner: ResourceNode): ResourceNode =>
  node({ group: TRIVY, version: "v1alpha1", kind, name, uid: `${kind}-${name}`, parentRefs: [ref(owner)] });

export const tree: ApplicationTree = {
  nodes: [
    deploy,
    rsOld,
    rsNew,
    pod,
    sts,
    svc,
    report("VulnerabilityReport", "replicaset-web-6b9f7c5d84-web", rsOld),
    report("VulnerabilityReport", "replicaset-web-7d4b9c8f6-web", rsNew),
    report("VulnerabilityReport", "replicaset-web-7d4b9c8f6-metrics", rsNew),
    report("ConfigAuditReport", "replicaset-web-7d4b9c8f6", rsNew),
    report("ExposedSecretReport", "replicaset-web-7d4b9c8f6-web", rsNew),
    report("VulnerabilityReport", "statefulset-postgres-postgres", sts),
    report("ConfigAuditReport", "statefulset-postgres", sts),
    report("ConfigAuditReport", "service-web", svc),
  ],
};

const PACKAGES: Array<[string, string, string | undefined]> = [
  ["openssl", "3.0.13-r0", "3.0.15-r1"],
  ["libcurl", "8.5.0-r0", "8.9.1-r0"],
  ["busybox", "1.36.1-r15", undefined],
  ["zlib", "1.3.1-r0", "1.3.1-r1"],
  ["libxml2", "2.11.7-r0", "2.11.8-r0"],
  ["golang.org/x/net", "v0.21.0", "v0.33.0"],
  ["google.golang.org/grpc", "v1.62.0", "v1.64.1"],
  ["github.com/golang-jwt/jwt/v4", "v4.5.0", "v4.5.2"],
  ["stdlib", "v1.22.1", "1.22.12"],
  ["musl", "1.2.4-r2", undefined],
  ["pcre2", "10.42-r1", undefined],
  ["expat", "2.6.0-r0", "2.6.3-r0"],
];

const SEVERITY_CYCLE = ["HIGH", "MEDIUM", "CRITICAL", "LOW", "MEDIUM", "HIGH", "UNKNOWN", "MEDIUM", "LOW", "HIGH"];
const TITLES = [
  "Heap buffer overflow when parsing crafted input",
  "Denial of service via excessive memory allocation",
  "Improper certificate validation in TLS handshake",
  "Use-after-free in connection teardown",
  "Integer overflow leads to out-of-bounds read",
  "Request smuggling through malformed headers",
  "Unbounded recursion when decoding nested structures",
];

function pick<T>(list: readonly T[], i: number): T {
  const value = list[i % list.length];
  if (value === undefined) throw new Error("empty fixture list");
  return value;
}

function vulnerabilities(seed: number, count: number): Vulnerability[] {
  return Array.from({ length: count }, (_, i) => {
    const [pkg, installed, fixed] = pick(PACKAGES, i * 7 + seed);
    const severity = pick(SEVERITY_CYCLE, i + seed);
    const id = `CVE-2026-${String(21000 + seed * 97 + i * 13).padStart(5, "0")}`;
    const score = { CRITICAL: 9.8, HIGH: 7.5, MEDIUM: 5.3, LOW: 3.1, UNKNOWN: undefined }[severity];
    return {
      vulnerabilityID: id,
      severity,
      score: score !== undefined ? Math.round((score - (i % 3) * 0.2) * 10) / 10 : undefined,
      resource: pkg,
      installedVersion: installed,
      fixedVersion: i % 5 === 4 ? undefined : fixed,
      title: `${pkg}: ${pick(TITLES, i + seed).toLowerCase()}`,
      primaryLink: `https://avd.aquasec.com/nvd/${id.toLowerCase()}`,
    };
  });
}

function summary(list: Vulnerability[]) {
  const count = (s: string) => list.filter((v) => v.severity === s).length;
  return {
    criticalCount: count("CRITICAL"),
    highCount: count("HIGH"),
    mediumCount: count("MEDIUM"),
    lowCount: count("LOW"),
    unknownCount: count("UNKNOWN"),
  };
}

function vulnReport(
  name: string,
  container: string,
  repository: string,
  tag: string,
  seed: number,
  count: number,
): VulnerabilityReport {
  const list = vulnerabilities(seed, count);
  return {
    metadata: { name, namespace: NS, labels: { "trivy-operator.container.name": container } },
    report: {
      artifact: { repository, tag },
      registry: { server: "ghcr.io" },
      os: { family: "alpine", name: "3.19.1" },
      scanner: { name: "Trivy", version: "0.58.1" },
      summary: summary(list),
      updateTimestamp: new Date(Date.now() - (seed + 1) * 47 * 60 * 1000).toISOString(),
      vulnerabilities: list,
    },
  };
}

const webAudit: ConfigAuditReport = {
  metadata: { name: "replicaset-web-7d4b9c8f6", namespace: NS },
  report: {
    scanner: { name: "Trivy", version: "0.58.1" },
    updateTimestamp: new Date(Date.now() - 52 * 60 * 1000).toISOString(),
    checks: [
      {
        checkID: "KSV014",
        title: "Root file system is not read-only",
        severity: "HIGH",
        category: "Kubernetes Security Check",
        success: false,
        messages: [
          "Container 'web' of ReplicaSet 'web-7d4b9c8f6' should set 'securityContext.readOnlyRootFilesystem' to true",
        ],
        remediation: "Change 'containers[].securityContext.readOnlyRootFilesystem' to 'true'.",
      },
      {
        checkID: "KSV020",
        title: "Runs with UID <= 10000",
        severity: "LOW",
        category: "Kubernetes Security Check",
        success: false,
        messages: ["Container 'metrics' of ReplicaSet 'web-7d4b9c8f6' should set 'securityContext.runAsUser' > 10000"],
        remediation: "Set 'containers[].securityContext.runAsUser' to an integer > 10000.",
      },
      {
        checkID: "KSV011",
        title: "CPU not limited",
        severity: "LOW",
        category: "Kubernetes Security Check",
        success: false,
        messages: ["Container 'metrics' of ReplicaSet 'web-7d4b9c8f6' should set 'resources.limits.cpu'"],
        remediation: "Set a limit value under 'containers[].resources.limits.cpu'.",
      },
      { checkID: "KSV001", title: "Can elevate its own privileges", severity: "MEDIUM", success: true },
      { checkID: "KSV003", title: "Default capabilities not dropped", severity: "LOW", success: true },
      { checkID: "KSV017", title: "Privileged container", severity: "HIGH", success: true },
    ],
  },
};

const webSecrets: ExposedSecretReport = {
  metadata: { name: "replicaset-web-7d4b9c8f6-web", namespace: NS, labels: { "trivy-operator.container.name": "web" } },
  report: {
    artifact: { repository: "acme/storefront-web", tag: "2.14.0" },
    registry: { server: "ghcr.io" },
    secrets: [
      {
        ruleID: "private-key",
        title: "Asymmetric Private Key",
        category: "AsymmetricPrivateKey",
        severity: "HIGH",
        target: "/etc/nginx/certs/dev.key",
        match: "-----BEGIN PRIVATE KEY-----*****-----END PRIVATE KEY",
      },
    ],
  },
};

const emptyAudit = (name: string): ConfigAuditReport => ({
  metadata: { name, namespace: NS },
  report: {
    checks: [
      { checkID: "KSV116", title: "Runs with a root primary or supplementary GID", severity: "LOW", success: true },
    ],
  },
});

export const manifests: Record<string, unknown> = {
  "replicaset-web-6b9f7c5d84-web": vulnReport(
    "replicaset-web-6b9f7c5d84-web",
    "web",
    "acme/storefront-web",
    "2.13.2",
    9,
    80,
  ),
  "replicaset-web-7d4b9c8f6-web": vulnReport(
    "replicaset-web-7d4b9c8f6-web",
    "web",
    "acme/storefront-web",
    "2.14.0",
    0,
    46,
  ),
  "replicaset-web-7d4b9c8f6-metrics": vulnReport(
    "replicaset-web-7d4b9c8f6-metrics",
    "metrics",
    "acme/metrics-exporter",
    "0.9.3",
    3,
    12,
  ),
  "replicaset-web-7d4b9c8f6": webAudit,
  "statefulset-postgres-postgres": vulnReport(
    "statefulset-postgres-postgres",
    "postgres",
    "library/postgres",
    "16.2-alpine",
    5,
    21,
  ),
  "statefulset-postgres": emptyAudit("statefulset-postgres"),
  "service-web": emptyAudit("service-web"),
};
manifests["replicaset-web-7d4b9c8f6-web-secrets"] = webSecrets;

export function manifestFor(kind: string, name: string): unknown {
  return kind === "ExposedSecretReport" ? manifests[`${name}-secrets`] : manifests[name];
}

export const resources = { deploy, pod, sts, svc };
