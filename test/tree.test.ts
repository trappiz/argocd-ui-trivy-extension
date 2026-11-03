import { describe, expect, it } from "vitest";
import { currentReportNodes, findReportNodes } from "../src/tree";
import type { ApplicationTree, K8sObject, ResourceNode } from "../src/types/argocd";

const TRIVY = "aquasecurity.github.io";

function n(kind: string, name: string, parent?: ResourceNode, extra: Partial<ResourceNode> = {}): ResourceNode {
  return {
    kind,
    name,
    namespace: "app",
    uid: `${kind}/${name}`,
    parentRefs: parent ? [{ kind: parent.kind, name: parent.name, namespace: "app", uid: parent.uid }] : undefined,
    ...extra,
  };
}

const report = (kind: string, name: string, owner: ResourceNode) => n(kind, name, owner, { group: TRIVY });
const obj = (node: ResourceNode): K8sObject => ({
  kind: node.kind,
  metadata: { name: node.name, namespace: "app", uid: node.uid },
});
const names = (nodes: ResourceNode[]) => nodes.map((x) => x.name).sort();

describe("findReportNodes", () => {
  const deploy = n("Deployment", "web", undefined, { group: "apps" });
  const rsOld = n("ReplicaSet", "web-1", deploy, { group: "apps", createdAt: "2026-01-01T00:00:00Z" });
  const rsNew = n("ReplicaSet", "web-2", deploy, { group: "apps", createdAt: "2026-02-01T00:00:00Z" });
  const pod = n("Pod", "web-2-abcde", rsNew);
  const cron = n("CronJob", "backup", undefined, { group: "batch" });
  const job = n("Job", "backup-2915", cron, { group: "batch" });
  const jobPod = n("Pod", "backup-2915-xyz", job);
  const svc = n("Service", "web");
  const orphan = n("ConfigMap", "settings");

  const tree: ApplicationTree = {
    nodes: [
      deploy,
      rsOld,
      rsNew,
      pod,
      cron,
      job,
      jobPod,
      svc,
      orphan,
      report("VulnerabilityReport", "replicaset-web-1-app", rsOld),
      report("VulnerabilityReport", "replicaset-web-2-app", rsNew),
      report("VulnerabilityReport", "replicaset-web-2-sidecar", rsNew),
      report("ConfigAuditReport", "replicaset-web-2", rsNew),
      report("VulnerabilityReport", "cronjob-backup-backup", cron),
      report("ConfigAuditReport", "service-web", svc),
      // Same kind name but a different API group must be ignored.
      n("VulnerabilityReport", "unrelated", rsNew, { group: "example.com" }),
    ],
  };

  it("finds reports below a Deployment and ignores superseded ReplicaSets", () => {
    expect(names(findReportNodes(tree, obj(deploy)))).toEqual([
      "replicaset-web-2",
      "replicaset-web-2-app",
      "replicaset-web-2-sidecar",
    ]);
  });

  it("falls back to the owner chain for a Pod", () => {
    expect(names(findReportNodes(tree, obj(pod)))).toContain("replicaset-web-2-app");
  });

  it("walks more than one level up", () => {
    expect(names(findReportNodes(tree, obj(jobPod)))).toEqual(["cronjob-backup-backup"]);
  });

  it("returns reports owned directly by the resource", () => {
    expect(names(findReportNodes(tree, obj(svc)))).toEqual(["service-web"]);
  });

  it("returns nothing for resources without reports", () => {
    expect(findReportNodes(tree, obj(orphan))).toEqual([]);
  });

  it("matches by kind and name when the uid is unknown", () => {
    const resource: K8sObject = { kind: "Service", metadata: { name: "web", namespace: "app" } };
    expect(names(findReportNodes(tree, resource))).toEqual(["service-web"]);
  });

  it("returns nothing for resources outside the tree", () => {
    const resource: K8sObject = { kind: "Deployment", metadata: { name: "other", namespace: "app" } };
    expect(findReportNodes(tree, resource)).toEqual([]);
    expect(findReportNodes({}, resource)).toEqual([]);
  });

  it("keeps an older ReplicaSet while the new one has not been scanned yet", () => {
    const partial: ApplicationTree = {
      nodes: [deploy, rsOld, rsNew, report("VulnerabilityReport", "replicaset-web-1-app", rsOld)],
    };
    expect(names(findReportNodes(partial, obj(deploy)))).toEqual(["replicaset-web-1-app"]);
  });

  it("lists current reports across the application", () => {
    expect(names(currentReportNodes(tree, "VulnerabilityReport"))).toEqual([
      "cronjob-backup-backup",
      "replicaset-web-2-app",
      "replicaset-web-2-sidecar",
    ]);
  });
});
