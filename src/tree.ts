import type { ApplicationTree, K8sObject, ResourceNode } from "./types/argocd";

export const TRIVY_GROUP = "aquasecurity.github.io";

export type ReportKind = "VulnerabilityReport" | "ConfigAuditReport" | "ExposedSecretReport";

const REPORT_KINDS: ReadonlySet<string> = new Set<ReportKind>([
  "VulnerabilityReport",
  "ConfigAuditReport",
  "ExposedSecretReport",
]);

export function isReportNode(node: ResourceNode): boolean {
  return node.group === TRIVY_GROUP && REPORT_KINDS.has(node.kind);
}

interface TreeIndex {
  byUid: Map<string, ResourceNode>;
  children: Map<string, ResourceNode[]>;
}

function indexTree(tree: ApplicationTree): TreeIndex {
  const byUid = new Map<string, ResourceNode>();
  const children = new Map<string, ResourceNode[]>();
  for (const node of tree.nodes ?? []) {
    if (node.uid) byUid.set(node.uid, node);
    for (const parent of node.parentRefs ?? []) {
      if (!parent.uid) continue;
      const list = children.get(parent.uid) ?? [];
      list.push(node);
      children.set(parent.uid, list);
    }
  }
  return { byUid, children };
}

function ownedReports(index: TreeIndex, uid: string): ResourceNode[] {
  return (index.children.get(uid) ?? []).filter(isReportNode);
}

function owners(index: TreeIndex, report: ResourceNode): ResourceNode[] {
  return (report.parentRefs ?? [])
    .map((ref) => (ref.uid ? index.byUid.get(ref.uid) : undefined))
    .filter((n): n is ResourceNode => n !== undefined);
}

/**
 * A Deployment or Rollout keeps old ReplicaSets around, and trivy-operator may
 * still have reports for them. Only the newest ReplicaSet per controller is
 * what actually runs, so reports owned by older siblings are dropped.
 */
function dropSupersededReplicaSets(index: TreeIndex, reports: ResourceNode[]): ResourceNode[] {
  const newest = new Map<string, ResourceNode>();
  for (const report of reports) {
    for (const owner of owners(index, report)) {
      const controller = owner.kind === "ReplicaSet" ? owner.parentRefs?.[0]?.uid : undefined;
      if (!controller) continue;
      const current = newest.get(controller);
      if (!current || (owner.createdAt ?? "") > (current.createdAt ?? "")) newest.set(controller, owner);
    }
  }
  return reports.filter((report) =>
    owners(index, report).every((owner) => {
      const controller = owner.kind === "ReplicaSet" ? owner.parentRefs?.[0]?.uid : undefined;
      return !controller || newest.get(controller)?.uid === owner.uid;
    }),
  );
}

function findNode(index: TreeIndex, tree: ApplicationTree, resource: K8sObject): ResourceNode | undefined {
  const { uid, name, namespace } = resource.metadata;
  if (uid && index.byUid.has(uid)) return index.byUid.get(uid);
  return (tree.nodes ?? []).find(
    (n) => n.kind === resource.kind && n.name === name && (n.namespace ?? "") === (namespace ?? ""),
  );
}

/**
 * Returns the Trivy report nodes that describe `resource`.
 *
 * trivy-operator attaches reports to the object it scanned, which is not
 * always the object the user clicked on: a Deployment's images are scanned via
 * its ReplicaSet, and a Pod's via its owner. So we first look at the resource
 * and everything below it, and if that turns up nothing, walk up the owner
 * chain until we find an ancestor with reports.
 */
export function findReportNodes(tree: ApplicationTree, resource: K8sObject): ResourceNode[] {
  const index = indexTree(tree);
  const self = findNode(index, tree, resource);
  if (!self?.uid) return [];

  const found: ResourceNode[] = [];
  const queue: ResourceNode[] = [self];
  const seen = new Set<string>();
  for (let node = queue.shift(); node; node = queue.shift()) {
    if (!node.uid || seen.has(node.uid)) continue;
    seen.add(node.uid);
    for (const child of index.children.get(node.uid) ?? []) {
      if (isReportNode(child)) found.push(child);
      else queue.push(child);
    }
  }
  if (found.length > 0) return dropSupersededReplicaSets(index, found);

  let current: ResourceNode | undefined = self;
  while (current) {
    const parentUid: string | undefined = current.parentRefs?.[0]?.uid;
    current = parentUid ? index.byUid.get(parentUid) : undefined;
    if (current?.uid) {
      const reports = ownedReports(index, current.uid);
      if (reports.length > 0) return reports;
    }
  }
  return [];
}

/** All reports of one kind in the application, minus superseded ReplicaSets. */
export function currentReportNodes(tree: ApplicationTree, kind: ReportKind): ResourceNode[] {
  const index = indexTree(tree);
  const reports = (tree.nodes ?? []).filter((n) => isReportNode(n) && n.kind === kind);
  return dropSupersededReplicaSets(index, reports);
}
