import type { Application, ApplicationTree, ResourceNode } from "./types/argocd";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function url(path: string, params: Record<string, string | undefined>): string {
  // Respect --rootpath: Argo CD sets <base href> to the configured root.
  const target = new URL(path, document.baseURI);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") target.searchParams.set(key, value);
  }
  return target.toString();
}

async function getJson<T>(href: string): Promise<T> {
  const response = await fetch(href, { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (!response.ok) {
    let message = response.statusText;
    try {
      message = ((await response.json()) as { message?: string }).message || message;
    } catch {
      // Body was not JSON; keep the status text.
    }
    throw new ApiError(response.status, message);
  }
  return (await response.json()) as T;
}

function appParams(app: Application) {
  return { appNamespace: app.metadata.namespace, project: app.spec.project };
}

export function getResourceTree(app: Application): Promise<ApplicationTree> {
  const name = encodeURIComponent(app.metadata.name);
  return getJson(url(`api/v1/applications/${name}/resource-tree`, appParams(app)));
}

// Report objects are immutable per resourceVersion, so successful lookups can
// be shared between the resource tab, the status panel and the flyout.
const manifestCache = new Map<string, Promise<unknown>>();

export function getManifest<T>(app: Application, node: ResourceNode): Promise<T> {
  const key = `${node.uid}@${node.resourceVersion ?? ""}`;
  const cached = manifestCache.get(key);
  if (cached) return cached as Promise<T>;

  const name = encodeURIComponent(app.metadata.name);
  const request = getJson<{ manifest: string }>(
    url(`api/v1/applications/${name}/resource`, {
      ...appParams(app),
      name: node.name,
      resourceName: node.name,
      namespace: node.namespace,
      group: node.group,
      version: node.version || "v1alpha1",
      kind: node.kind,
    }),
  ).then((res) => JSON.parse(res.manifest) as T);

  manifestCache.set(key, request);
  request.catch(() => manifestCache.delete(key));
  const oldest = manifestCache.keys().next();
  if (manifestCache.size > 500 && !oldest.done) manifestCache.delete(oldest.value);
  return request;
}

export interface Fetched<T> {
  node: ResourceNode;
  manifest: T;
}

/** Fetches manifests with a small concurrency limit to avoid flooding argocd-server. Order is preserved. */
export async function getManifests<T>(
  app: Application,
  nodes: readonly ResourceNode[],
  limit = 6,
): Promise<Fetched<T>[]> {
  const results: Fetched<T>[] = [];
  let next = 0;
  const worker = async () => {
    for (let i = next++; i < nodes.length; i = next++) {
      const node = nodes[i];
      if (node) results[i] = { node, manifest: await getManifest<T>(app, node) };
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, nodes.length) }, worker));
  return results;
}
