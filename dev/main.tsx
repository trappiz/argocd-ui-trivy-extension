// Local preview: stands in for Argo CD by providing window.extensionsAPI and
// answering the extension's API calls from fixtures. Loaded before the
// extension bundle so the registrations land here.
import * as React from "react";
import type { FlyoutProps, ResourceNode, ResourceTabProps, StatusPanelProps } from "../src/types/argocd";
import { application, manifestFor, resources, tree } from "./fixtures";

type Tab = { kind: string; title: string; component: React.ComponentType<ResourceTabProps> };
type Panel = {
  title: string;
  component: React.ComponentType<StatusPanelProps>;
  flyout?: React.ComponentType<FlyoutProps>;
};

const tabs: Tab[] = [];
const panels: Panel[] = [];

window.extensionsAPI = {
  registerResourceExtension: (component, _group, kind, title) => tabs.push({ kind, title, component }),
  registerStatusPanelExtension: (component, title, _id, flyout) => panels.push({ title, component, flyout }),
};

const realFetch = window.fetch.bind(window);
window.fetch = async (input, init) => {
  const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, location.href);
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  await new Promise((r) => setTimeout(r, 250));

  if (url.pathname.endsWith("/resource-tree")) return json(tree);
  if (url.pathname.endsWith("/resource")) {
    const manifest = manifestFor(url.searchParams.get("kind") ?? "", url.searchParams.get("name") ?? "");
    return manifest ? json({ manifest: JSON.stringify(manifest) }) : json({ message: "not found" }, 404);
  }
  return realFetch(input, init);
};

const toObject = (n: ResourceNode) => ({
  kind: n.kind,
  metadata: { name: n.name, namespace: n.namespace, uid: n.uid },
});

// ?resource=sts&dark&flyout preselects state, which keeps screenshots reproducible.
const params = new URLSearchParams(location.search);

const Harness = () => {
  const [selected, setSelected] = React.useState<keyof typeof resources>(
    (params.get("resource") as keyof typeof resources | null) ?? "deploy",
  );
  const [dark, setDark] = React.useState(params.has("dark"));
  const [flyoutOpen, setFlyoutOpen] = React.useState(params.has("flyout"));
  const resource = resources[selected];
  const tab = tabs.find((t) => t.kind === resource.kind);
  const panel = panels[0];

  return (
    <div className={dark ? "theme-dark" : ""}>
      <div className="harness">
        <header className="harness__bar">
          <strong>argocd-trivy-extension preview</strong>
          <select value={selected} onChange={(e) => setSelected(e.target.value as keyof typeof resources)}>
            {Object.entries(resources).map(([key, n]) => (
              <option key={key} value={key}>
                {n.kind}/{n.name}
              </option>
            ))}
          </select>
          <label>
            <input type="checkbox" checked={dark} onChange={(e) => setDark(e.target.checked)} /> Dark
          </label>
        </header>

        {panel && (
          <section className="harness__panel">
            <div className="harness__label">{panel.title}</div>
            <panel.component application={application} openFlyout={() => setFlyoutOpen(true)} />
          </section>
        )}

        <section className="harness__tab">
          <div className="harness__label">
            {resource.kind} / {resource.name} — {tab?.title}
          </div>
          {tab && <tab.component key={selected} application={application} resource={toObject(resource)} tree={tree} />}
        </section>

        {flyoutOpen && panel?.flyout && (
          <aside className="harness__flyout">
            <button className="harness__close" onClick={() => setFlyoutOpen(false)}>
              ×
            </button>
            <panel.flyout application={application} tree={tree} />
          </aside>
        )}
      </div>
    </div>
  );
};

window.addEventListener("load", () => {
  const ReactDOM = (
    window as unknown as { ReactDOM: { createRoot(el: Element): { render(node: React.ReactNode): void } } }
  ).ReactDOM;
  const root = document.getElementById("root");
  if (root) ReactDOM.createRoot(root).render(<Harness />);
});
