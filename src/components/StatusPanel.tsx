import * as React from "react";
import { getManifests, getResourceTree } from "../api";
import { appKey, useAsync } from "../hooks";
import {
  SEVERITIES,
  Severity,
  SeverityCounts,
  VulnerabilityReport,
  addCounts,
  containerName,
  countsFromSummary,
  emptyCounts,
  imageRef,
} from "../reports";
import { currentReportNodes } from "../tree";
import type { Application, ApplicationTree, FlyoutProps, StatusPanelProps } from "../types/argocd";
import { ErrorMessage, Loading, Message, SeverityFilter, severityLabel } from "./common";

interface WorkloadRow {
  key: string;
  owner: string;
  ownerKind: string;
  namespace?: string;
  container: string;
  image: string;
  counts: SeverityCounts;
}

async function loadRows(application: Application, tree: ApplicationTree): Promise<WorkloadRow[]> {
  const nodes = currentReportNodes(tree, "VulnerabilityReport");
  const reports = await getManifests<VulnerabilityReport>(application, nodes);
  return reports.map(({ node, manifest: report }) => {
    const owner = node.parentRefs?.[0];
    return {
      key: node.uid ?? report.metadata.name,
      owner: owner?.name ?? report.metadata.name,
      ownerKind: owner?.kind ?? "",
      namespace: node.namespace,
      container: containerName(report),
      image: imageRef(report),
      counts: countsFromSummary(report.report.summary),
    };
  });
}

const worstFirst = (a: WorkloadRow, b: WorkloadRow) => {
  for (const s of SEVERITIES) {
    if (a.counts[s] !== b.counts[s]) return b.counts[s] - a.counts[s];
  }
  return a.owner.localeCompare(b.owner);
};

const REFRESH_MS = 5 * 60 * 1000;

/** Compact summary in the application header. Fetches its own tree because Argo CD does not pass one here. */
export const StatusPanel = ({ application, openFlyout }: StatusPanelProps) => {
  const [tick, setTick] = React.useState(0);
  React.useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), REFRESH_MS);
    return () => clearInterval(id);
  }, []);

  const state = useAsync(
    async () => loadRows(application, await getResourceTree(application)),
    `${appKey(application)}|${tick}`,
    true,
  );

  if (!state.data) {
    return (
      <div className="tv tv-panel">
        <span className="tv-subtle" title={state.error?.message}>
          {state.error ? "Unavailable" : "Loading…"}
        </span>
      </div>
    );
  }

  const totals = state.data.reduce((sum, row) => addCounts(sum, row.counts), emptyCounts());
  const headline: Severity[] = ["CRITICAL", "HIGH"];

  return (
    <div className="tv tv-panel">
      {state.data.length === 0 ? (
        <span className="tv-subtle">No reports</span>
      ) : (
        <button
          type="button"
          className="tv-panel__button"
          onClick={openFlyout}
          title="Show vulnerabilities per workload"
        >
          {headline.map((s) => (
            <span key={s} className={`tv-panel__count${totals[s] > 0 ? ` tv-sev-${s.toLowerCase()}` : ""}`}>
              <span className="tv-panel__value">{totals[s]}</span> {severityLabel(s)}
            </span>
          ))}
        </button>
      )}
    </div>
  );
};

export const Flyout = ({ application, tree }: FlyoutProps) => {
  const reportKey = currentReportNodes(tree, "VulnerabilityReport")
    .map((n) => `${n.uid}@${n.resourceVersion}`)
    .join(",");
  const state = useAsync(() => loadRows(application, tree), `${appKey(application)}|${reportKey}`);

  if (state.error)
    return (
      <div className="tv">
        <ErrorMessage error={state.error} />
      </div>
    );
  if (!state.data)
    return (
      <div className="tv">
        <Loading />
      </div>
    );

  const rows = [...state.data].sort(worstFirst);
  const totals = rows.reduce((sum, row) => addCounts(sum, row.counts), emptyCounts());

  return (
    <div className="tv tv-flyout">
      <h4 className="tv-flyout__title">Vulnerabilities in {application.metadata.name}</h4>
      {rows.length === 0 ? (
        <Message title="No vulnerability reports in this application" />
      ) : (
        <>
          <SeverityFilter counts={totals} />
          <div className="tv-table-wrap">
            <table className="tv-table">
              <thead>
                <tr>
                  <th>Workload</th>
                  <th>Container</th>
                  {SEVERITIES.map((s) => (
                    <th key={s} className="tv-num" title={severityLabel(s)}>
                      {s.charAt(0)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.key}>
                    <td>
                      {row.owner}
                      <div className="tv-subtle">{[row.ownerKind, row.namespace].filter(Boolean).join(" · ")}</div>
                    </td>
                    <td>
                      {row.container}
                      <div className="tv-subtle tv-mono">{row.image}</div>
                    </td>
                    {SEVERITIES.map((s) => (
                      <td
                        key={s}
                        className={`tv-num${row.counts[s] > 0 ? ` tv-cell-${s.toLowerCase()}` : " tv-subtle"}`}
                      >
                        {row.counts[s]}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="tv-subtle tv-flyout__hint">Open a workload and select its Security tab for the full list.</p>
        </>
      )}
    </div>
  );
};
