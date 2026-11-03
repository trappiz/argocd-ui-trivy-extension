import * as React from "react";
import { vulnerabilitiesToCsv } from "../csv";
import {
  SEVERITIES,
  Severity,
  SeverityCounts,
  SortDirection,
  SortKey,
  VulnerabilityReport,
  containerName,
  countBySeverity,
  countsFromSummary,
  dedupeVulnerabilities,
  emptyCounts,
  filterVulnerabilities,
  imageRef,
  sortVulnerabilities,
} from "../reports";
import { Message, SeverityBadge, SeverityFilter, ShowMore, formatAge } from "./common";

const PAGE_SIZE = 100;

const DEFAULT_DIRECTION: Record<SortKey, SortDirection> = {
  severity: "asc",
  id: "asc",
  package: "asc",
  score: "desc",
};

function download(filename: string, content: string) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([content], { type: "text/csv;charset=utf-8" }));
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 0);
}

/** Index of the report with the most severe findings, so the dropdown opens on what matters. */
function worstReport(reports: readonly VulnerabilityReport[]): number {
  let worst = 0;
  let worstCounts: SeverityCounts = emptyCounts();
  reports.forEach((report, i) => {
    const counts = countsFromSummary(report.report.summary);
    const diff = SEVERITIES.map((s) => counts[s] - worstCounts[s]).find((d) => d !== 0) ?? 0;
    if (i === 0 || diff > 0) {
      worst = i;
      worstCounts = counts;
    }
  });
  return worst;
}

const EMPTY_REPORT: VulnerabilityReport = { metadata: { name: "" }, report: {} };

export const Vulnerabilities = ({ reports }: { reports: VulnerabilityReport[] }) => {
  const [selected, setSelected] = React.useState(() => worstReport(reports));
  const [query, setQuery] = React.useState("");
  const [severities, setSeverities] = React.useState<ReadonlySet<Severity>>(() => new Set());
  const [fixableOnly, setFixableOnly] = React.useState(false);
  const [sort, setSort] = React.useState<{ key: SortKey; direction: SortDirection }>({
    key: "severity",
    direction: "asc",
  });
  // "Show more" pages are tied to the filters they were opened for, so changing
  // a filter starts from the first page again.
  const filterKey = `${String(selected)}|${query}|${[...severities].join()}|${String(fixableOnly)}`;
  const [page, setPage] = React.useState({ filterKey, limit: PAGE_SIZE });
  const limit = page.filterKey === filterKey ? page.limit : PAGE_SIZE;

  const report = reports[Math.min(selected, reports.length - 1)] ?? EMPTY_REPORT;
  const all = React.useMemo(() => dedupeVulnerabilities(report.report.vulnerabilities ?? []), [report]);
  const counts = React.useMemo(() => countBySeverity(all), [all]);
  const fixable = React.useMemo(() => all.filter((v) => v.fixedVersion).length, [all]);
  const rows = React.useMemo(
    () => sortVulnerabilities(filterVulnerabilities(all, { query, severities, fixableOnly }), sort.key, sort.direction),
    [all, query, severities, fixableOnly, sort],
  );

  const toggleSeverity = (s: Severity) =>
    setSeverities((prev) => {
      const next = new Set(prev);
      if (!next.delete(s)) next.add(s);
      return next;
    });

  const sortBy = (key: SortKey) =>
    setSort((prev) =>
      prev.key === key
        ? { key, direction: prev.direction === "asc" ? "desc" : "asc" }
        : { key, direction: DEFAULT_DIRECTION[key] },
    );

  const header = (key: SortKey, label: string, className = "") => (
    <th
      className={`tv-sortable ${className}`}
      aria-sort={sort.key === key ? (sort.direction === "asc" ? "ascending" : "descending") : "none"}
      onClick={() => sortBy(key)}
    >
      {label}
      {sort.key === key && (
        <i className={`fa fa-caret-${sort.direction === "asc" ? "up" : "down"}`} aria-hidden="true" />
      )}
    </th>
  );

  const { scanner, os, updateTimestamp } = report.report;

  return (
    <div>
      <div className="tv-meta">
        {reports.length > 1 ? (
          <select className="tv-select" value={selected} onChange={(e) => setSelected(Number(e.target.value))}>
            {reports.map((r, i) => (
              <option key={r.metadata.name} value={i}>
                {containerName(r) || r.metadata.name}
              </option>
            ))}
          </select>
        ) : (
          containerName(report) && <span className="tv-meta__container">{containerName(report)}</span>
        )}
        <code className="tv-meta__image" title={report.report.artifact?.digest}>
          {imageRef(report)}
        </code>
        <span className="tv-meta__muted">
          {[
            os?.family && `${os.family} ${os.name ?? ""}`.trim(),
            scanner?.version && `Trivy ${scanner.version}`,
            updateTimestamp && `scanned ${formatAge(updateTimestamp)}`,
          ]
            .filter(Boolean)
            .join(" · ")}
        </span>
      </div>

      <SeverityFilter counts={counts} selected={severities} onToggle={toggleSeverity} />

      {all.length === 0 ? (
        <Message title="No known vulnerabilities">Trivy found nothing in this image.</Message>
      ) : (
        <>
          <div className="tv-toolbar">
            <input
              className="tv-search"
              type="search"
              placeholder="Search ID, package or title"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <label className="tv-checkbox">
              <input type="checkbox" checked={fixableOnly} onChange={(e) => setFixableOnly(e.target.checked)} />
              Fix available ({fixable})
            </label>
            <span className="tv-toolbar__spacer" />
            <span className="tv-meta__muted">
              {rows.length === all.length ? `${all.length} findings` : `${rows.length} of ${all.length} findings`}
            </span>
            <button
              type="button"
              className="argo-button argo-button--base-o"
              disabled={rows.length === 0}
              onClick={() => download(`${report.metadata.name}.csv`, vulnerabilitiesToCsv(rows))}
            >
              <i className="fa fa-download" aria-hidden="true" /> CSV
            </button>
          </div>

          {rows.length === 0 ? (
            <Message title="Nothing matches the current filters" />
          ) : (
            <div className="tv-table-wrap">
              <table className="tv-table">
                <thead>
                  <tr>
                    {header("severity", "Severity", "tv-col-severity")}
                    {header("id", "Vulnerability")}
                    {header("package", "Package")}
                    <th>Installed</th>
                    <th>Fixed in</th>
                    {header("score", "Score", "tv-num")}
                  </tr>
                </thead>
                <tbody>
                  {rows.slice(0, limit).map((v) => (
                    <tr key={`${v.vulnerabilityID}|${v.resource}|${v.installedVersion}`}>
                      <td>
                        <SeverityBadge severity={v.severity} />
                      </td>
                      <td>
                        {v.primaryLink ? (
                          <a href={v.primaryLink} target="_blank" rel="noopener noreferrer">
                            {v.vulnerabilityID}
                          </a>
                        ) : (
                          v.vulnerabilityID
                        )}
                        {v.title && (
                          <div className="tv-subtle" title={v.title}>
                            {v.title}
                          </div>
                        )}
                      </td>
                      <td className="tv-mono">{v.resource}</td>
                      <td className="tv-mono tv-nowrap">{v.installedVersion}</td>
                      <td className="tv-mono tv-nowrap">{v.fixedVersion || <span className="tv-subtle">—</span>}</td>
                      <td className="tv-num">{v.score !== undefined ? v.score.toFixed(1) : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <ShowMore
            shown={Math.min(limit, rows.length)}
            total={rows.length}
            onClick={() => setPage({ filterKey, limit: limit + PAGE_SIZE })}
          />
        </>
      )}
    </div>
  );
};
