import * as React from "react";
import { ExposedSecretReport, containerName, countBySeverity, imageRef, severityRank } from "../reports";
import { Message, SeverityBadge, SeverityFilter } from "./common";

export const Secrets = ({ reports }: { reports: ExposedSecretReport[] }) => {
  const rows = React.useMemo(
    () =>
      reports
        .flatMap((r) => (r.report.secrets ?? []).map((secret) => ({ secret, report: r })))
        .sort((a, b) => severityRank(a.secret.severity) - severityRank(b.secret.severity)),
    [reports],
  );
  const counts = countBySeverity(rows.map((r) => r.secret));

  return (
    <div>
      <SeverityFilter counts={counts} />
      {rows.length === 0 ? (
        <Message title="No exposed secrets">Trivy did not find credentials or keys baked into these images.</Message>
      ) : (
        <div className="tv-table-wrap">
          <table className="tv-table">
            <thead>
              <tr>
                <th className="tv-col-severity">Severity</th>
                <th>Rule</th>
                <th>Container</th>
                <th>File</th>
                <th>Match</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ secret, report }) => (
                <tr key={`${report.metadata.name}|${secret.ruleID}|${secret.target ?? ""}|${secret.match ?? ""}`}>
                  <td>
                    <SeverityBadge severity={secret.severity} />
                  </td>
                  <td>
                    {secret.title || secret.ruleID}
                    <div className="tv-subtle">{secret.category}</div>
                  </td>
                  <td title={imageRef(report)}>{containerName(report)}</td>
                  <td className="tv-mono">{secret.target}</td>
                  <td className="tv-mono">{secret.match}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
