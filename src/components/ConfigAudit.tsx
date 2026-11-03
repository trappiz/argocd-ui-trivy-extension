import * as React from "react";
import { ConfigAuditReport, Severity, countBySeverity, normalizeSeverity, severityRank, uniqueKeys } from "../reports";
import { Message, SeverityBadge, SeverityFilter, formatAge } from "./common";

export const ConfigAudit = ({ reports }: { reports: ConfigAuditReport[] }) => {
  const [showPassed, setShowPassed] = React.useState(false);
  const [severities, setSeverities] = React.useState<ReadonlySet<Severity>>(() => new Set());

  const checks = React.useMemo(
    () =>
      reports
        .flatMap((r) => r.report.checks ?? [])
        .sort((a, b) => Number(a.success) - Number(b.success) || severityRank(a.severity) - severityRank(b.severity)),
    [reports],
  );
  const failed = checks.filter((c) => !c.success);
  const counts = countBySeverity(failed);
  const visible = checks.filter(
    (c) => (showPassed || !c.success) && (severities.size === 0 || severities.has(normalizeSeverity(c.severity))),
  );
  const keys = uniqueKeys(visible.map((c) => [c.checkID, ...(c.messages ?? [])].join("|")));
  const scanned = reports[0]?.report.updateTimestamp;

  const toggleSeverity = (s: Severity) =>
    setSeverities((prev) => {
      const next = new Set(prev);
      if (!next.delete(s)) next.add(s);
      return next;
    });

  return (
    <div>
      <div className="tv-meta">
        <span className="tv-meta__muted">
          {failed.length} of {checks.length} checks failed{scanned && ` · scanned ${formatAge(scanned)}`}
        </span>
        <span className="tv-toolbar__spacer" />
        <label className="tv-checkbox">
          <input type="checkbox" checked={showPassed} onChange={(e) => setShowPassed(e.target.checked)} />
          Show passed checks
        </label>
      </div>

      <SeverityFilter counts={counts} selected={severities} onToggle={toggleSeverity} />

      {visible.length === 0 ? (
        <Message title={failed.length === 0 ? "All checks passed" : "Nothing matches the current filters"} />
      ) : (
        <ul className="tv-checks">
          {visible.map((check, i) => (
            <li key={keys[i]} className={`tv-check${check.success ? " tv-check--passed" : ""}`}>
              <div className="tv-check__head">
                {check.success ? (
                  <span className="tv-badge tv-badge--passed">Passed</span>
                ) : (
                  <SeverityBadge severity={check.severity} />
                )}
                <span className="tv-check__title">{check.title || check.checkID}</span>
                <code className="tv-check__id">{check.checkID}</code>
              </div>
              {!check.success && (
                <div className="tv-check__body">
                  {check.messages?.map((m) => (
                    <div key={m}>{m}</div>
                  ))}
                  {check.remediation && (
                    <div className="tv-subtle">
                      <strong>Remediation:</strong> {check.remediation}
                    </div>
                  )}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};
