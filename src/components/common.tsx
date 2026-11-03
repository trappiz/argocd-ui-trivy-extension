import * as React from "react";
import { ApiError } from "../api";
import { SEVERITIES, Severity, SeverityCounts, normalizeSeverity } from "../reports";

const LABELS: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  UNKNOWN: "Unknown",
};

export function severityLabel(severity: string): string {
  return LABELS[normalizeSeverity(severity)];
}

export const SeverityBadge = ({ severity }: { severity: string }) => {
  const s = normalizeSeverity(severity);
  return <span className={`tv-badge tv-sev-${s.toLowerCase()}`}>{LABELS[s]}</span>;
};

interface SeverityFilterProps {
  counts: SeverityCounts;
  selected?: ReadonlySet<Severity>;
  onToggle?: (severity: Severity) => void;
}

/** Severity totals; doubles as a filter when `onToggle` is given. */
export const SeverityFilter = ({ counts, selected, onToggle }: SeverityFilterProps) => (
  <div className="tv-counts" role={onToggle ? "group" : undefined} aria-label="Filter by severity">
    {SEVERITIES.map((s) => {
      const active = !selected || selected.size === 0 || selected.has(s);
      const className = `tv-count tv-sev-${s.toLowerCase()}${active ? "" : " tv-count--off"}`;
      const content = (
        <>
          <span className="tv-count__value">{counts[s]}</span>
          <span className="tv-count__label">{LABELS[s]}</span>
        </>
      );
      return onToggle ? (
        <button
          key={s}
          type="button"
          className={className}
          aria-pressed={selected?.has(s) ?? false}
          onClick={() => onToggle(s)}
        >
          {content}
        </button>
      ) : (
        <span key={s} className={className}>
          {content}
        </span>
      );
    })}
  </div>
);

export const Message = ({ title, children }: { title: string; children?: React.ReactNode }) => (
  <div className="tv-message">
    <div className="tv-message__title">{title}</div>
    {children !== undefined && <div className="tv-message__body">{children}</div>}
  </div>
);

export const Loading = ({ label = "Loading reports…" }: { label?: string }) => (
  <div className="tv-loading">
    <i className="fa fa-circle-notch fa-spin" aria-hidden="true" /> {label}
  </div>
);

export const ErrorMessage = ({ error }: { error: Error }) => {
  if (error instanceof ApiError && error.status === 403) {
    return (
      <Message title="Access denied">Your Argo CD role is not allowed to read this application's resources.</Message>
    );
  }
  return <Message title="Could not load Trivy reports">{error.message}</Message>;
};

export function formatAge(timestamp: string | undefined, now = Date.now()): string {
  if (!timestamp) return "";
  const seconds = Math.max(0, Math.round((now - Date.parse(timestamp)) / 1000));
  if (Number.isNaN(seconds)) return "";
  if (seconds < 60) return "just now";
  const units: Array<[number, string]> = [
    [86400, "d"],
    [3600, "h"],
    [60, "m"],
  ];
  for (const [size, suffix] of units) {
    if (seconds >= size) return `${Math.floor(seconds / size)}${suffix} ago`;
  }
  return "";
}

export const ShowMore = ({ shown, total, onClick }: { shown: number; total: number; onClick: () => void }) =>
  shown < total ? (
    <div className="tv-more">
      <button type="button" className="argo-button argo-button--base-o" onClick={onClick}>
        Show more ({total - shown} remaining)
      </button>
    </div>
  ) : null;
