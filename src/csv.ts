import type { Vulnerability } from "./reports";

function escape(value: string | number | undefined): string {
  let text = value === undefined ? "" : String(value);
  // Report fields are untrusted; stop spreadsheets from evaluating them as formulas.
  if (typeof value === "string" && /^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function toCsv(rows: ReadonlyArray<ReadonlyArray<string | number | undefined>>): string {
  return rows.map((row) => row.map(escape).join(",")).join("\r\n") + "\r\n";
}

export function vulnerabilitiesToCsv(list: readonly Vulnerability[]): string {
  return toCsv([
    ["Severity", "ID", "Package", "Installed", "Fixed", "Score", "Title", "Link"],
    ...list.map((v) => [
      v.severity,
      v.vulnerabilityID,
      v.resource,
      v.installedVersion,
      v.fixedVersion,
      v.score,
      v.title,
      v.primaryLink,
    ]),
  ]);
}
