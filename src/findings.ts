export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  file?: string;
  line?: number;
  resource?: string;
  /** Plain-English instruction an AI coding agent can follow. */
  fix?: string;
}

export function severityAtLeast(s: Severity, min: Severity): boolean {
  return SEVERITY_ORDER.indexOf(s) <= SEVERITY_ORDER.indexOf(min);
}

export function sortFindings(f: Finding[]): Finding[] {
  return [...f].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}
