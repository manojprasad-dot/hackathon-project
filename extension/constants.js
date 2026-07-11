// PhishGuard Edge AI — shared constants
// Single source of truth for demo data, thresholds, and copy.
// In production these values are replaced by live model output.

export const THRESHOLDS = {
  SAFE_MAX: 30,
  WARNING_MAX: 65,
};

export const VERDICTS = {
  safe: { label: "Safe", color: "var(--safe)" },
  warning: { label: "Suspicious", color: "var(--warning)" },
  danger: { label: "Dangerous", color: "var(--danger)" },
};

export function verdictForScore(score) {
  if (score <= THRESHOLDS.SAFE_MAX) return "safe";
  if (score <= THRESHOLDS.WARNING_MAX) return "warning";
  return "danger";
}
