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

// Demo scenarios — used by the built-in demo switcher only.
export const DEMO_SCENARIOS = {
  safe: {
    domain: "accounts.google.com",
    score: 4,
    confidence: 98.6,
    scanMs: 3.1,
    reasons: [
      { icon: "shield-check", severity: "safe", weight: 0.9, title: "Valid certificate chain", detail: "EV certificate issued by a trusted authority, matches domain." },
      { icon: "clock", severity: "safe", weight: 0.8, title: "Established domain age", detail: "Domain registered over 10 years ago." },
      { icon: "type", severity: "safe", weight: 0.6, title: "No homograph characters", detail: "All characters are standard ASCII, no lookalikes detected." },
    ],
  },
  warning: {
    domain: "secure-paypa1-verify.com",
    score: 54,
    confidence: 87.2,
    scanMs: 4.4,
    reasons: [
      { icon: "type", severity: "warning", weight: 0.7, title: "Suspicious keyword pattern", detail: "Brand name combined with \u201cverify\u201d / \u201csecure\u201d in subdomain." },
      { icon: "link", severity: "warning", weight: 0.55, title: "Newly registered domain", detail: "Domain was registered 6 days ago." },
      { icon: "route", severity: "warning", weight: 0.4, title: "One redirect before landing", detail: "Single redirect through a URL shortener." },
    ],
  },
  danger: {
    domain: "185.23.41.9/login/secure",
    score: 92,
    confidence: 99.1,
    scanMs: 3.8,
    reasons: [
      { icon: "server", severity: "danger", weight: 0.95, title: "Raw IP address as host", detail: "URL uses an IP address instead of a domain name." },
      { icon: "key-round", severity: "danger", weight: 0.85, title: "Login form on unverified host", detail: "Password field detected on a domain with no certificate." },
      { icon: "shuffle", severity: "danger", weight: 0.7, title: "High URL entropy", detail: "Path contains randomized characters typical of phishing kits." },
      { icon: "route", severity: "danger", weight: 0.6, title: "4 redirects before landing", detail: "Chain crosses 3 different top-level domains." },
    ],
  },
  offline: {
    domain: "internal-tool.local",
    score: 12,
    confidence: 91.4,
    scanMs: 2.6,
    reasons: [
      { icon: "wifi-off", severity: "safe", weight: 0.5, title: "Offline inference", detail: "No network connection — scored using on-device model only." },
      { icon: "shield-check", severity: "safe", weight: 0.4, title: "Local network host", detail: "Resolved to a private IP range." },
    ],
  },
};

export const RECENT_SCANS_SEED = [
  { domain: "github.com", score: 2, confidence: 99.2, latencyMs: 2.8, time: "2m ago" },
  { domain: "mail.google.com", score: 3, confidence: 98.9, latencyMs: 3.0, time: "14m ago" },
  { domain: "secure-paypa1-verify.com", score: 54, confidence: 87.2, latencyMs: 4.4, time: "31m ago" },
  { domain: "figma.com", score: 5, confidence: 99.0, latencyMs: 2.9, time: "1h ago" },
];
