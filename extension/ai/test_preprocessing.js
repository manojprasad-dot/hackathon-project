/**
 * PhishGuard -- extension/ai/test_preprocessing.js
 * Quick smoke-test: run extractFeatures() on known phishing and safe URLs
 * and print the 30-feature vectors.
 *
 * Usage:  node extension/ai/test_preprocessing.js
 */

// Minimal shim so preprocessing.js "require" works in Node
const { extractFeatures, FEATURE_NAMES } = require("./preprocessing.js");

const TEST_CASES = [
  { url: "https://google.com",                            expected: "SAFE"     },
  { url: "https://github.com",                            expected: "SAFE"     },
  { url: "http://paypal-secure-login.xyz/verify",         expected: "PHISHING" },
  { url: "http://192.168.1.1/phishing-page",              expected: "PHISHING" },
  { url: "https://amazon-account-update.club/login",      expected: "PHISHING" },
  { url: "https://secure.paypa1.com/signin",              expected: "PHISHING" },
  { url: "https://dropbox-file-share.tk/download",        expected: "PHISHING" },
  { url: "https://netflix.com",                           expected: "SAFE"     },
];

console.log("\n" + "=".repeat(72));
console.log("  PhishGuard -- preprocessing.js smoke test");
console.log("  Verifying 30-feature extraction on known URLs");
console.log("=".repeat(72));

let allOk = true;

for (const { url, expected } of TEST_CASES) {
  const { features, vector } = extractFeatures(url);

  // Quick heuristic: flag score
  let score = 0;
  if (features.is_ip_address)           score += 0.70;
  if (features.brand_in_hostname)       score += 0.55;
  if (features.has_suspicious_keyword)  score += 0.40;
  if (features.is_known_tld_suspicious) score += 0.35;
  if (features.is_known_legitimate)     score -= 1.00;
  const predicted = score > 0.3 ? "PHISHING" : "SAFE";
  const correct   = predicted === expected;
  if (!correct) allOk = false;

  console.log(`\n  ${correct ? "OK" : "WRONG"} | ${expected.padEnd(8)} → ${predicted.padEnd(8)}`);
  console.log(`       URL   : ${url}`);
  console.log(`       Score : ${score.toFixed(2)}`);
  console.log(`       ip=${features.is_ip_address} https=${features.uses_https} known_legit=${features.is_known_legitimate} brand=${features.brand_in_hostname} kw=${features.has_suspicious_keyword} tld=${features.is_known_tld_suspicious}`);
  console.log(`       vector[0..5]: [${Array.from(vector).slice(0,6).join(", ")}]`);
}

console.log("\n" + "=".repeat(72));
console.log(allOk ? "  ALL TESTS PASSED" : "  SOME TESTS FAILED");
console.log("  Feature vector length: " + FEATURE_NAMES.length);
console.log("=".repeat(72) + "\n");

process.exit(allOk ? 0 : 1);
