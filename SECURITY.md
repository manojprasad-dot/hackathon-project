# Security Policy

## Architecture

PhishGuard Edge AI performs **all** phishing detection inference on-device using ONNX Runtime Web (WebAssembly). No URLs, domains, or browsing metadata are transmitted to external servers.

## Reporting a Vulnerability

If you discover a security vulnerability in PhishGuard Edge AI, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email: [security@phishguard.dev](mailto:security@phishguard.dev)
3. Include a detailed description and reproduction steps
4. Allow 48 hours for initial response

## Scope

| Component | In Scope |
|-----------|----------|
| Extension JavaScript (background.js, content.js, predictor.js) | ✅ |
| ONNX model inference pipeline | ✅ |
| Feature extraction logic | ✅ |
| Training scripts (backend/) | ❌ (offline only) |
| Third-party ONNX Runtime Web library | ❌ (report upstream) |

## Privacy Guarantees

- Zero URLs transmitted to external servers
- Zero cloud API calls for inference
- All scan history stored in `chrome.storage.local` only
- No telemetry, analytics, or tracking
