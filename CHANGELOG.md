# Changelog

## 0.2.0

- Make bare `wirewhy` check a saved site, with a first-run setup prompt.
- Add NGINX health and local/SSH log inspection after website failures.
- Discover and remember app services from upstream ports; support explicit units and log files.
- Resolve named NGINX upstreams and preserve inherited logs alongside location logs.
- Show matched error excerpts with timestamps, confidence, and credential redaction.
- Detect stalled response bodies even after HTTP 200 headers.
- Show concise, matched error excerpts in the terminal and omit duplicate access-log entries.

## 0.1.0

- Add URL diagnostics, synchronous error explanations, and passive request observation.
- Add `check`, `explain`, and `run` commands.
- Add text, JSON, Markdown, and JSONL reports.
- Ship CommonJS, ESM, and TypeScript declarations with zero runtime dependencies.
