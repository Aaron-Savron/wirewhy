# API

## `inspectSite(url, options?)`

Returns `Promise<SiteReport>`. Uses GET and reads up to 1 MB of the response under the request timeout. If the response fails, it inspects recent server logs when server access is configured.

Options: `ssh` (alias or `user@host`), `sshConfig` (absolute path), `local`, `sudo`, `service` (systemd unit), `logs` (absolute app log paths), `nginxConfig` (absolute path), `includeLogs`, `timeoutMs`, `method`, and `signal`. `discoveredService` supplies a previous unit when the upstream is no longer listening; the CLI saves this automatically.

On a failed public check, Wirewhy probes `/` directly against the matching NGINX listener on the configured server. It sends the site's hostname as `Host` and TLS SNI, then compares that response with the public result. Query strings and custom URL paths are not sent to this probe.

`formatSiteReport(report, format?)` returns text, JSON, or Markdown. The report includes website status, NGINX process/unit/config health, app service status, and selected log excerpts. `complete: false` means server inspection was missing or incomplete.

SSH checks stream a Python 3 collector to the server. No files or agent are installed. Config tests use NGINX’s `-T`; log reads are bounded to recent tail entries and ten-minute journals.

## `diagnose(url, options?)`

Returns `Promise<Report>`. Sends HEAD by default, with optional DNS, TCP, and TLS checks after a transport failure.

| Option | Default | Meaning |
| --- | --- | --- |
| `method` | `HEAD` | `HEAD` or `GET` |
| `timeoutMs` | `5000` | Per-stage timeout, from 1 to 60000 |
| `signal` | none | Cancel the check and follow-up probes |
| `compareSystemCa` | `true` | Compare certificate stores after a TLS validation error |

The system-CA comparison starts two fresh Node processes with different trust settings, both connecting to the same resolved address. It is skipped if the runtime lacks `--use-system-ca` or proxy configuration makes a direct comparison unreliable. TCP probes test one resolved address per family, directly from the current host.

## `explain(error, options?)`

Returns `Report` synchronously. Reads error codes from nested causes and AggregateError children. It does not parse error messages or make network requests.

Options: `url`, `method`, `status`, `durationMs`, `runtime`, and `checks`. Supply the latter two when integrating with your own diagnostics. HTTP status alone can be explained with `explain(null, { url, status: 429 })`.

## `observe({ onReport, includeSuccessful? })`

Returns an unsubscribe function. Transport failures and HTTP status errors are reported by default. Status errors are reported when headers arrive; successful requests are reported when the response completes. Each request emits at most one report.

Callback exceptions and rejected promises are contained. Keep callbacks short because diagnostic subscriptions run inside the HTTP client. `run --output` uses synchronous file appends and is intended for debugging.

## `formatReport(report, format?)`

Returns text, JSON, or a Markdown code block. Default: `text`.

## Report

`schemaVersion` is `1`. Reports include `timestamp`, `outcome`, `request`, `runtime`, `error`, `checks`, and `findings`. `diagnose` also includes total `checkDurationMs`; `request.durationMs` covers the HTTP attempt and redirects.

Findings contain a stable `code`, `confidence`, `summary`, `evidence`, and `nextSteps`. An unknown failure remains unknown. Use finding codes for programmatic handling.

Preload settings: `WIREWHY_FORMAT`, `WIREWHY_ALL=1`, and `WIREWHY_OUTPUT` (JSONL file path).
