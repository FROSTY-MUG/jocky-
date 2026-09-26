# 06 — Frontend Dashboard

Stack: **TypeScript** (strict, `noUncheckedIndexedAccess`), **React 18** + **Vite**, **Tailwind CSS 3.4**, **Framer Motion 11**, **TanStack Query v5** (server state), **Zustand** (UI state), **React Router v6**, **Recharts** (metrics), **Cytoscape.js** with `cytoscape-dagre` (the process→network→file graph), **@tanstack/react-virtual** (large evidence tables), **Zod** (runtime validation of every API response), **Radix UI** primitives (accessible, unstyled) styled with Tailwind.

Rendering budget: the fleet view must stay at 60 fps with 5,000 agents; the graph must lay out 2,000 nodes/5,000 edges in < 800 ms. Both are enforced by a Playwright perf test in CI.

---

## 1. Information architecture

```
/                       → Overview (fleet health, active jobs, top findings, alert banner)
/agents                 → Agents list (filter: team, state, platform, version, variant, last-seen)
/agents/:id             → Agent detail (health, collectors, journal, version pin, quarantine/revoke)
/jobs                   → Jobs list (filter: state, script, requester, ticket, time range)
/jobs/new               → Job composer (script → scope → budget → schedule → review → submit)
/jobs/:id               → Job detail (per-target state, progress, logs, consent metadata, bundles)
/scripts                → Modules & builds (variants, hashes, diversity report, tlog proof, revoke)
/findings               → Findings workbench (severity/technique/status filters, bulk triage, saved views)
/findings/:id           → Finding detail (evidence refs, graph excerpt, timeline, MITRE mapping, comments)
/graph                  → Graph explorer (free-form: root entity, depth, kind filters, time scrubber)
/timeline               → Timeline (multi-agent merged, zoom to second, artifact lanes)
/audit                  → Audit log (append-only view, chain verification status, export)
/settings               → Team, RBAC, retention, correlation rules, integrations
/settings/security      → Session, passkeys, VPN posture, WebRTC policy status
```

---

## 2. Key views

### 2.1 Overview

- **Fleet strip**: `healthy / degraded / quarantined / offline` counts as animated segmented bars (Framer Motion `layout` transitions, not decorative spinners).
- **Active jobs**: a compact table with live per-target progress (WSS), color-coded by state; clicking a row deep-links to the job detail.
- **Top findings (last 24 h)**: severity-sorted cards; each card carries a **trust badge** (`full` / `degraded` / `suspect`) because presenting degraded evidence as complete is the single most dangerous UI failure in a DFIR tool.
- **Alert banner**: rendered only for real conditions (audit chain failure, tlog checkpoint invalid, mass verification failures), sourced from the same alerting rules as the ops stack so UI and pager never disagree.

### 2.2 Agents

Virtualized table (5k rows, 60 fps) with columns: host, platform, state, agent version, **variant index** (hover shows the diversification seed + code hash — this is how we *show* polymorphism to judges), last heartbeat (relative + absolute on hover), capabilities (`bpf`/`etw`/`tpm`/`mft` as small pills), and an actions menu.

Agent detail includes a **collector health panel** that renders each collector as a row with `available / degraded / unavailable` plus the machine-readable reason, e.g. `etw: unavailable — Microsoft-Windows-Kernel-Network provider disabled (0x5)`. That reason string is exactly what the agent reported; the UI never paraphrases or hides it.

### 2.3 Job composer

A 5-step wizard with server-side validation at each step:

1. **Script** — pick a module; the picker shows the build's `semantics_hash`, variant count, diversity report summary, and SBOM link. Revoked builds are filtered out with a reason.
2. **Scope** — host/network/path pickers with a live **scope summary** ("2 hosts, 1 /16 network, 2 path globs, egress limited to 10.20.0.0/16"). Out-of-scope input is rejected client-side *and* server-side; the server is the authority.
3. **Budget** — sliders with the server's max values as ceilings; shows the estimated impact ("≈ 25% of one core for ≤ 300 s, ≤ 512 MB").
4. **Schedule** — now or a time; shows the consent-token TTL implication ("tokens issued at dispatch, valid 15 min").
5. **Review** — a diff-style summary, the ticket ID, and the two-person approval requirement if scope > 1 host or any `net_egress` is present.

### 2.4 Findings workbench

- Filter chips: severity, ATT&CK technique, agent, status, confidence ≥ X, trust level, time range, free-text (Postgres `websearch_to_tsquery` over `title`+`detail`).
- Bulk actions: set status, assign, add to case. Every bulk action is one audit entry with the affected IDs.
- **Evidence inspector**: click a finding → side panel showing the raw artifact JSON with a "copy as JSON" and "open in graph" action, plus the exact bundle object key and byte range (`evidence_refs`) so an analyst can pull the raw bytes.
- **Honesty affordance**: if `trust != full`, the panel header shows a warning stripe with the degradation reasons and a link to the collector health panel for that agent at that time.

### 2.5 Graph explorer (process → network → file)

Data source: `GET /v1/graph?root=<entity_key>&depth=N&kinds=...`, which runs a recursive CTE over `edges` (bounded depth ≤ 5, bounded node count ≤ 5,000, `statement_timeout = 3s`).

- **Cytoscape.js** with the `dagre` layout for the default (directed, time-ordered) view and `fcose` for clustered exploration.
- Node styling by kind: process (rounded rect, colored by signature validity — signed/unsigned/revoked), socket (hexagon, colored by direction), file (document shape, colored by write/read), registry/service (diamond).
- Edge labels: `spawned`, `loaded`, `connected_to`, `wrote`, `listened`.
- **Time scrubber**: a bottom timeline that filters the graph to a window; implemented by passing `observed_from/observed_to` to the API rather than filtering client-side (so the DB does the work).
- **Provenance overlay**: toggling "show evidence" draws a dotted edge from each node to a small bundle chip; hovering a chip shows `agent`, `job`, `build_id`, `variant_index`, and `trust`. This makes every claim in the graph traceable to a signed artifact — the core differentiator versus a generic graph UI.
- Framer Motion is used for node enter/exit and for the panel slide-ins; graph layout itself is *not* animated frame-by-frame (that would tank performance).

### 2.6 Timeline

Lanes: processes, network, files, registry, log events. Virtualized horizontal canvas; zoom levels second/minute/hour/day. Overlapping events stack with a count badge. "Clear logs" gaps render as a **red hatched region** (evidence of T1070.001), which is exactly the kind of thing an analyst must not miss.

### 2.7 Audit

Append-only table with a live **chain integrity indicator**: the UI calls `GET /v1/audit/verify?from=&to=` which recomputes the hash chain server-side and returns `{verified: true, entries: N, head_hash: "..."}`. If verification fails, the header turns red and the alert banner appears. Export to CSV/JSONL requires `auditor` or `admin` and is itself audited.

---

## 3. Real-time layer

- `WSS /ws/events` with a **single multiplexed socket** per session. Subscribe messages: `{"sub":"findings","team":"c4-ir"}`, `{"sub":"job","id":"..."}`, `{"sub":"agents"}`.
- Server-side fan-out from Redis pub/sub; **authorization is applied per subscription** (the same Casbin policy as REST) and re-checked on token refresh.
- Backpressure: the client sends `{"ack": seq}`; if unacked > 500, the server pauses the stream and the client shows "live updates paused — resyncing", then does a REST catch-up from the last acked sequence. No silent divergence.
- Reconnect: exponential backoff with jitter, capped at 30 s, with a `since` cursor so no events are lost.
- Fallback: if WSS is blocked (a corporate proxy stripping upgrades), the client automatically degrades to 10 s polling and displays a "degraded: polling" indicator.

---

## 4. Security of the frontend

### 4.1 Headers (set at Cloudflare, asserted by a CI test against the deployed origin)

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'nonce-<per-response>';
  style-src 'self' 'nonce-<per-response>';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self' wss://api.jocky.internal https://api.jocky.internal;
  form-action 'none';
  frame-ancestors 'none';
  base-uri 'none';
  object-src 'none';
  require-trusted-types-for 'script';
  trusted-types jocky;
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), serial=(),
                    bluetooth=(), hid=(), midi=(), payment=(), publickey-credentials-get=(self)
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

Note that `connect-src` contains **only** our own origin and the API — there is no wildcard, so even if code attempted a STUN/TURN connection to a third-party host, the browser would block it.

### 4.2 WebRTC leak prevention (three independent layers)

1. **Policy layer** — `Permissions-Policy` disables the media devices; `connect-src` has no third-party origins, so `RTCPeerConnection`'s ICE/STUN traffic to `stun:*` is blocked by CSP.
2. **Application layer** — a module installed *before* any other app code removes the API surface entirely:

```ts
// src/security/no-webrtc.ts  — imported first in main.tsx, before React
const BLOCKED = ["RTCPeerConnection", "webkitRTCPeerConnection", "RTCDataChannel",
                 "mozRTCPeerConnection", "RTCRtpSender", "RTCRtpReceiver"] as const;

export function enforceNoWebRTC(): void {
  for (const name of BLOCKED) {
    if (name in window) {
      Object.defineProperty(window, name, {
        configurable: false,
        writable: false,
        value: new Proxy(function () {}, {
          construct() { throw new Error(`JOCKY: ${name} is disabled by policy (no WebRTC, no STUN leaks)`); },
          apply()     { throw new Error(`JOCKY: ${name} is disabled by policy`); },
        }),
      });
    }
  }
  // Also strip the legacy ICE candidate path and getUserMedia
  for (const name of ["getUserMedia", "webkitGetUserMedia", "mozGetUserMedia"] as const) {
    if (navigator.mediaDevices && name in navigator.mediaDevices) {
      Object.defineProperty(navigator.mediaDevices, name, {
        configurable: false, value: () => Promise.reject(new Error("JOCKY: media capture disabled")),
      });
    }
  }
}
```

3. **Verification layer** — a startup self-test (`src/security/leak-selfcheck.ts`) asserts the constructors throw, and a CI Playwright test navigates the app and asserts via CDP that no connection was attempted to any origin outside the allowlist (checked by intercepting `Network.requestWillBeSent` and failing on a non-allowlisted host). The dashboard's `/settings/security` page displays the live result of this self-test, so an analyst can *see* that the protection is active rather than trusting documentation.

### 4.3 VPN-only access

- Cloudflare Access policy: allow only `identity in group("jocky-analysts") AND ip.src in {198.51.100.0/24, 203.0.113.0/24}` (the VPN egress ranges), with device posture checks (disk encryption on, EDR present, OS patch level). Everything else → 403 with no detail.
- Origin (ALB) additionally allowlists Cloudflare's published ranges + a shared secret header (`CF-Origin-Auth`), so the origin is unreachable even if someone learns its IP.
- The app calls `GET /v1/session/posture` on load; if the response indicates the request did not arrive via the VPN path (checked server-side by inspecting the `CF-Connecting-IP` against the VPN ranges), the session is terminated with an explanatory screen. This prevents a misconfigured analyst laptop from silently working over a coffee-shop network.
- Documentation requirement for analysts (in `docs/07`): WireGuard client with `AllowedIPs = 0.0.0.0/0` (full tunnel), `PersistentKeepalive = 25`, and a kill-switch (`wg-quick` with `Table = off` + nftables rules that drop all egress except the VPN endpoint and the DNS resolver). DNS via the tunnel's resolver only, with `systemd-resolved` DNS-over-TLS pinned to the tunnel resolver. Leak tests: `https://browserleaks.com/ip`, `https://dnsleaktest.com`, and an internal `GET /v1/session/posture` that asserts the observed egress IP is in the VPN pool.

### 4.4 RBAC in the UI

- The UI **hides** actions the user cannot perform, but the server **enforces** them. The UI derives capabilities from `GET /v1/session` → `{role, permissions[]}`; a component `<Can perm="job:create">` wraps gated controls.
- A CI test (`tests/rbac-ui.spec.ts`) runs the app as each role with a mocked API and asserts that no forbidden control is rendered *and* that a forced render still produces a 403 from the real API in the integration suite. Defense in depth, verified.

### 4.5 Session management

- Session cookie: `__Host-jocky_session`, `httpOnly`, `Secure`, `SameSite=Strict`, 30 min idle / 8 h absolute.
- Idle timer with a 60 s warning modal, server-authoritative (the server expires the session; the client just reflects it).
- Logout clears client caches (TanStack Query cache + any IndexedDB), calls `DELETE /v1/auth/session`, and clears the service-worker cache.
- **No tokens in `localStorage`.** Ever. Access tokens are held in memory only; refresh is via the cookie.
- Tab-scoped logout broadcast via `BroadcastChannel` so all tabs drop state simultaneously.

### 4.6 XSS/rendering safety

- All evidence text renders as React text nodes. `dangerouslySetInnerHTML` is banned by an ESLint rule (`react/no-danger` set to `error`) and a CI grep gate.
- Any structured evidence (JSON) is rendered by a pretty-printer component that escapes by construction.
- Trusted Types policy `jocky` is the only one allowed; a `require-trusted-types-for 'script'` directive makes DOM-XSS sinks throw rather than execute.
- A unit test feeds a corpus of XSS payloads (from the OWASP cheat sheet) through every evidence renderer and asserts no script execution (jsdom + `window.__xssFired` sentinel).

---

## 5. Accessibility & usability (not decoration — analysts work under stress)

- WCAG 2.2 AA: contrast ≥ 4.5:1 for text, ≥ 3:1 for UI borders; severity is **never** conveyed by color alone (each severity also has an icon and a text label).
- Full keyboard navigation for the findings workbench and graph (arrow keys traverse edges; `Enter` opens the evidence panel); a command palette (`Ctrl+K`) with fuzzy search over actions, entities, and saved views.
- Reduced-motion: `prefers-reduced-motion` disables all Framer Motion transitions and the animated fleet bars degrade to static segments.
- Screen-reader announcements for live updates via an `aria-live="polite"` region, throttled to 1 announcement per 5 s so the tool is usable with a screen reader during a busy incident.

---

## 6. Frontend testing

| Layer | Tool | Gate |
|---|---|---|
| Unit | Vitest + Testing Library | 80% line coverage on `src/lib`, `src/security` |
| Contract | Zod schemas validated against the manager's OpenAPI/JSON-Schema in CI | Any drift fails the build |
| E2E | Playwright (Chromium + Firefox) against a docker-composed stack | Happy paths: login → create job → see results → triage finding |
| Security | Playwright + CDP: CSP violations, WebRTC attempt detection, non-allowlisted request detection, XSS corpus | Must be zero violations |
| Perf | Playwright + `PerformanceObserver` | Fleet view ≥ 60 fps at 5k rows; graph layout < 800 ms at 2k nodes |
| A11y | `@axe-core/playwright` | Zero critical/serious violations |