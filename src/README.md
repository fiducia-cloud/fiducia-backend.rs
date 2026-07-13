# src

The entire Rust backend. This crate is a **bin-only** crate (no `lib.rs`); all
code lives in `main.rs`.

- **`main.rs`** — builds the axum `Router` and runs it. It wires:
  - health/info probes (`/healthz`, `/api/health`, `/api/info`);
  - the customer portal, rendered server-side with Maud and refreshed with HTMX
    (`/app`, `/app/*`), plus its `/app/ws` WebSocket and `/app/events` SSE
    streams that push rendered dashboard fragments and `fiducia:sync` change
    frames;
  - PostgreSQL-backed API keys, preferences, trusted sessions, and the
    `@fiducia/sync` write path (`/api/customer/...`). `DATABASE_URL` is required;
    storage failures return 503 and never fabricate customer state or versions;
  - a static-file fallback that serves the built Astro site (`STATIC_DIR`).

`build_router()` is intentionally split from `main()` so unit tests can exercise
routes without binding a socket. Cluster-wide node observability is not exposed
as customer data: the coordination panels state that they are unavailable until
the node supplies an authenticated tenant-scoped read contract. This tier never
substitutes invented lock, request, KV, or service rows.
