# webhook-guard

[![CI](https://github.com/adamabdo-xynora/webhook-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/adamabdo-xynora/webhook-guard/actions/workflows/ci.yml)

A security-hardened webhook receiver pattern in TypeScript, extracted from production systems I run. Five defenses, each with tests. The fourth one is why this repo exists.

## Why this exists

A vendor's webhook once echoed my endpoint's own authentication secret back to me inside the payload body. My receiver archived raw payloads to disk for replay and audit — standard practice — which meant every single delivery was writing a live credential into storage. Rotating the secret couldn't fix it: the next payload echoed the new one. Adding the discovered path to a redaction list couldn't fix it either — a path list only covers echoes you've already noticed.

The only durable fix is redaction by **value**: scan every payload for the values of your known secrets — any key, any nesting depth, anywhere inside a longer string — and replace them before anything touches disk. Most public webhook examples store payloads raw. This repo is the pattern I wish I'd started from.

## The five defenses

### 1. Signature verification before anything else (`src/verify.ts`)

HMAC-SHA256 over the raw bytes, compared with `crypto.timingSafeEqual`. The body is never parsed — not even as JSON — until the signature verifies: parsing attacker-controlled input before authentication is free attack surface. The expected digest is computed before any comparison branch so failure paths do similar work, and no failure reason ever includes the secret or the expected signature.

### 2. Dedup by delivery ID (`src/dedup.ts`)

Redelivery is the system working as designed — timeouts and provider retries mean the same delivery arrives more than once in normal operation. `handleOnce` keys on the delivery ID against a small persistent store, and records only **after** the handler succeeds, so a failed attempt stays retryable. A corrupt store throws instead of silently starting empty, because a silently-reset dedup store double-processes everything. The comments are honest about the limits: this is at-most-once recording per successful processing, not "exactly once," and the `DedupStore` interface is the seam for an atomic test-and-set backend when that matters.

### 3. Date-partitioned raw payload storage (`src/storage.ts`)

Payloads archive to `baseDir/YYYY/MM/DD/<deliveryId>.json` (UTC) for replay and audit. Redeliveries never overwrite — each attempt is evidence, so a second store lands on a suffixed path claimed via exclusive create. Delivery IDs are sanitized before touching the filesystem: external input doesn't get to steer a write path. And every write goes through a filter seam — which is where the next defense lives.

### 4. Credential redaction by value, not by path (`src/redact.ts`) — the centerpiece

Before storage, a redactor scans the payload for the **values** of known secrets (collected from env) and replaces every occurrence with `[REDACTED:name]` — in values, in keys, mid-string, at any depth. It also matches each secret's JSON-escaped form, because a secret containing `"` or a backslash looks different in serialized JSON and a raw-only match silently misses it. Longer secrets replace first so overlapping credentials can't shred each other into leaked fragments. The headline test plants a secret at `data.attempts[1].request.headers.Authorization`, runs the full store pipeline, then reads back every file in the archive and proves the secret reached none of them.

### 5. Deny-by-default audit output (`src/audit.ts`, `src/audit-cli.ts`)

Ad-hoc debug printing is how secrets leak: someone logs a payload to chase a bug and a credential rides along into scrollback, log aggregators, or a pasted message. The audit CLI prints only allowlisted top-level fields; everything else is withheld and only counted. It never traverses into nesting even when a nested key matches the allowlist — an allowlist that reaches into nesting becomes a path list, and this repo has opinions about path lists. A guarantee test seeds every non-allowlisted value with a marker and proves no marker appears anywhere in the output.

## Running it

    npm install
    npm test
    npx tsx src/audit-cli.ts storage/payloads 2026-08-19
    WEBHOOK_SECRET=... npx tsx src/server.ts

`src/server.ts` is the receiver process: `node:http` in front of the five modules, with every security decision left in them. It listens on 8080, takes `POST /webhook` with `x-webhook-signature` and `x-delivery-id` headers, and refuses to start without a signing secret — there is no default, because a default is a credential shipped in a layer. The Dockerfile keeps the same rule: no secret is an `ARG`, an `ENV`, or a file in the build context, and it only ever arrives through `-e` at run time. The `test` target carries the toolchain and runs the suite offline; the default target is just node plus the compiled receiver.

    docker build --target test -t webhook-guard:test . && docker run --rm webhook-guard:test npm test
    docker build -t webhook-guard . && docker run --rm -p 8080:8080 -e WEBHOOK_SECRET=... -v webhook-data:/data webhook-guard

### Container image

The runtime image is published to GHCR on every version tag, by a workflow whose gate runs the 68
tests and the typecheck inside the test image first — the push step is unreachable unless both pass.

    docker pull ghcr.io/adamabdo-xynora/webhook-guard:0.1.1
    docker run --rm -p 8080:8080 -e WEBHOOK_SECRET=... ghcr.io/adamabdo-xynora/webhook-guard:0.1.1

It runs the compiled receiver on port 8080: `GET /healthz` answers 200, and an unsigned
`POST /webhook` answers 401 `missing signature header`. Run without `WEBHOOK_SECRET` it refuses to
start and exits 1, which is the behaviour described above rather than a failure to configure. The
image is node plus `dist/` — it has no `node_modules` at all, because the package declares no
runtime dependencies. Published for `linux/amd64` and `linux/arm64`.

The image carries signed build provenance, so you can check that these bytes came from this
repository's CI rather than from someone with push access to the registry:

    gh attestation verify oci://ghcr.io/adamabdo-xynora/webhook-guard:0.1.1 --owner adamabdo-xynora

`0.1.0` remains published, `linux/amd64` only and without an attestation. Its digest has not
changed and will not: a version that alters its bytes is not a version.

## Scope

This is a pattern, not a framework: five small modules with no runtime dependencies, meant to be read and adapted. The tests are the specification.

MIT licensed.
