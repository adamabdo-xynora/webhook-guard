# syntax=docker/dockerfile:1
#
# webhook-guard — receiver image.
#
# Two things this file is for, and how to check each:
#
#   The suite, offline, inside the image (all 68 tests, no secrets needed):
#     docker build --target test -t webhook-guard:test .
#     docker run --rm webhook-guard:test npm test
#     docker run --rm webhook-guard:test npx tsc --noEmit
#
#   The receiver, as a lean runtime image (the default target):
#     docker build -t webhook-guard .
#     docker run --rm -p 8080:8080 -e WEBHOOK_SECRET=... -v webhook-data:/data webhook-guard
#
# The base is node:22-slim rather than node:22 — the CI workflow pins Node 22,
# and the suite was run on the slim variant to confirm nothing in it needs the
# full image's toolchain.
#
# Secrets, and why none of them are in here
# -----------------------------------------
# This repository exists because a credential ended up somewhere it should not
# have. An image layer is exactly such a place: an ARG or ENV holding a secret
# survives in the image history, a COPYed .env is readable by anyone who can
# pull the image, and a "default" secret baked into a Dockerfile is a secret
# published on every registry the image reaches. So there is no ARG, no ENV,
# and no COPY that carries one. The signing secret enters only at run time —
# `-e WEBHOOK_SECRET=...` or a file mounted and named by WEBHOOK_SECRET_FILE —
# and src/server.ts refuses to start without it rather than defaulting to
# anything. .dockerignore closes the other route: what cannot enter the build
# context cannot be copied into a layer, even by a later careless COPY.

# ---------------------------------------------------------------------------
# deps: everything the lockfile pins, cached on the lockfile alone.
#
# Only the manifests are copied, so this layer is rebuilt when a dependency
# changes and reused when only source does. Every dependency in package.json
# is a devDependency — TypeScript, vitest, tsx, @types/node — which is to say
# this stage is a toolchain, not a runtime.
# ---------------------------------------------------------------------------
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# ---------------------------------------------------------------------------
# test: the toolchain plus the full source and test trees.
#
# `npx tsc --noEmit` runs at build time, in the same order as ci.yml, so a type
# error fails `docker build --target test` the way it fails CI. The suite is
# left to `docker run` so its output is the thing a reader sees, not a layer
# log. Nothing here reaches the network: vitest runs against tmpdir and the
# only secrets are the fixture strings in test/.
# ---------------------------------------------------------------------------
FROM deps AS test
COPY tsconfig.json ./
COPY src ./src
COPY test ./test
RUN npx tsc --noEmit
CMD ["npm", "test"]

# ---------------------------------------------------------------------------
# build: compile to JavaScript.
#
# Required, not optional: the sources import each other as `./verify.js` the
# way `nodenext` wants for compiled output, so Node cannot run the .ts files
# directly — `node --experimental-strip-types src/server.ts` on node:22-slim
# fails with ERR_MODULE_NOT_FOUND for `./dedup.js`. tsx rewrites the
# specifiers, but tsx is a devDependency and the runtime stage has none. tsc
# produces the files that make the imports true.
# ---------------------------------------------------------------------------
FROM deps AS build
COPY tsconfig.json ./
COPY src ./src
RUN npx tsc

# ---------------------------------------------------------------------------
# runtime: node, the compiled receiver, and nothing else.
#
# There is no `npm ci --omit=dev` here because there is nothing for it to
# install: package.json declares no runtime dependencies, so the step would
# create an empty node_modules and a layer that documents nothing. The five
# modules import only node:crypto, node:fs, node:http and node:path — that is
# the "dependency-free by design" the module comments talk about, and it is
# what lets the runtime image be the base image plus dist/.
#
# package.json is copied for one field: "type": "module". Without it Node reads
# dist/*.js as CommonJS and the ESM imports fail at startup.
#
# Test tooling — vitest, tsx, tsc, the test/ tree — is deliberately absent.
# The container's job is to hold a live signing secret and verify signatures
# with it; every extra executable in the image is something an attacker who
# gets a shell can run, and a TypeScript toolchain is a lot of executable.
# What is not in the image cannot be used from inside it.
#
# Running it:
#   docker run --rm -p 8080:8080 -e WEBHOOK_SECRET=... -v webhook-data:/data webhook-guard
#
#   -p 8080:8080   the receiver listens on 8080 (override with -e PORT=...)
#   -e WEBHOOK_SECRET=...  the shared HMAC secret; or mount a file and pass
#                  -e WEBHOOK_SECRET_FILE=/run/secrets/webhook_secret
#   -v ...:/data   the archive and dedup store. Without a volume they live in
#                  the container's writable layer and vanish with it — fine for
#                  a smoke test, not for anything you want to audit later.
#
#   POST /webhook with headers x-webhook-signature (sha256=<hex>),
#   x-delivery-id, and optionally x-webhook-timestamp. GET /healthz answers 200.
# ---------------------------------------------------------------------------
FROM node:22-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app

COPY --from=build /app/dist ./dist
COPY package.json ./

# The archive root, owned by the unprivileged `node` user the base image ships.
# The process writes payloads and the dedup store here and nowhere else.
RUN mkdir -p /data && chown node:node /data
USER node

EXPOSE 8080

# Plain node, not `npm start`: npm would sit between the container runtime and
# the process, forwarding (or not forwarding) signals, adding a process the
# image does not otherwise need. server.ts handles SIGTERM itself.
CMD ["node", "dist/server.js"]
