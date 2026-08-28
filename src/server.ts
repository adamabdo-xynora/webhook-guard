/*
 * The receiver process: HTTP in front of the five modules.
 *
 * Same split as audit-cli.ts, for the same reason. Every security decision —
 * is this signature genuine, has this delivery been seen, may this ID become a
 * filename, which bytes may reach disk — is a pure function or a small class in
 * verify.ts, dedup.ts, storage.ts and redact.ts, and each is tested by calling
 * it. What is left here is transport: read the bytes off the socket, hand them
 * to those modules in the documented order, and turn the answer into a status
 * code. Nothing in this file inspects a payload, and nothing in it parses one.
 *
 * Order of operations, and why it is this order
 * ---------------------------------------------
 *   1. buffer the raw body            (bytes only — never JSON.parse'd, here or later)
 *   2. verifySignature                (reject before anything trusts the request)
 *   3. read the delivery ID header    (after 2: an unauthenticated caller steers nothing)
 *   4. handleOnce -> storePayload     (dedup guards the store; the filter redacts before disk)
 *
 * Configuration comes from the environment. The signing secret is the only
 * value the process refuses to start without, and there is deliberately no
 * default for it: a receiver that falls back to a built-in secret is a receiver
 * that accepts forged deliveries and looks healthy while doing it.
 *
 *   WEBHOOK_SECRET        the shared HMAC secret, or
 *   WEBHOOK_SECRET_FILE   a path to a file holding it (a mounted secret) — one of the two, not both
 *   PORT                  TCP port to listen on            (default 8080)
 *   STORAGE_DIR           archive root; payloads go under <dir>/payloads,
 *                         the dedup store is <dir>/deliveries.json   (default /data)
 *
 * The variable is named WEBHOOK_SECRET on purpose: `secretsFromEnv` selects
 * credential-shaped names, so the signing secret is automatically among the
 * values redacted from every archived payload. That is the echo the README
 * opens with, closed by construction rather than by remembering to configure it.
 *
 * Usage:
 *   WEBHOOK_SECRET=... npx tsx src/server.ts
 *   npm run build && WEBHOOK_SECRET=... node dist/server.js
 */

import { mkdir, readFile } from 'node:fs/promises';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { join } from 'node:path';

import { FileDedupStore, handleOnce } from './dedup.js';
import { redactBuffer, secretsFromEnv, type Secret } from './redact.js';
import { storePayload } from './storage.js';
import { verifySignature } from './verify.js';

const DEFAULT_PORT = 8080;
const DEFAULT_STORAGE_DIR = '/data';

/** Route that accepts deliveries. Everything else is 404. */
const WEBHOOK_PATH = '/webhook';

/** Liveness probe: answers 200 with no authentication and touches no state. */
const HEALTH_PATH = '/healthz';

const SIGNATURE_HEADER = 'x-webhook-signature';
const TIMESTAMP_HEADER = 'x-webhook-timestamp';
const DELIVERY_ID_HEADER = 'x-delivery-id';

/**
 * Largest body accepted, in bytes.
 *
 * The body is buffered whole before verification (the HMAC needs all of it),
 * so without a cap an unauthenticated caller could hold as much memory as it
 * likes. Webhook payloads are small; a megabyte is generous.
 */
const MAX_BODY_BYTES = 1024 * 1024;

/** How long a shutdown waits for in-flight requests before exiting anyway. */
const SHUTDOWN_GRACE_MS = 5_000;

async function main(): Promise<void> {
  const signingSecret = await loadSigningSecret(process.env);
  const secrets = collectSecrets(process.env, signingSecret);
  const port = parsePort(process.env['PORT']);
  const storageDir = process.env['STORAGE_DIR'] ?? DEFAULT_STORAGE_DIR;

  // The dedup store writes into this directory directly, so it has to exist
  // before the first delivery; storePayload creates its own dated subtree.
  await mkdir(storageDir, { recursive: true });

  const receiver = new Receiver({
    signingSecret,
    filter: makeLoggingRedactionFilter(secrets),
    payloadsDir: join(storageDir, 'payloads'),
    dedup: new FileDedupStore(join(storageDir, 'deliveries.json')),
  });

  const server = createServer((req, res) => {
    receiver.handle(req, res).catch((err: unknown) => {
      // Whatever went wrong, the message is a module's own wording — a path, a
      // delivery ID, a store diagnosis — never payload bytes. See the module
      // comments for why each one is safe to print.
      log(`error: ${(err as Error).message}`);
      if (!res.headersSent) {
        reply(res, 500, 'internal error\n');
      } else {
        res.destroy();
      }
    });
  });

  server.listen(port, () => {
    log(`listening on port ${port}, archiving under ${storageDir}, ${secrets.length} secret(s) redacted`);
  });

  // As PID 1 in a container the process gets no default signal handling from
  // the kernel, so without these `docker stop` would wait out its timeout and
  // then SIGKILL — losing whatever write was in flight. Close the listener,
  // let in-flight requests finish, then exit.
  for (const signal of ['SIGTERM', 'SIGINT'] as const) {
    process.once(signal, () => shutdown(server, signal));
  }
}

interface ReceiverOptions {
  signingSecret: string;
  filter: (payload: Buffer) => Buffer;
  payloadsDir: string;
  dedup: FileDedupStore;
}

/** The request pipeline. One instance per process; holds no per-request state. */
class Receiver {
  readonly #opts: ReceiverOptions;

  constructor(opts: ReceiverOptions) {
    this.#opts = opts;
  }

  async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.url === HEALTH_PATH && req.method === 'GET') {
      reply(res, 200, 'ok\n');
      return;
    }

    if (req.url !== WEBHOOK_PATH) {
      reply(res, 404, 'not found\n');
      return;
    }

    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      reply(res, 405, 'method not allowed\n');
      return;
    }

    const rawBody = await readBody(req);
    if (rawBody === null) {
      reply(res, 413, 'payload too large\n');
      return;
    }

    // Verification first. `rawBody` is exactly the bytes off the wire — not
    // decoded, not trimmed, not re-serialized — which is what the HMAC covers.
    const timestampHeader = headerValue(req, TIMESTAMP_HEADER);
    const verdict = verifySignature({
      secret: this.#opts.signingSecret,
      signatureHeader: headerValue(req, SIGNATURE_HEADER) ?? '',
      rawBody,
      ...(timestampHeader !== undefined ? { timestampHeader } : {}),
    });

    if (!verdict.valid) {
      // The reason is one of verify.ts's coarse strings, designed to be safe
      // to hand back: it names the kind of failure, never the expected value.
      log(`rejected: ${verdict.reason}`);
      reply(res, 401, `${verdict.reason}\n`);
      return;
    }

    // Only now is anything else about the request looked at.
    const deliveryId = headerValue(req, DELIVERY_ID_HEADER);
    if (deliveryId === undefined || deliveryId.length === 0) {
      reply(res, 400, `missing ${DELIVERY_ID_HEADER} header\n`);
      return;
    }

    // storePayload validates the ID before touching the filesystem and runs
    // the redaction filter before any write; handleOnce records the ID only
    // after the store succeeds, so a failed write stays retryable.
    const outcome = await handleOnce(this.#opts.dedup, deliveryId, () =>
      storePayload({
        baseDir: this.#opts.payloadsDir,
        deliveryId,
        rawBody,
        filter: this.#opts.filter,
      }),
    );

    // A 200 for a duplicate as well: the provider is retrying because it never
    // saw our earlier success, and a non-2xx would only make it retry again.
    log(`${outcome.processed ? 'stored' : 'duplicate'} ${JSON.stringify(deliveryId)}`);
    reply(res, 200, `${JSON.stringify({ processed: outcome.processed })}\n`, 'application/json');
  }
}

/**
 * Resolve the signing secret from the environment, or refuse to start.
 *
 * Fails on: neither variable set, both set (ambiguous — which one wins should
 * never be a question), or a file that is empty after trimming the trailing
 * newline editors and secret mounts tend to add.
 */
async function loadSigningSecret(env: Record<string, string | undefined>): Promise<string> {
  const inline = env['WEBHOOK_SECRET'];
  const filePath = env['WEBHOOK_SECRET_FILE'];

  if (inline !== undefined && filePath !== undefined) {
    fail('set WEBHOOK_SECRET or WEBHOOK_SECRET_FILE, not both');
  }

  if (inline !== undefined) {
    if (inline.length === 0) fail('WEBHOOK_SECRET is set but empty');
    return inline;
  }

  if (filePath !== undefined) {
    let contents: string;
    try {
      contents = await readFile(filePath, 'utf8');
    } catch (err) {
      fail(`cannot read WEBHOOK_SECRET_FILE ${JSON.stringify(filePath)}: ${(err as Error).message}`);
    }
    const value = contents.replace(/\r?\n$/, '');
    if (value.length === 0) fail(`WEBHOOK_SECRET_FILE ${JSON.stringify(filePath)} is empty`);
    return value;
  }

  fail('no signing secret: set WEBHOOK_SECRET or WEBHOOK_SECRET_FILE');
}

/**
 * The redaction set: every credential-shaped variable in the environment, plus
 * the signing secret itself when it arrived via a file and so is not in the
 * environment to be picked up. The secret this process verifies with is the
 * one a provider is most likely to echo, so it is never left out.
 */
function collectSecrets(env: Record<string, string | undefined>, signingSecret: string): Secret[] {
  const secrets = secretsFromEnv(env);
  if (!secrets.some((secret) => secret.value === signingSecret)) {
    secrets.push({ name: 'WEBHOOK_SECRET', value: signingSecret });
  }
  return secrets;
}

/**
 * The storage filter, with a log line per redaction.
 *
 * `redactBuffer` rather than `makeRedactionFilter`, because the filter
 * signature has no channel for hit counts and an operator should be able to
 * see THAT a delivery echoed a credential. Names and counts only — the values
 * never leave redact.ts, and this function has no way to print them.
 */
function makeLoggingRedactionFilter(secrets: Secret[]): (payload: Buffer) => Buffer {
  const snapshot = secrets.map((secret) => ({ name: secret.name, value: secret.value }));

  return (payload: Buffer): Buffer => {
    const { output, hits } = redactBuffer(payload, snapshot);
    for (const hit of hits) {
      log(`redacted ${hit.name} (${hit.count} occurrence${hit.count === 1 ? '' : 's'})`);
    }
    return output;
  };
}

/**
 * Buffer the whole request body, or `null` if it exceeds `MAX_BODY_BYTES`.
 *
 * Checks the declared Content-Length first so an honest oversized request is
 * refused before a byte is read, and counts the bytes as they arrive so a
 * dishonest one is cut off at the cap.
 */
function readBody(req: IncomingMessage): Promise<Buffer | null> {
  const declared = Number(req.headers['content-length'] ?? '0');
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    req.resume();
    return Promise.resolve(null);
  }

  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let received = 0;

    req.on('data', (chunk: Buffer) => {
      received += chunk.length;
      if (received > MAX_BODY_BYTES) {
        req.removeAllListeners('data');
        req.resume();
        resolve(null);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * A single header value, or `undefined` if absent or repeated.
 *
 * Node folds a repeated header into an array; two signature headers is not a
 * request this receiver wants to guess about, so it reads as missing.
 */
function headerValue(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  return typeof value === 'string' ? value : undefined;
}

function reply(res: ServerResponse, status: number, body: string, contentType = 'text/plain'): void {
  res.writeHead(status, {
    'Content-Type': `${contentType}; charset=utf-8`,
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function parsePort(text: string | undefined): number {
  if (text === undefined) return DEFAULT_PORT;
  const port = Number(text);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    fail(`PORT must be an integer between 0 and 65535, got ${JSON.stringify(text)}`);
  }
  return port;
}

function shutdown(server: Server, signal: string): void {
  log(`${signal} received, shutting down`);
  server.close(() => process.exit(0));
  // Do not let one slow client keep a stopping container alive forever.
  setTimeout(() => process.exit(0), SHUTDOWN_GRACE_MS).unref();
}

/** One line to stderr. Payload bytes never pass through here — see `handle`. */
function log(message: string): void {
  process.stderr.write(`${new Date().toISOString()} ${message}\n`);
}

/** Print the reason and exit non-zero; `never`, so callers can use it as a terminator. */
function fail(reason: string): never {
  process.stderr.write(`server: ${reason}\n`);
  process.exit(1);
}

// Entry point. Top-level await: the wrapper's whole body is this one call.
await main();
