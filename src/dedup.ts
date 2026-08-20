/*
 * Idempotent webhook delivery handling, keyed on delivery ID.
 *
 * The receiver owns idempotency
 * -----------------------------
 * Webhook providers redeliver. A response that times out, a 5xx from a
 * restarting process, a provider-side retry policy that fires on any
 * non-2xx — all of these produce a second copy of a delivery the receiver
 * may have already fully processed. Redelivery is the transport working as
 * designed, not an anomaly, and no sender-side setting turns it off.
 *
 * That leaves the receiver as the only place the duplicate can be absorbed.
 * The tool is the provider's delivery ID: a stable identifier that is the
 * same across every attempt at the same delivery (unlike an event ID, which
 * some providers reuse across fan-out, or a timestamp, which does not repeat).
 * Record the ID once processing succeeds; refuse to process an ID already on
 * record.
 *
 * What this does not promise
 * --------------------------
 * "Exactly once" is not on offer here, and `handleOnce` documents precisely
 * where the gap is. What this gives you is a durable record of delivery IDs
 * that survives restarts, and a guard that never runs a handler for an ID
 * already recorded.
 */

import { open, readFile, rename, unlink } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';

export interface DedupStore {
  has(deliveryId: string): Promise<boolean>;
  record(deliveryId: string, nowMs?: number): Promise<void>;
  /** Removes entries older than `maxAgeMs`; resolves to the number removed. */
  prune(maxAgeMs: number, nowMs?: number): Promise<number>;
}

/** Current on-disk schema version. Bump only alongside a migration path. */
const FORMAT_VERSION = 1;

interface StoreFile {
  version: typeof FORMAT_VERSION;
  seen: Record<string, number>;
}

/**
 * A dedup store backed by a single JSON file.
 *
 * Suited to a single process with a modest delivery volume — the whole map is
 * held in memory and rewritten on every mutation. A multi-process or
 * high-throughput receiver wants a store with real atomic test-and-set
 * (Redis `SET NX`, a unique index in Postgres); the `DedupStore` interface is
 * the seam for swapping one in.
 */
export class FileDedupStore implements DedupStore {
  readonly #filePath: string;

  /** In-flight or completed load. Cleared on failure so a retry re-reads. */
  #loaded: Promise<Map<string, number>> | undefined;

  /** Serializes persistence so two writers cannot interleave temp/rename. */
  #writes: Promise<void> = Promise.resolve();

  #tmpCounter = 0;

  constructor(filePath: string) {
    this.#filePath = filePath;
  }

  async has(deliveryId: string): Promise<boolean> {
    const seen = await this.#load();
    return seen.has(deliveryId);
  }

  async record(deliveryId: string, nowMs: number = Date.now()): Promise<void> {
    const seen = await this.#load();
    // Re-recording a known ID just refreshes its timestamp. That is harmless
    // on its own — the guard against double-processing is in `handleOnce`,
    // which checks before it calls the handler.
    seen.set(deliveryId, nowMs);
    await this.#persist(seen);
  }

  async prune(maxAgeMs: number, nowMs: number = Date.now()): Promise<number> {
    const seen = await this.#load();

    let removed = 0;
    for (const [deliveryId, recordedAtMs] of seen) {
      if (nowMs - recordedAtMs > maxAgeMs) {
        seen.delete(deliveryId);
        removed += 1;
      }
    }

    // Nothing changed, so there is nothing to write. Note that pruning is a
    // deliberate trade: an ID dropped here will be processed again if the
    // provider redelivers it later, so `maxAgeMs` must comfortably exceed the
    // provider's retry window.
    if (removed > 0) {
      await this.#persist(seen);
    }

    return removed;
  }

  #load(): Promise<Map<string, number>> {
    this.#loaded ??= this.#read().catch((err: unknown) => {
      this.#loaded = undefined;
      throw err;
    });
    return this.#loaded;
  }

  async #read(): Promise<Map<string, number>> {
    let raw: string;
    try {
      raw = await readFile(this.#filePath, 'utf8');
    } catch (err) {
      // A store that has never been written is genuinely empty; that is the
      // one and only case where "no entries" is a safe reading of a failed
      // read. Every other error propagates.
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        return new Map();
      }
      throw err;
    }

    // A corrupt store must never be silently treated as empty. Doing so would
    // forget every delivery ID on record and re-open the door to processing
    // all of them a second time — a failure that looks like a clean start and
    // behaves like a replay of the entire history. Fail loudly instead and let
    // an operator decide.
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(
        `dedup store at ${this.#filePath} is corrupt and was not parsed as JSON: ` +
          `${(err as Error).message}. Refusing to continue with an empty store; ` +
          `inspect or restore the file.`,
      );
    }

    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error(
        `dedup store at ${this.#filePath} is corrupt: expected a JSON object.`,
      );
    }

    const { version, seen } = parsed as Partial<StoreFile>;

    if (version !== FORMAT_VERSION) {
      throw new Error(
        `dedup store at ${this.#filePath} is corrupt or unsupported: ` +
          `expected version ${FORMAT_VERSION}, found ${JSON.stringify(version)}.`,
      );
    }

    if (typeof seen !== 'object' || seen === null || Array.isArray(seen)) {
      throw new Error(
        `dedup store at ${this.#filePath} is corrupt: "seen" must be an object.`,
      );
    }

    const entries = new Map<string, number>();
    for (const [deliveryId, recordedAtMs] of Object.entries(seen)) {
      if (typeof recordedAtMs !== 'number' || !Number.isFinite(recordedAtMs)) {
        throw new Error(
          `dedup store at ${this.#filePath} is corrupt: entry ${JSON.stringify(deliveryId)} ` +
            `has a non-numeric timestamp.`,
        );
      }
      entries.set(deliveryId, recordedAtMs);
    }

    return entries;
  }

  #persist(seen: Map<string, number>): Promise<void> {
    const contents: StoreFile = {
      version: FORMAT_VERSION,
      seen: Object.fromEntries(seen),
    };
    const serialized = `${JSON.stringify(contents, null, 2)}\n`;

    this.#writes = this.#writes.then(
      () => this.#writeAtomically(serialized),
      () => this.#writeAtomically(serialized),
    );
    return this.#writes;
  }

  async #writeAtomically(serialized: string): Promise<void> {
    // Write to a temp file in the same directory, then rename over the target:
    // rename within a filesystem is atomic, so a crash mid-write can never leave
    // a truncated or half-written store — readers see either the old file or the
    // new one, and a truncated dedup store is a forgotten delivery ID.
    const tmpPath = join(
      dirname(this.#filePath),
      `.${basename(this.#filePath)}.${process.pid}.${this.#tmpCounter++}.tmp`,
    );

    try {
      const handle = await open(tmpPath, 'wx');
      try {
        await handle.writeFile(serialized, 'utf8');
        // Flush before the rename, so the rename cannot land ahead of the bytes
        // it is meant to publish. (The directory entry itself is left to the OS;
        // full durability across power loss would also fsync the directory.)
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(tmpPath, this.#filePath);
    } catch (err) {
      // Never leave a stray temp file behind on a failed write.
      await unlink(tmpPath).catch(() => {});
      throw err;
    }
  }
}

/**
 * Run `handler` for `deliveryId` only if that ID has not been recorded before.
 *
 * Ordering, and what it buys
 * --------------------------
 * The ID is recorded *after* the handler resolves, never before. If the handler
 * throws, nothing is written, so the delivery stays retryable: the provider's
 * next attempt — or your own requeue — finds a clean store and runs the work
 * again. Recording first would be the opposite failure, and the worse one: a
 * delivery that failed to process would be marked done forever and silently
 * dropped.
 *
 * The guarantee is therefore at-most-once *recording per successful
 * processing*, not exactly-once processing. The window is real: if the process
 * crashes between the handler resolving and `record` completing, the ID is not
 * on record and the next redelivery will process it a second time. Nothing
 * short of committing the handler's effects and the dedup record in one
 * transaction closes that window, which is why handlers should be idempotent in
 * their own right where they can be — upsert rather than insert, key outbound
 * calls by delivery ID, make the second run a no-op.
 *
 * The check-then-act between `has` and `record` is likewise not atomic. Two
 * concurrent deliveries of the same ID against a `FileDedupStore` can both see
 * an empty store and both run. Single-flight the work per delivery ID, or back
 * this with a store whose test-and-set is genuinely atomic.
 */
export async function handleOnce<T>(
  store: DedupStore,
  deliveryId: string,
  handler: () => Promise<T>,
): Promise<{ processed: true; result: T } | { processed: false }> {
  if (await store.has(deliveryId)) {
    return { processed: false };
  }

  const result = await handler();

  await store.record(deliveryId);

  return { processed: true, result };
}
