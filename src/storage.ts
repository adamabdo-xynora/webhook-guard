/*
 * Date-partitioned storage of incoming webhook payloads, for replay and audit.
 *
 * Why keep the bytes at all
 * -------------------------
 * A verified delivery is evidence. When a downstream handler turns out to have
 * mis-parsed an amount, when a provider disputes what it sent, or when a bug is
 * only reproducible against the exact body that triggered it, the archived bytes
 * are the only ground truth left — the parsed object has already been through
 * whatever coercion the bug lives in. So this module writes the payload as it
 * arrived, partitioned by UTC day so that retention, export, and "what did we
 * receive on the 19th" all reduce to a directory listing.
 *
 * The filter seam
 * ---------------
 * Archiving raw bodies conflicts with not archiving secrets: webhook payloads
 * carry tokens, card fragments, addresses, and anything else the provider felt
 * like including. `StoreOptions.filter` is the single seam where a redaction
 * pass sits, and it sits *in front of* disk by construction — see `storePayload`.
 *
 * Everything here is deliberately dependency-free (node:fs/promises, node:path)
 * so the audit path has nothing between it and the filesystem.
 */

import { mkdir, open, readdir, rename, unlink } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';

/**
 * Transforms payload bytes on their way to disk.
 *
 * Buffer in, Buffer out — the archive stores bytes, not objects, so a filter
 * that needs structure is responsible for parsing and re-serializing, and for
 * the fact that doing so no longer reproduces the sender's exact bytes.
 */
export type PayloadFilter = (payload: Buffer) => Buffer;

export interface StoreOptions {
  /** Root of the archive, e.g. "storage/payloads". */
  baseDir: string;
  /** Provider delivery ID; becomes the filename. Untrusted input. */
  deliveryId: string;
  /** The raw, unparsed request body bytes. */
  rawBody: Buffer;
  /** Applied to `rawBody` before anything is written. Defaults to identity. */
  filter?: PayloadFilter;
  /** Injected clock in unix milliseconds, used instead of `Date.now()`. */
  nowMs?: number;
}

/** Identity filter: the default, and the only thing that stores raw bytes. */
const IDENTITY: PayloadFilter = (payload) => payload;

/**
 * Characters permitted in a delivery ID once it is used as a filename.
 * Note what is absent: "/", "\", NUL, and everything else a path can be steered
 * with. Dots are allowed — provider IDs contain them — which is why "." and ".."
 * are rejected separately below.
 */
const SAFE_DELIVERY_ID = /^[A-Za-z0-9._-]+$/;

/**
 * Upper bound on collision suffixes before giving up. A delivery redelivered
 * ten thousand times on one day is a runaway, not an archive problem; failing
 * loudly beats spinning through `open` calls forever.
 */
const MAX_ATTEMPT_SUFFIX = 10_000;

/** Distinguishes concurrent temp files within one process. */
let tmpCounter = 0;

/**
 * Store one delivery's payload under `<baseDir>/YYYY/MM/DD/<deliveryId>.json`.
 *
 * Resolves with the path actually written, which is not always the path you
 * would predict from the delivery ID — see the collision handling below.
 */
export async function storePayload(opts: StoreOptions): Promise<{ path: string }> {
  const { baseDir, deliveryId, rawBody } = opts;
  const nowMs = opts.nowMs ?? Date.now();

  // Validate before creating a single directory. A rejected delivery ID must
  // leave no trace under `baseDir` at all — otherwise a probe for "../../etc"
  // still gets to tell you, via the directories it created, what it reached.
  assertSafeDeliveryId(deliveryId);

  // ---------------------------------------------------------------------
  // Filter first. This ordering is the entire point of the module's shape.
  //
  // This seam exists so a redaction pass can be inserted in front of disk, and
  // the API shape makes "write the unfiltered payload" impossible to do
  // accidentally — you'd have to bypass this module. `rawBody` is read exactly
  // once, here; from this line on only `filtered` is in scope for any write,
  // and no fs call below ever names `rawBody`. A caller who wants secrets
  // stripped supplies a filter and is then guaranteed, without auditing the
  // write path, that the unredacted bytes never reached the disk.
  // ---------------------------------------------------------------------
  const filter = opts.filter ?? IDENTITY;
  const filtered = filter(rawBody);

  const dir = join(baseDir, ...utcDateParts(nowMs));
  await mkdir(dir, { recursive: true });

  // -------------------------------------------------------------------------
  // Never overwrite an existing payload.
  //
  // Redeliveries are normal (see the dedup module: a provider retries whenever
  // its 2xx does not get back to it) and each attempt's payload is audit
  // evidence in its own right — attempts can differ in body, and the difference
  // is often exactly what an investigation is looking for. Overwriting destroys
  // the history you built this to keep, so a taken name falls through to
  // `<deliveryId>.<n>.json` with the next free integer n starting at 1.
  //
  // The name is claimed with an exclusive create ("wx"), not with an
  // existence check followed by a write: only the create is atomic, so two
  // concurrent stores of the same ID land on different suffixes instead of
  // both deciding ".1" is free and one of them clobbering the other.
  // -------------------------------------------------------------------------
  const path = await claimFreePath(dir, deliveryId);

  await writeAtomically(path, filtered);

  return { path };
}

/**
 * Full paths of the payloads stored on one UTC day, sorted.
 *
 * An absent directory means nothing was received that day, which is a fact
 * about the archive rather than an error — callers get `[]`.
 */
export async function listPayloads(
  baseDir: string,
  dateUtc: { year: number; month: number; day: number },
): Promise<string[]> {
  const dir = join(
    baseDir,
    String(dateUtc.year).padStart(4, '0'),
    String(dateUtc.month).padStart(2, '0'),
    String(dateUtc.day).padStart(2, '0'),
  );

  let names: string[];
  try {
    names = await readdir(dir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return [];
    }
    throw err;
  }

  // Skip anything that is not a published payload. In practice that means the
  // dot-prefixed temp files an interrupted write can strand: reporting one as
  // an archived delivery would be reporting a half-written file as evidence.
  return names
    .filter((name) => !name.startsWith('.') && name.endsWith('.json'))
    .sort()
    .map((name) => join(dir, name));
}

/**
 * Reject any delivery ID that could steer the write path.
 *
 * A delivery ID is external input: it arrives in a header or in the body of a
 * request anyone can send. Interpolating it into a path unchecked is a path
 * traversal — "../../../etc/cron.d/x" would put attacker bytes wherever the
 * process can write, and a plain "/" would silently scatter the archive across
 * directories that no `listPayloads` call will ever look in. The allowlist is
 * the check, not a blocklist of known-bad sequences: an allowlist cannot be
 * outflanked by an encoding you did not think of.
 */
function assertSafeDeliveryId(deliveryId: string): void {
  if (!SAFE_DELIVERY_ID.test(deliveryId)) {
    throw new Error(
      `refusing to store delivery ${JSON.stringify(deliveryId)}: a delivery ID used ` +
        `as a filename must contain only [A-Za-z0-9._-].`,
    );
  }

  // "." and ".." pass the character allowlist and are still not filenames —
  // they name directories, and ".." names the parent. Excluded explicitly.
  if (deliveryId === '.' || deliveryId === '..') {
    throw new Error(
      `refusing to store delivery ${JSON.stringify(deliveryId)}: a delivery ID must ` +
        `not be a path segment reference.`,
    );
  }
}

/** UTC year/month/day as zero-padded path segments. */
function utcDateParts(nowMs: number): [string, string, string] {
  const at = new Date(nowMs);

  // getUTC*, never the local-time getters. The partition is a property of the
  // delivery, not of the machine that happened to receive it: a receiver in
  // Los Angeles and its failover in Frankfurt must file the same delivery under
  // the same day, and an operator asking for "the 19th" must get one answer.
  return [
    String(at.getUTCFullYear()).padStart(4, '0'),
    String(at.getUTCMonth() + 1).padStart(2, '0'),
    String(at.getUTCDate()).padStart(2, '0'),
  ];
}

/**
 * Exclusively create the first free filename for `deliveryId` in `dir` and
 * return its path. The created file is empty; `writeAtomically` renames the
 * finished payload over it.
 */
async function claimFreePath(dir: string, deliveryId: string): Promise<string> {
  for (let n = 0; n <= MAX_ATTEMPT_SUFFIX; n += 1) {
    const path = join(dir, n === 0 ? `${deliveryId}.json` : `${deliveryId}.${n}.json`);

    let handle;
    try {
      handle = await open(path, 'wx');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
        continue;
      }
      throw err;
    }
    await handle.close();
    return path;
  }

  throw new Error(
    `refusing to store delivery ${JSON.stringify(deliveryId)}: more than ` +
      `${MAX_ATTEMPT_SUFFIX} attempts already archived for this UTC day.`,
  );
}

/** Write `contents` to `path` via a temp file in the same directory, then rename. */
async function writeAtomically(path: string, contents: Buffer): Promise<void> {
  // Same pattern as FileDedupStore: rename within a filesystem is atomic, so a
  // crash mid-write can never publish a truncated payload. A half-written
  // archive entry is worse than a missing one — it reads as evidence.
  const tmpPath = join(dirname(path), `.${basename(path)}.${process.pid}.${tmpCounter++}.tmp`);

  try {
    const handle = await open(tmpPath, 'wx');
    try {
      await handle.writeFile(contents);
      // Flush before the rename, so the rename cannot land ahead of the bytes
      // it is meant to publish. (The directory entry itself is left to the OS;
      // full durability across power loss would also fsync the directory.)
      await handle.sync();
    } finally {
      await handle.close();
    }
    // Renames over the empty file claimed by `claimFreePath` — the claim
    // reserved the name, this publishes the contents.
    await rename(tmpPath, path);
  } catch (err) {
    // Never leave a stray temp file behind on a failed write.
    await unlink(tmpPath).catch(() => {});
    throw err;
  }
}
