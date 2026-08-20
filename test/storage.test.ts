import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { listPayloads, storePayload } from '../src/storage.js';

/** The same realistic delivery the other suites use. */
const DELIVERY_ID = 'dlv_8f3a2b';

const PAYLOAD = Buffer.from(
  JSON.stringify({
    event: 'invoice.paid',
    delivery_id: 'dlv_8f3a2b',
    data: { invoice_id: 'inv_20260819_0042', amount_cents: 124900 },
  }),
  'utf8',
);

/** 2026-08-19T12:00:00Z — mid-day UTC, so no timezone can shift the date. */
const AUG_19_NOON_UTC = Date.UTC(2026, 7, 19, 12, 0, 0);

let dir: string;
let baseDir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'webhook-guard-storage-'));
  baseDir = join(dir, 'payloads');
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

/** Every regular file under `root`, as paths relative to it, sorted. */
async function walk(root: string): Promise<string[]> {
  const found: string[] = [];

  const visit = async (current: string, prefix: string): Promise<void> => {
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw err;
    }
    for (const entry of entries) {
      const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.isDirectory()) {
        await visit(join(current, entry.name), rel);
      } else {
        found.push(rel);
      }
    }
  };

  await visit(root, '');
  return found.sort();
}

describe('storePayload', () => {
  it('stores a payload at the dated path derived from nowMs', async () => {
    const { path } = await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: PAYLOAD,
      nowMs: AUG_19_NOON_UTC,
    });

    expect(path).toBe(join(baseDir, '2026', '08', '19', 'dlv_8f3a2b.json'));
    expect(await readFile(path)).toEqual(PAYLOAD);
  });

  it('partitions by the UTC date, not the local one', async () => {
    // 2026-08-20T03:30:00Z. In America/Los_Angeles that instant is still
    // 2026-08-19 (20:30 PDT), so a receiver reading local date parts would file
    // this delivery a day early — and its Frankfurt failover would not.
    const justAfterUtcMidnight = Date.UTC(2026, 7, 20, 3, 30, 0);

    const pacificDate = new Date(justAfterUtcMidnight).toLocaleDateString('en-CA', {
      timeZone: 'America/Los_Angeles',
    });
    expect(pacificDate).toBe('2026-08-19');

    const { path } = await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: PAYLOAD,
      nowMs: justAfterUtcMidnight,
    });

    expect(path).toBe(join(baseDir, '2026', '08', '20', 'dlv_8f3a2b.json'));
    expect(await walk(baseDir)).toEqual(['2026/08/20/dlv_8f3a2b.json']);
  });

  it('zero-pads single-digit months and days', async () => {
    const { path } = await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: PAYLOAD,
      nowMs: Date.UTC(2026, 0, 5, 12, 0, 0),
    });

    expect(path).toBe(join(baseDir, '2026', '01', '05', 'dlv_8f3a2b.json'));
  });

  it('applies the filter before writing: the unfiltered bytes never reach disk', async () => {
    const rawBody = Buffer.from(
      JSON.stringify({
        event: 'invoice.paid',
        delivery_id: 'dlv_8f3a2b',
        data: {
          invoice_id: 'inv_20260819_0042',
          amount_cents: 124900,
          customer_api_key: 'fixture_customer_key_0000000000000000',
        },
      }),
      'utf8',
    );

    const redacted = Buffer.from(
      JSON.stringify({
        event: 'invoice.paid',
        delivery_id: 'dlv_8f3a2b',
        data: {
          invoice_id: 'inv_20260819_0042',
          amount_cents: 124900,
          customer_api_key: '[REDACTED]',
        },
      }),
      'utf8',
    );

    const seenByFilter: Buffer[] = [];

    const { path } = await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody,
      nowMs: AUG_19_NOON_UTC,
      filter: (payload) => {
        seenByFilter.push(payload);
        return redacted;
      },
    });

    // The filter saw the raw bytes...
    expect(seenByFilter).toEqual([rawBody]);

    // ...and only its output was written.
    const onDisk = await readFile(path);
    expect(onDisk).toEqual(redacted);
    expect(onDisk.includes('fixture_customer_key_0000000000000000')).toBe(false);

    // Nothing anywhere under baseDir carries the secret — not the payload, not
    // a stranded temp file from the write.
    for (const rel of await walk(baseDir)) {
      const contents = await readFile(join(baseDir, rel));
      expect(contents.includes('fixture_customer_key_0000000000000000')).toBe(false);
      expect(contents.equals(rawBody)).toBe(false);
    }
  });

  it('defaults to an identity filter, storing the bytes exactly as received', async () => {
    // Not valid JSON and not valid UTF-8: the archive stores bytes, so whatever
    // the sender put on the wire is what comes back out.
    const rawBody = Buffer.from([0x7b, 0x22, 0xff, 0xfe, 0x00, 0x22, 0x7d]);

    const { path } = await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody,
      nowMs: AUG_19_NOON_UTC,
    });

    expect(await readFile(path)).toEqual(rawBody);
  });

  it('never overwrites: a redelivery on the same day lands on a suffixed path', async () => {
    const first = Buffer.from(JSON.stringify({ event: 'invoice.paid', attempt: 1 }), 'utf8');
    const second = Buffer.from(JSON.stringify({ event: 'invoice.paid', attempt: 2 }), 'utf8');
    const third = Buffer.from(JSON.stringify({ event: 'invoice.paid', attempt: 3 }), 'utf8');

    const a = await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: first,
      nowMs: AUG_19_NOON_UTC,
    });
    const b = await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: second,
      nowMs: AUG_19_NOON_UTC,
    });
    const c = await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: third,
      nowMs: AUG_19_NOON_UTC,
    });

    const day = join(baseDir, '2026', '08', '19');
    expect(a.path).toBe(join(day, 'dlv_8f3a2b.json'));
    expect(b.path).toBe(join(day, 'dlv_8f3a2b.1.json'));
    expect(c.path).toBe(join(day, 'dlv_8f3a2b.2.json'));

    // Every attempt survives with its own bytes — that is the audit trail.
    expect(await readFile(a.path)).toEqual(first);
    expect(await readFile(b.path)).toEqual(second);
    expect(await readFile(c.path)).toEqual(third);
  });

  it.each([
    '../escape',
    '../../etc/passwd',
    '..',
    '.',
    'nested/id',
    'back\\slash',
    'has space',
    'null\0byte',
    '',
  ])('refuses delivery ID %j and writes nothing', async (deliveryId) => {
    await expect(
      storePayload({ baseDir, deliveryId, rawBody: PAYLOAD, nowMs: AUG_19_NOON_UTC }),
    ).rejects.toThrow(/delivery ID/i);

    // Not even the date directories were created: a rejected ID leaves no trace
    // under baseDir, and nothing was written outside it either.
    expect(await walk(baseDir)).toEqual([]);
    expect(await walk(dir)).toEqual([]);
  });

  it('leaves no temp files behind after a store', async () => {
    await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: PAYLOAD,
      nowMs: AUG_19_NOON_UTC,
    });
    await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: PAYLOAD,
      nowMs: AUG_19_NOON_UTC,
    });

    const entries = await readdir(join(baseDir, '2026', '08', '19'));

    expect(entries.filter((name) => name.endsWith('.tmp'))).toEqual([]);
    expect(entries.sort()).toEqual(['dlv_8f3a2b.1.json', 'dlv_8f3a2b.json']);
  });
});

describe('listPayloads', () => {
  it('returns the sorted payloads stored on the requested UTC day', async () => {
    await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: PAYLOAD,
      nowMs: AUG_19_NOON_UTC,
    });
    await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: PAYLOAD,
      nowMs: AUG_19_NOON_UTC,
    });
    await storePayload({
      baseDir,
      deliveryId: 'dlv_1b9d40',
      rawBody: PAYLOAD,
      nowMs: AUG_19_NOON_UTC,
    });
    // A different day, which must not show up in the 19th's listing.
    await storePayload({
      baseDir,
      deliveryId: 'dlv_c41e07',
      rawBody: PAYLOAD,
      nowMs: Date.UTC(2026, 7, 20, 12, 0, 0),
    });

    const day = join(baseDir, '2026', '08', '19');

    expect(await listPayloads(baseDir, { year: 2026, month: 8, day: 19 })).toEqual([
      join(day, 'dlv_1b9d40.json'),
      join(day, 'dlv_8f3a2b.1.json'),
      join(day, 'dlv_8f3a2b.json'),
    ]);

    expect(await listPayloads(baseDir, { year: 2026, month: 8, day: 20 })).toEqual([
      join(baseDir, '2026', '08', '20', 'dlv_c41e07.json'),
    ]);
  });

  it('returns [] for a day with no directory', async () => {
    await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: PAYLOAD,
      nowMs: AUG_19_NOON_UTC,
    });

    expect(await listPayloads(baseDir, { year: 2026, month: 8, day: 18 })).toEqual([]);
    // And an archive that has never been written to at all is not an error.
    expect(await listPayloads(join(dir, 'no-such-archive'), { year: 2026, month: 8, day: 19 }))
      .toEqual([]);
  });

  it('accepts single-digit month and day numbers', async () => {
    const { path } = await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: PAYLOAD,
      nowMs: Date.UTC(2026, 0, 5, 12, 0, 0),
    });

    expect(await listPayloads(baseDir, { year: 2026, month: 1, day: 5 })).toEqual([path]);
  });
});
