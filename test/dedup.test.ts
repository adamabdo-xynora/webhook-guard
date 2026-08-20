import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { FileDedupStore, handleOnce } from '../src/dedup.js';

/** A realistic provider delivery ID: stable across every attempt at one delivery. */
const DELIVERY_ID = 'dlv_8f3a2b';

let dir: string;
let storePath: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'webhook-guard-dedup-'));
  storePath = join(dir, 'deliveries.json');
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('handleOnce', () => {
  it('a redelivered payload is processed exactly once', async () => {
    const store = new FileDedupStore(storePath);

    let processedCount = 0;
    const handler = async (): Promise<string> => {
      processedCount += 1;
      return 'invoice.paid handled';
    };

    // First attempt: the provider's original delivery.
    const first = await handleOnce(store, DELIVERY_ID, handler);
    // Second attempt: the provider retried because our 200 never got back to it.
    const second = await handleOnce(store, DELIVERY_ID, handler);

    expect(processedCount).toBe(1);
    expect(first).toEqual({ processed: true, result: 'invoice.paid handled' });
    expect(second).toEqual({ processed: false });
  });

  it('does not record a delivery whose handler threw, leaving it retryable', async () => {
    const store = new FileDedupStore(storePath);

    let attempts = 0;
    let processedCount = 0;
    const flakyHandler = async (): Promise<string> => {
      attempts += 1;
      if (attempts === 1) {
        throw new Error('downstream ledger unavailable');
      }
      processedCount += 1;
      return 'ok';
    };

    await expect(handleOnce(store, 'dlv_c41e07', flakyHandler)).rejects.toThrow(
      'downstream ledger unavailable',
    );
    expect(processedCount).toBe(0);
    expect(await store.has('dlv_c41e07')).toBe(false);

    // The provider retries. A failed attempt must not have burned the ID.
    const retry = await handleOnce(store, 'dlv_c41e07', flakyHandler);

    expect(retry).toEqual({ processed: true, result: 'ok' });
    expect(processedCount).toBe(1);
    expect(await store.has('dlv_c41e07')).toBe(true);
  });

  it('processes distinct delivery IDs independently', async () => {
    const store = new FileDedupStore(storePath);
    const handled: string[] = [];

    for (const id of ['dlv_8f3a2b', 'dlv_1b9d40', 'dlv_8f3a2b']) {
      await handleOnce(store, id, async () => {
        handled.push(id);
      });
    }

    expect(handled).toEqual(['dlv_8f3a2b', 'dlv_1b9d40']);
  });
});

describe('FileDedupStore', () => {
  it('survives a restart: a new instance on the same path sees recorded IDs', async () => {
    const before = new FileDedupStore(storePath);
    await before.record(DELIVERY_ID);

    // A fresh instance stands in for a fresh process — nothing is shared but
    // the file on disk.
    const after = new FileDedupStore(storePath);

    expect(await after.has(DELIVERY_ID)).toBe(true);
    expect(await after.has('dlv_never_seen')).toBe(false);
  });

  it('treats a missing file as an empty store', async () => {
    const store = new FileDedupStore(join(dir, 'does-not-exist.json'));

    expect(await store.has(DELIVERY_ID)).toBe(false);
  });

  it('prunes entries older than maxAgeMs and keeps recent ones', async () => {
    const store = new FileDedupStore(storePath);
    const dayMs = 24 * 60 * 60 * 1000;
    const t0 = 1_776_000_000_000;

    await store.record('dlv_8f3a2b', t0);
    await store.record('dlv_1b9d40', t0 + 6 * dayMs);

    // Seven days on: the first entry is 7 days old, the second is 1 day old.
    const removed = await store.prune(dayMs, t0 + 7 * dayMs);

    expect(removed).toBe(1);
    expect(await store.has('dlv_8f3a2b')).toBe(false);
    expect(await store.has('dlv_1b9d40')).toBe(true);

    // The prune is persisted, not just applied in memory.
    const reopened = new FileDedupStore(storePath);
    expect(await reopened.has('dlv_8f3a2b')).toBe(false);
    expect(await reopened.has('dlv_1b9d40')).toBe(true);

    // And a pruned ID is processable again — the cost of bounding the store.
    let processedCount = 0;
    const result = await handleOnce(store, 'dlv_8f3a2b', async () => {
      processedCount += 1;
      return 'reprocessed';
    });

    expect(result).toEqual({ processed: true, result: 'reprocessed' });
    expect(processedCount).toBe(1);
  });

  it('reports zero removed when nothing is old enough', async () => {
    const store = new FileDedupStore(storePath);
    const t0 = 1_776_000_000_000;

    await store.record(DELIVERY_ID, t0);

    expect(await store.prune(60_000, t0 + 30_000)).toBe(0);
    expect(await store.has(DELIVERY_ID)).toBe(true);
  });

  it('throws on a corrupt store file instead of silently starting empty', async () => {
    await writeFile(storePath, '  not json at all {{{', 'utf8');

    const store = new FileDedupStore(storePath);

    await expect(store.has(DELIVERY_ID)).rejects.toThrow(/corrupt/i);
    // Still throws on a second call — a corrupt store never degrades to empty.
    await expect(store.has(DELIVERY_ID)).rejects.toThrow(/corrupt/i);
    await expect(store.record(DELIVERY_ID)).rejects.toThrow(/corrupt/i);
  });

  it('throws on well-formed JSON with the wrong shape', async () => {
    await writeFile(storePath, JSON.stringify({ version: 99, seen: {} }), 'utf8');

    await expect(new FileDedupStore(storePath).has(DELIVERY_ID)).rejects.toThrow(/corrupt/i);

    await writeFile(storePath, JSON.stringify({ version: 1, seen: ['dlv_8f3a2b'] }), 'utf8');

    await expect(new FileDedupStore(storePath).has(DELIVERY_ID)).rejects.toThrow(/corrupt/i);
  });

  it('leaves no temp files behind after an atomic write', async () => {
    const store = new FileDedupStore(storePath);

    await store.record(DELIVERY_ID);
    await store.record('dlv_1b9d40');

    const entries = await readdir(dir);

    expect(entries.filter((name) => name.endsWith('.tmp'))).toEqual([]);
    expect(entries).toEqual(['deliveries.json']);
  });

  it('writes the documented file format', async () => {
    const store = new FileDedupStore(storePath);
    const t0 = 1_776_000_000_000;

    await store.record(DELIVERY_ID, t0);

    expect(JSON.parse(await readFile(storePath, 'utf8'))).toEqual({
      version: 1,
      seen: { dlv_8f3a2b: t0 },
    });
  });
});
