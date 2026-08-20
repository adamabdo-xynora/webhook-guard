import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { auditPayload, runAudit, DEFAULT_ALLOWLIST } from '../src/audit.js';
import { storePayload } from '../src/storage.js';

/** The same realistic delivery the other suites use. */
const DELIVERY_ID = 'dlv_8f3a2b';

/** 2026-08-19T12:00:00Z — mid-day UTC, so no timezone can shift the date. */
const AUG_19_NOON_UTC = Date.UTC(2026, 7, 19, 12, 0, 0);
const AUG_19 = { year: 2026, month: 8, day: 19 } as const;

let dir: string;
let baseDir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'webhook-guard-audit-'));
  baseDir = join(dir, 'payloads');
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

/** JSON bytes, the way a payload reaches the archive. */
function bytes(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(value), 'utf8');
}

describe('auditPayload', () => {
  it('shows only allowlisted top-level fields', () => {
    const view = auditPayload(
      `/archive/${DELIVERY_ID}.json`,
      bytes({
        event: 'invoice.paid',
        delivery_id: DELIVERY_ID,
        data: { invoice_id: 'inv_20260819_0042', api_key: 'fixturekey_9c81f0a2b7' },
      }),
    );

    expect(view.shown).toHaveProperty('event', '"invoice.paid"');
    expect(view.shown).toHaveProperty('delivery_id', `"${DELIVERY_ID}"`);

    // `data` is not allowlisted, so the whole subtree is absent — not summarized,
    // not typed, not counted by name.
    expect(view.shown).not.toHaveProperty('data');

    // The point of the module: the credential nested inside the withheld field
    // is nowhere in what an operator would be shown or a script would serialize.
    expect(JSON.stringify(view)).not.toContain('fixturekey_9c81f0a2b7');
  });

  it('counts the withheld top-level fields', () => {
    const view = auditPayload(
      `/archive/${DELIVERY_ID}.json`,
      bytes({
        event: 'invoice.paid', // shown
        created_at: '2026-08-19T12:00:00Z', // shown
        data: {}, // withheld
        request: { id: 'req_1' }, // withheld
        pending_webhooks: 2, // withheld
      }),
    );

    expect(Object.keys(view.shown).sort()).toEqual(['created_at', 'event']);
    expect(view.withheldCount).toBe(3);
  });

  it('never traverses into nested objects, even when a nested key is allowlisted', () => {
    // `data.event` matches an allowlisted name at a nested path. Matching it
    // would turn the allowlist into a path list, which is the failure mode
    // redact.ts exists to argue against.
    const view = auditPayload(
      `/archive/${DELIVERY_ID}.json`,
      bytes({
        delivery_id: DELIVERY_ID,
        data: { event: 'nested.event.name', api_version: '2026-01-01' },
      }),
    );

    expect(Object.keys(view.shown)).toEqual(['delivery_id']);
    expect(view.shown).not.toHaveProperty('event');
    expect(view.shown).not.toHaveProperty('api_version');
    expect(JSON.stringify(view)).not.toContain('nested.event.name');
    expect(view.withheldCount).toBe(1);
  });

  it('truncates long values to 120 characters with an ellipsis', () => {
    const long = 'a'.repeat(500);
    const view = auditPayload(`/archive/${DELIVERY_ID}.json`, bytes({ event: long }));

    const shown = view.shown['event'] as string;
    expect(shown).toHaveLength(121); // 120 characters plus the ellipsis
    expect(shown.endsWith('…')).toBe(true);
    expect(shown.slice(0, 120)).toBe(`"${'a'.repeat(119)}`);
  });

  it('leaves a value of exactly the cap untruncated', () => {
    // 118 characters plus the two quotes JSON.stringify adds is exactly 120.
    const exact = 'b'.repeat(118);
    const view = auditPayload(`/archive/${DELIVERY_ID}.json`, bytes({ event: exact }));

    expect(view.shown['event']).toBe(`"${exact}"`);
    expect(view.shown['event']).not.toContain('…');
  });

  it('returns the sentinel for an unparseable payload instead of throwing', () => {
    const view = auditPayload(
      `/archive/${DELIVERY_ID}.json`,
      Buffer.from('{"event": "invoice.paid", ', 'utf8'),
    );

    expect(view.withheldCount).toBe(-1);
    expect(view.shown).toEqual({});
    expect(view.deliveryId).toBe(DELIVERY_ID);
  });

  it('reports valid JSON that is not an object as unparseable', () => {
    for (const notAnObject of ['[1,2,3]', '"a string"', 'null', '42']) {
      const view = auditPayload('/archive/x.json', Buffer.from(notAnObject, 'utf8'));
      expect(view.withheldCount).toBe(-1);
      expect(view.shown).toEqual({});
    }
  });

  it('honours a custom allowlist in place of the default', () => {
    const payload = bytes({
      event: 'invoice.paid',
      account_id: 'acct_4471',
      data: { amount_cents: 124900 },
    });

    const custom = auditPayload('/archive/x.json', payload, ['account_id']);

    expect(custom.shown).toEqual({ account_id: '"acct_4471"' });
    // `event` is allowlisted by default and withheld here — the argument wins.
    expect(custom.shown).not.toHaveProperty('event');
    expect(custom.withheldCount).toBe(2);

    // Same bytes under the default allowlist, to show the difference is the list.
    expect(auditPayload('/archive/x.json', payload).shown).toHaveProperty('event');
    expect(DEFAULT_ALLOWLIST).toContain('event');
  });

  it('recovers the delivery ID from the filename, with or without a redelivery suffix', () => {
    expect(auditPayload(`/a/b/${DELIVERY_ID}.json`, bytes({})).deliveryId).toBe(DELIVERY_ID);
    expect(auditPayload(`/a/b/${DELIVERY_ID}.1.json`, bytes({})).deliveryId).toBe(DELIVERY_ID);
    expect(auditPayload(`/a/b/${DELIVERY_ID}.42.json`, bytes({})).deliveryId).toBe(DELIVERY_ID);

    // Dots are legal inside a delivery ID, so only a numeric final segment is
    // treated as a redelivery suffix.
    expect(auditPayload('/a/b/dlv.8f3a.json', bytes({})).deliveryId).toBe('dlv.8f3a');
  });
});

describe('runAudit', () => {
  it('audits every payload archived on a UTC day', async () => {
    await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: bytes({ event: 'invoice.paid', delivery_id: DELIVERY_ID, data: { a: 1 } }),
      nowMs: AUG_19_NOON_UTC,
    });

    // Same delivery ID again: a redelivery, archived alongside the first attempt
    // as `<id>.1.json` rather than overwriting it.
    await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: bytes({ event: 'invoice.paid', delivery_id: DELIVERY_ID, data: { a: 2 } }),
      nowMs: AUG_19_NOON_UTC,
    });

    const views = await runAudit(baseDir, AUG_19);

    expect(views).toHaveLength(2);
    // Both attempts map back to the one delivery they are attempts of.
    expect(views.map((v) => v.deliveryId)).toEqual([DELIVERY_ID, DELIVERY_ID]);
    // Sorted by filename, and "<id>.1.json" sorts ahead of "<id>.json".
    expect(views.map((v) => v.path.replace(/^.*\//, ''))).toEqual([
      `${DELIVERY_ID}.1.json`,
      `${DELIVERY_ID}.json`,
    ]);

    for (const view of views) {
      expect(view.shown).toEqual({
        event: '"invoice.paid"',
        delivery_id: `"${DELIVERY_ID}"`,
      });
      expect(view.withheldCount).toBe(1);
    }
  });

  it('returns no views for a day with nothing archived', async () => {
    await expect(runAudit(baseDir, { year: 2026, month: 8, day: 18 })).resolves.toEqual([]);
  });

  it('carries a custom allowlist through to each payload', async () => {
    await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: bytes({ event: 'invoice.paid', account_id: 'acct_4471' }),
      nowMs: AUG_19_NOON_UTC,
    });

    const views = await runAudit(baseDir, AUG_19, ['account_id']);

    expect(views[0]?.shown).toEqual({ account_id: '"acct_4471"' });
  });

  it('does not stop on an unparseable file in the middle of a day', async () => {
    const { path } = await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: bytes({ event: 'invoice.paid' }),
      nowMs: AUG_19_NOON_UTC,
    });

    // Corrupt bytes landing next to a good payload — a truncated write from an
    // older tool, say. One bad file must not cost the audit of the whole day.
    await writeFile(join(path, '..', 'zz_corrupt.json'), '{not json', 'utf8');

    const views = await runAudit(baseDir, AUG_19);

    expect(views).toHaveLength(2);
    expect(views[0]?.withheldCount).toBe(0);
    expect(views[1]?.withheldCount).toBe(-1);
  });
});

describe('the guarantee', () => {
  it('withheld content never appears in the audit output', async () => {
    // Every value outside the allowlist is a distinctive marker. If any of them
    // shows up anywhere in the serialized result — as a value, inside a key
    // name, in an error message, in a truncated prefix — this fails. That is
    // the whole claim of the module, stated as one assertion.
    const markers = [
      'MARKER_TOP_LEVEL_SECRET_a1',
      'MARKER_NESTED_UNDER_DATA_b2',
      'MARKER_NESTED_ALLOWLISTED_KEY_c3',
      'MARKER_DEEPLY_NESTED_d4',
      'MARKER_IN_ARRAY_e5',
      'MARKER_AS_KEY_f6',
      'MARKER_LONG_g7',
    ];

    await storePayload({
      baseDir,
      deliveryId: DELIVERY_ID,
      rawBody: bytes({
        // Allowlisted, and carrying nothing distinctive.
        event: 'invoice.paid',
        delivery_id: DELIVERY_ID,
        created_at: '2026-08-19T12:00:00Z',

        // Everything below is withheld.
        api_key: 'MARKER_TOP_LEVEL_SECRET_a1',
        data: {
          token: 'MARKER_NESTED_UNDER_DATA_b2',
          // A nested key that matches the allowlist: still withheld, because the
          // allowlist matches fields, not paths.
          event: 'MARKER_NESTED_ALLOWLISTED_KEY_c3',
          deep: { deeper: { deepest: 'MARKER_DEEPLY_NESTED_d4' } },
          items: ['MARKER_IN_ARRAY_e5'],
        },
        // A marker in the key position, not the value position.
        MARKER_AS_KEY_f6: 'irrelevant',
        // Long enough to be truncated if it were ever shown, so a truncated
        // prefix of it would still be caught by the assertion below.
        notes: `MARKER_LONG_g7${'x'.repeat(500)}`,
      }),
      nowMs: AUG_19_NOON_UTC,
    });

    const views = await runAudit(baseDir, AUG_19);
    const serialized = JSON.stringify(views);

    for (const marker of markers) {
      expect(serialized).not.toContain(marker);
    }

    // And the audit is still useful: it reported what it was allowed to report.
    expect(views[0]?.shown).toEqual({
      event: '"invoice.paid"',
      delivery_id: `"${DELIVERY_ID}"`,
      created_at: '"2026-08-19T12:00:00Z"',
    });
    expect(views[0]?.withheldCount).toBe(4);
  });
});
