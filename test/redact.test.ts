import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { makeRedactionFilter, redactBuffer, secretsFromEnv } from '../src/redact.js';
import { storePayload } from '../src/storage.js';

/** The endpoint's own signing secret, echoed back by the provider. */
const ENDPOINT_SECRET = 'whsec_9f2c8a1d4e6b0a7c3f5d';

/** 2026-08-19T12:00:00Z — mid-day UTC, so no timezone can shift the date. */
const AUG_19_NOON_UTC = Date.UTC(2026, 7, 19, 12, 0, 0);

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'webhook-guard-redact-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

/** Every regular file under `root`, as absolute paths, sorted. */
async function walk(root: string): Promise<string[]> {
  const found: string[] = [];

  const visit = async (current: string): Promise<void> => {
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw err;
    }
    for (const entry of entries) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) {
        await visit(path);
      } else {
        found.push(path);
      }
    }
  };

  await visit(root);
  return found.sort();
}

/** A delivery-attempt dump of the shape providers actually send. */
function attemptsPayload(): Buffer {
  return Buffer.from(
    JSON.stringify({
      event: 'invoice.paid',
      delivery_id: 'dlv_8f3a2b',
      data: {
        invoice_id: 'inv_20260819_0042',
        amount_cents: 124900,
        attempts: [
          {
            attempt: 1,
            status: 502,
            request: {
              url: 'https://example.test/hooks/invoice',
              headers: { 'Content-Type': 'application/json' },
            },
          },
          {
            attempt: 2,
            status: 200,
            request: {
              url: 'https://example.test/hooks/invoice',
              // The echo. The provider is mirroring back the credentials it
              // used to call us, four levels deep and inside a longer string.
              headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${ENDPOINT_SECRET}`,
              },
            },
          },
        ],
      },
    }),
    'utf8',
  );
}

describe('the storage seam', () => {
  it('a secret planted deep in a nested payload never reaches disk', async () => {
    const baseDir = join(dir, 'payloads');
    const rawBody = attemptsPayload();

    // Sanity check on the fixture itself: if the secret were not actually in
    // the payload, every assertion below would pass for the wrong reason.
    expect(rawBody.toString('utf8')).toContain(ENDPOINT_SECRET);

    // The real storage module, the real filter, a real temp directory. The
    // point of this test is the wiring, so nothing here is a stand-in.
    await storePayload({
      baseDir,
      deliveryId: 'dlv_8f3a2b',
      rawBody,
      filter: makeRedactionFilter([{ name: 'endpoint_secret', value: ENDPOINT_SECRET }]),
      nowMs: AUG_19_NOON_UTC,
    });

    // Read back EVERY file the store created — not just the path it returned.
    // A leak into a stranded temp file is still a leak, and the claim being
    // tested is about the directory, not about one filename.
    const files = await walk(baseDir);
    expect(files).toHaveLength(1);

    for (const file of files) {
      const contents = await readFile(file, 'utf8');
      expect(contents).not.toContain(ENDPOINT_SECRET);
      // The distinguishing part of the credential, in case a partial
      // replacement left a usable tail behind.
      expect(contents).not.toContain('9f2c8a1d4e6b0a7c3f5d');
    }

    const stored = await readFile(files[0]!, 'utf8');
    expect(stored).toContain('[REDACTED:endpoint_secret]');

    // Still valid JSON, still the same document: redaction replaces the value
    // in place, it does not corrupt the archive.
    const parsed = JSON.parse(stored);
    expect(parsed.data.attempts[1].request.headers.Authorization).toBe(
      'Bearer [REDACTED:endpoint_secret]',
    );
    expect(parsed.data.invoice_id).toBe('inv_20260819_0042');
  });
});

describe('redactBuffer', () => {
  it('replaces a secret appearing as a whole string value', () => {
    const payload = Buffer.from(JSON.stringify({ token: ENDPOINT_SECRET }), 'utf8');

    const { output, hits } = redactBuffer(payload, [
      { name: 'endpoint_secret', value: ENDPOINT_SECRET },
    ]);

    expect(JSON.parse(output.toString('utf8'))).toEqual({
      token: '[REDACTED:endpoint_secret]',
    });
    expect(hits).toEqual([{ name: 'endpoint_secret', count: 1 }]);
  });

  it('replaces a secret inside a longer string', () => {
    const payload = Buffer.from(
      JSON.stringify({ headers: { Authorization: `Bearer ${ENDPOINT_SECRET}` } }),
      'utf8',
    );

    const { output } = redactBuffer(payload, [
      { name: 'endpoint_secret', value: ENDPOINT_SECRET },
    ]);

    const text = output.toString('utf8');
    expect(text).not.toContain(ENDPOINT_SECRET);
    // The surrounding string survives — only the credential is replaced.
    expect(JSON.parse(text).headers.Authorization).toBe('Bearer [REDACTED:endpoint_secret]');
  });

  it('replaces a secret in a key as well as a value, at any depth', () => {
    const payload = Buffer.from(
      JSON.stringify({ meta: { [ENDPOINT_SECRET]: { nested: [{ v: ENDPOINT_SECRET }] } } }),
      'utf8',
    );

    const { output, hits } = redactBuffer(payload, [
      { name: 'endpoint_secret', value: ENDPOINT_SECRET },
    ]);

    const text = output.toString('utf8');
    expect(text).not.toContain(ENDPOINT_SECRET);
    expect(JSON.parse(text)).toEqual({
      meta: { '[REDACTED:endpoint_secret]': { nested: [{ v: '[REDACTED:endpoint_secret]' }] } },
    });
    expect(hits).toEqual([{ name: 'endpoint_secret', count: 2 }]);
  });

  it('replaces multiple distinct secrets with their respective names', () => {
    const apiKey = 'fixturekey_4b7d1e9a2c6f';
    const dbUrl = 'postgres://user:hunter2hunter2@db.internal:5432/app';
    const payload = Buffer.from(
      JSON.stringify({
        headers: { Authorization: `Bearer ${ENDPOINT_SECRET}` },
        data: { key: apiKey, notes: [`connect via ${dbUrl} then retry`] },
      }),
      'utf8',
    );

    const { output, hits } = redactBuffer(payload, [
      { name: 'endpoint_secret', value: ENDPOINT_SECRET },
      { name: 'stripe_key', value: apiKey },
      { name: 'database_url', value: dbUrl },
    ]);

    const text = output.toString('utf8');
    for (const value of [ENDPOINT_SECRET, apiKey, dbUrl]) {
      expect(text).not.toContain(value);
    }
    expect(text).toContain('[REDACTED:endpoint_secret]');
    expect(text).toContain('[REDACTED:stripe_key]');
    expect(text).toContain('[REDACTED:database_url]');

    // Each name reported exactly once, each with its own count.
    expect([...hits].sort((a, b) => a.name.localeCompare(b.name))).toEqual([
      { name: 'database_url', count: 1 },
      { name: 'endpoint_secret', count: 1 },
      { name: 'stripe_key', count: 1 },
    ]);
  });

  it('replaces repeated occurrences of the same secret and reports an accurate count', () => {
    const payload = Buffer.from(
      JSON.stringify({
        attempts: [
          { headers: { Authorization: `Bearer ${ENDPOINT_SECRET}` } },
          { headers: { Authorization: `Bearer ${ENDPOINT_SECRET}` } },
          { headers: { Authorization: `Bearer ${ENDPOINT_SECRET}` } },
        ],
        echo: `retrying with ${ENDPOINT_SECRET}`,
      }),
      'utf8',
    );

    const { output, hits } = redactBuffer(payload, [
      { name: 'endpoint_secret', value: ENDPOINT_SECRET },
    ]);

    const text = output.toString('utf8');
    expect(text).not.toContain(ENDPOINT_SECRET);
    expect(text.split('[REDACTED:endpoint_secret]').length - 1).toBe(4);
    expect(hits).toEqual([{ name: 'endpoint_secret', count: 4 }]);
  });

  it('handles a secret containing " and \\ characters when embedded in serialized JSON', () => {
    // A credential with JSON metacharacters in it. Serializing the payload
    // escapes them, so the bytes on the wire do not contain the raw value at
    // all — matching only the raw form would report zero hits and archive the
    // credential untouched.
    const awkward = 'fixturekey_"quote\\slash"_7f3a9b2c';
    const serialized = Buffer.from(
      JSON.stringify({ data: { vendor: { key: awkward }, note: `using ${awkward} now` } }),
      'utf8',
    );

    // The fixture must really be escaped, or this test proves nothing.
    expect(serialized.toString('utf8')).not.toContain(awkward);
    expect(serialized.toString('utf8')).toContain('fixturekey_\\"quote\\\\slash\\"_7f3a9b2c');

    const { output, hits } = redactBuffer(serialized, [{ name: 'vendor_key', value: awkward }]);
    const text = output.toString('utf8');

    // No fragment survives: not the raw form, not the escaped form, and not any
    // of the pieces the escaping splits the value into. A half-replacement
    // would leave one of these behind.
    expect(text).not.toContain(awkward);
    expect(text).not.toContain(JSON.stringify(awkward).slice(1, -1));
    for (const fragment of awkward.split(/["\\]/).filter((part) => part.length >= 3)) {
      expect(text).not.toContain(fragment);
    }

    expect(hits).toEqual([{ name: 'vendor_key', count: 2 }]);
    const parsed = JSON.parse(text);
    expect(parsed.data.vendor.key).toBe('[REDACTED:vendor_key]');
    expect(parsed.data.note).toBe('using [REDACTED:vendor_key] now');
  });

  it('redacts an overlapping secret as the longest match, leaving no fragment', () => {
    const short = 'abcdef123456';
    const long = 'abcdef123456_extended';
    const payload = Buffer.from(JSON.stringify({ auth: { token: long } }), 'utf8');

    // Short one listed first, to prove the ordering is the implementation's
    // doing and not an accident of the caller's argument order.
    const { output, hits } = redactBuffer(payload, [
      { name: 'short_key', value: short },
      { name: 'long_key', value: long },
    ]);

    const text = output.toString('utf8');
    expect(JSON.parse(text).auth.token).toBe('[REDACTED:long_key]');

    // Nothing of either secret is left, and crucially no "_extended" tail —
    // that is what a short-first replacement would strand on disk.
    expect(text).not.toContain(short);
    expect(text).not.toContain(long);
    expect(text).not.toContain('_extended');
    expect(text).not.toContain('[REDACTED:short_key]');

    expect(hits).toEqual([{ name: 'long_key', count: 1 }]);
  });

  it('returns identical bytes when there are no secrets', () => {
    const payload = attemptsPayload();

    const { output, hits } = redactBuffer(payload, []);

    expect(output.equals(payload)).toBe(true);
    expect(hits).toEqual([]);
  });

  it('reports names only, never values', () => {
    const payload = Buffer.from(
      JSON.stringify({ a: ENDPOINT_SECRET, b: `x ${ENDPOINT_SECRET} y` }),
      'utf8',
    );

    const { hits } = redactBuffer(payload, [
      { name: 'endpoint_secret', value: ENDPOINT_SECRET },
    ]);

    // A hit report is destined for a log line. If it carried the value, the
    // credential would simply move from the archive to the log.
    const serializedHits = JSON.stringify(hits);
    expect(serializedHits).not.toContain(ENDPOINT_SECRET);
    expect(serializedHits).not.toContain('9f2c8a1d4e6b0a7c3f5d');
    for (const hit of hits) {
      expect(Object.keys(hit).sort()).toEqual(['count', 'name']);
    }
  });
});

describe('secretsFromEnv', () => {
  it('selects credential-shaped variables and skips the rest', () => {
    const env: Record<string, string | undefined> = {
      WEBHOOK_ENDPOINT_SECRET: ENDPOINT_SECRET,
      MY_TOKEN_X: 'tok_5c1e8a4d0b93',
      PATH: '/usr/local/bin:/usr/bin:/bin',
      HOME: '/Users/example',
      UNSET_SECRET: undefined,
    };

    const secrets = secretsFromEnv(env);
    const names = secrets.map((secret) => secret.name).sort();

    // WEBHOOK_ matches by prefix; MY_TOKEN_X matches by substring even though
    // it starts with nothing in particular.
    expect(names).toEqual(['MY_TOKEN_X', 'WEBHOOK_ENDPOINT_SECRET']);
    expect(secrets.find((secret) => secret.name === 'WEBHOOK_ENDPOINT_SECRET')?.value).toBe(
      ENDPOINT_SECRET,
    );
  });

  it('skips values shorter than 8 characters', () => {
    const secrets = secretsFromEnv({
      SECRET_TINY: 'abc12',
      SECRET_EMPTY: '',
      SECRET_REAL: 'k9d2m4x7q1',
    });

    // "abc12" would match inside ordinary payload content and shred the
    // archive; a credential that short is a different problem entirely.
    expect(secrets.map((secret) => secret.name)).toEqual(['SECRET_REAL']);
  });

  it('honours a custom prefix list', () => {
    const env = {
      ACME_KEY: 'acme_2f8b6d1c0a',
      WEBHOOK_ENDPOINT_SECRET: ENDPOINT_SECRET,
      OTHER_VALUE: 'not_a_credential_value',
    };

    const secrets = secretsFromEnv(env, ['ACME_']);

    // Custom prefixes replace the defaults, but the SECRET/TOKEN substring rule
    // is unconditional — it is the backstop for oddly named variables.
    expect(secrets.map((secret) => secret.name).sort()).toEqual([
      'ACME_KEY',
      'WEBHOOK_ENDPOINT_SECRET',
    ]);
  });
});

describe('makeRedactionFilter', () => {
  it('produces a Buffer-in, Buffer-out filter', () => {
    const filter = makeRedactionFilter([{ name: 'endpoint_secret', value: ENDPOINT_SECRET }]);
    const output = filter(Buffer.from(`prefix ${ENDPOINT_SECRET} suffix`, 'utf8'));

    expect(Buffer.isBuffer(output)).toBe(true);
    expect(output.toString('utf8')).toBe('prefix [REDACTED:endpoint_secret] suffix');
  });

  it('is unaffected by later mutation of the caller\u2019s secret list', () => {
    const secrets = [{ name: 'endpoint_secret', value: ENDPOINT_SECRET }];
    const filter = makeRedactionFilter(secrets);

    // Whether a delivery gets redacted must not depend on when it arrived
    // relative to someone editing the array they passed in.
    secrets.length = 0;

    expect(filter(Buffer.from(ENDPOINT_SECRET, 'utf8')).toString('utf8')).toBe(
      '[REDACTED:endpoint_secret]',
    );
  });
});
