import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { verifySignature } from '../src/verify.js';

const SECRET = 'whsec_9d4f1c7ae2b84f0aa1c3e5d7b9f10246';

const PAYLOAD = Buffer.from(
  JSON.stringify({
    event: 'invoice.paid',
    delivery_id: 'dlv_8f3a2b',
    data: { invoice_id: 'inv_20260819_0042', amount_cents: 124900 },
  }),
  'utf8',
);

/** Build the header a well-behaved sender would send for these bytes. */
function sign(body: Buffer, secret: string = SECRET): string {
  return `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
}

describe('verifySignature', () => {
  it('accepts a signature produced with the shared secret', () => {
    const result = verifySignature({
      secret: SECRET,
      signatureHeader: sign(PAYLOAD),
      rawBody: PAYLOAD,
    });

    expect(result).toEqual({ valid: true });
  });

  it('rejects a body tampered with after signing', () => {
    const signatureHeader = sign(PAYLOAD);

    const tampered = Buffer.from(PAYLOAD);
    tampered[10] = tampered[10]! ^ 0x01;

    const result = verifySignature({
      secret: SECRET,
      signatureHeader,
      rawBody: tampered,
    });

    expect(result).toEqual({ valid: false, reason: 'signature mismatch' });
  });

  it('rejects a signature produced with the wrong secret', () => {
    const result = verifySignature({
      secret: SECRET,
      signatureHeader: sign(PAYLOAD, 'whsec_attacker_guess'),
      rawBody: PAYLOAD,
    });

    expect(result).toEqual({ valid: false, reason: 'signature mismatch' });
  });

  it('rejects a header missing the "sha256=" prefix', () => {
    const bareHex = createHmac('sha256', SECRET).update(PAYLOAD).digest('hex');

    const result = verifySignature({
      secret: SECRET,
      signatureHeader: bareHex,
      rawBody: PAYLOAD,
    });

    expect(result).toEqual({ valid: false, reason: 'malformed signature header' });
  });

  it('rejects an empty signature header', () => {
    const result = verifySignature({
      secret: SECRET,
      signatureHeader: '',
      rawBody: PAYLOAD,
    });

    expect(result).toEqual({ valid: false, reason: 'missing signature header' });
  });

  it('rejects a timestamp 10 minutes old under the default tolerance', () => {
    const nowSeconds = 1_776_000_000;

    const result = verifySignature({
      secret: SECRET,
      signatureHeader: sign(PAYLOAD),
      rawBody: PAYLOAD,
      timestampHeader: String(nowSeconds - 600),
      nowSeconds,
    });

    expect(result).toEqual({ valid: false, reason: 'timestamp outside tolerance' });
  });

  it('accepts a timestamp 10 seconds old', () => {
    const nowSeconds = 1_776_000_000;

    const result = verifySignature({
      secret: SECRET,
      signatureHeader: sign(PAYLOAD),
      rawBody: PAYLOAD,
      timestampHeader: String(nowSeconds - 10),
      nowSeconds,
    });

    expect(result).toEqual({ valid: true });
  });

  it('rejects a correctly formatted signature of the wrong length without throwing', () => {
    // Valid hex, valid prefix, but 16 bytes instead of 32 — the length branch
    // must short-circuit before timingSafeEqual, which throws on mismatch.
    const shortHex = createHmac('sha256', SECRET).update(PAYLOAD).digest('hex').slice(0, 32);

    const call = () =>
      verifySignature({
        secret: SECRET,
        signatureHeader: `sha256=${shortHex}`,
        rawBody: PAYLOAD,
      });

    expect(call).not.toThrow();
    expect(call()).toEqual({ valid: false, reason: 'signature mismatch' });
  });

  it('never echoes the secret or the expected signature in a failure reason', () => {
    const expectedHex = createHmac('sha256', SECRET).update(PAYLOAD).digest('hex');

    const result = verifySignature({
      secret: SECRET,
      signatureHeader: sign(PAYLOAD, 'whsec_attacker_guess'),
      rawBody: PAYLOAD,
    });

    expect(result.valid).toBe(false);
    const reason = result.valid ? '' : result.reason;
    expect(reason).not.toContain(SECRET);
    expect(reason).not.toContain(expectedHex);
  });
});
