/*
 * HMAC-SHA256 webhook signature verification.
 *
 * Reject before parse
 * -------------------
 * This module operates on bytes only. It never hands `rawBody` to `JSON.parse`
 * — or to any other interpreter, validator, or business logic — and callers must
 * not either until `verifySignature` has returned `{ valid: true }`.
 *
 * A webhook body is attacker-controlled input: anyone who can reach the endpoint
 * can put arbitrary bytes in it. The signature is the only thing that tells us
 * the bytes came from the sender we share a secret with. Every piece of code that
 * touches the body before that check runs is code an unauthenticated stranger can
 * reach — parsers, schema coercion, ORM lookups, log formatters. That is attack
 * surface handed out for free, and parsers in particular have a long history of
 * being the weak link (deep-nesting and quadratic-blowup DoS, prototype pollution
 * via `__proto__`, type-confusion bugs downstream). Verifying first shrinks the
 * pre-auth surface to one constant-time byte comparison.
 *
 * It also means verification must run on the *raw* bytes, not on a re-serialized
 * object: `JSON.stringify(JSON.parse(body))` changes key order, whitespace, and
 * number formatting, and the HMAC will not match. Capture the raw buffer at the
 * transport layer and pass it here untouched.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

const SIGNATURE_PREFIX = 'sha256=';
const DEFAULT_TOLERANCE_SECONDS = 300;

/** Hex digest of SHA-256: an even-length run of hex characters. */
const HEX_PATTERN = /^(?:[0-9a-fA-F]{2})+$/;

/** Unix seconds, optionally signed. Rejects whitespace, decimals, and "1e9". */
const UNIX_SECONDS_PATTERN = /^-?\d+$/;

export interface VerifyOptions {
  /** The shared webhook secret. */
  secret: string;
  /** Raw header value from the request, format "sha256=<hex>". */
  signatureHeader: string;
  /** The raw, unparsed request body bytes. */
  rawBody: Buffer;
  /** Replay window in seconds. Defaults to 300. */
  toleranceSeconds?: number;
  /** Optional unix-seconds timestamp header value; if provided, reject if outside tolerance. */
  timestampHeader?: string;
  /** Injected clock in unix seconds, used instead of `Date.now()` when provided. */
  nowSeconds?: number;
}

/**
 * Verify an HMAC-SHA256 webhook signature over the raw request body.
 *
 * Failure reasons are deliberately coarse and never echo the expected signature
 * or the secret — an error string is an oracle if you let it be one.
 */
export function verifySignature(
  opts: VerifyOptions,
): { valid: true } | { valid: false; reason: string } {
  const { secret, signatureHeader, rawBody } = opts;

  if (signatureHeader.trim().length === 0) {
    return { valid: false, reason: 'missing signature header' };
  }

  const header = signatureHeader.trim();
  if (!header.startsWith(SIGNATURE_PREFIX)) {
    return { valid: false, reason: 'malformed signature header' };
  }
  const providedHex = header.slice(SIGNATURE_PREFIX.length);

  // Compute the expected digest before inspecting the provided one, so that a
  // well-formed-but-wrong signature and a length-mismatched one cost the same
  // HMAC work. The remaining branches are structural, not secret-dependent.
  const expected = createHmac('sha256', secret).update(rawBody).digest();

  if (!HEX_PATTERN.test(providedHex)) {
    return { valid: false, reason: 'malformed signature header' };
  }

  const provided = Buffer.from(providedHex, 'hex');

  // timingSafeEqual throws on length mismatch, so the lengths must be compared
  // first — a differing length is public information (it is right there in the
  // header) and leaks nothing about the expected digest.
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    return { valid: false, reason: 'signature mismatch' };
  }

  // Replay window is checked only after the body is known to be authentic. The
  // timestamp header is not covered by this signature, so an unauthenticated
  // caller must not be able to steer any logic with it.
  if (opts.timestampHeader !== undefined) {
    const tolerance = opts.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
    const timestamp = Number(opts.timestampHeader.trim());
    const now = opts.nowSeconds ?? Math.floor(Date.now() / 1000);

    // Fail closed: an unparseable timestamp or a nonsensical tolerance is
    // treated exactly like a stale one.
    if (
      !UNIX_SECONDS_PATTERN.test(opts.timestampHeader.trim()) ||
      !Number.isFinite(timestamp) ||
      !Number.isFinite(tolerance) ||
      tolerance < 0 ||
      Math.abs(now - timestamp) > tolerance
    ) {
      return { valid: false, reason: 'timestamp outside tolerance' };
    }
  }

  return { valid: true };
}
