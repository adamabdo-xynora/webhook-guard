/*
 * Deny-by-default auditing of stored webhook payloads.
 *
 * Why an allowlist, and why it is the whole module
 * -----------------------------------------------
 * Ad-hoc debug printing is how secrets leak. Someone is chasing a bug in an
 * archived delivery, drops a `console.log(payload)` into a script to see what
 * arrived, and the payload — whole, including whatever the provider decided to
 * embed in it — goes to a log aggregator, or a terminal scrollback that is
 * still open when a screen gets shared, or a Slack message pasted for a
 * colleague. None of those are places a credential can be recalled from. The
 * leak does not need a mistake in the receiver; it only needs a human wanting
 * to look at the data, which is the one thing an archive exists to permit.
 *
 * So this tool prints ONLY fields it affirmatively recognizes. Every other
 * field is withheld — not truncated, not masked, not summarized by type:
 * absent. A field that nobody has vouched for is exactly the field most likely
 * to be carrying something you did not intend to display, because it is the one
 * nobody has looked at.
 *
 * Redaction (redact.ts) is the safety net under storage: it keeps known secret
 * values from reaching disk. This allowlist is the safety net under human eyes:
 * it keeps everything else from reaching a screen. They fail differently — a
 * value redaction cannot see a credential it was never told about, and an
 * allowlist does not care what a field contains — which is the point of having
 * both.
 *
 * Why nesting is never traversed
 * ------------------------------
 * Only top-level keys are matched, and a nested object is withheld whole even
 * when a key inside it matches the allowlist. The moment an allowlist can reach
 * into nesting it stops being a list of fields and becomes a list of paths, and
 * this repo has already written down (at length, in redact.ts) what paths do:
 * they cover the shapes someone has already seen, and they are silently wrong
 * the instant a provider nests the same data one level deeper or renames a
 * parent. A path list that is silently wrong about redaction leaks a secret to
 * disk; a path list that is silently wrong here prints one to a screen. The
 * flat rule has no such failure mode: `data` is not in the allowlist, so
 * nothing under `data` is ever displayed, no matter what it is called.
 *
 * Dependency-free apart from ./storage.js, for the same reason storage.ts is:
 * the audit path should have nothing between it and the filesystem.
 */

import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';

import { listPayloads } from './storage.js';

/** What an operator is permitted to see about one archived payload. */
export interface AuditView {
  /** Path the payload was read from. */
  path: string;
  /** Delivery ID recovered from the filename, redelivery suffix removed. */
  deliveryId: string;
  /** Allowlisted top-level fields, stringified and length-capped. */
  shown: Record<string, string>;
  /**
   * How many top-level fields were withheld, or `WITHHELD_UNPARSEABLE` when the
   * file did not parse as a JSON object. A count, never a list: naming the
   * withheld keys would already disclose part of what was withheld.
   */
  withheldCount: number;
}

/**
 * Fields that are safe to display for every provider this receiver speaks to:
 * routing and envelope metadata, chosen because none of them is a place a
 * credential has ever plausibly been put. Anything carrying business data —
 * `data`, `object`, `request` — is deliberately absent.
 */
export const DEFAULT_ALLOWLIST: readonly string[] = [
  'event',
  'delivery_id',
  'created_at',
  'livemode',
  'api_version',
];

/**
 * `withheldCount` for a file that is not a JSON object.
 *
 * A sentinel rather than an exception: one corrupt file in a day's archive must
 * not stop the audit of the rest, and rather than 0 because "nothing was
 * withheld" and "nothing could be read" are different facts and an operator
 * needs to be able to tell them apart.
 */
const WITHHELD_UNPARSEABLE = -1;

/**
 * Longest stringified value that is displayed in full.
 *
 * A cap on volume, not a security control — a 120-character prefix of a secret
 * is still a disclosure, which is why the allowlist and not this is what keeps
 * secrets off the screen. What it buys is that one field cannot flood the
 * terminal and push the rest of the audit out of the scrollback.
 */
const MAX_VALUE_CHARS = 120;

/** Appended in place of the characters a truncated value dropped. */
const ELLIPSIS = '…';

/**
 * Audit one payload's bytes.
 *
 * `path` is used for the delivery ID and echoed back; the bytes are the only
 * thing inspected. Never throws on payload content: an audit run over a day's
 * archive should survive whatever is in that archive.
 */
export function auditPayload(
  path: string,
  rawBytes: Buffer,
  allowlist: readonly string[] = DEFAULT_ALLOWLIST,
): AuditView {
  const deliveryId = deliveryIdFromPath(path);

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBytes.toString('utf8'));
  } catch {
    // The parse error is discarded rather than reported. `JSON.parse` puts the
    // offending text in its message ("Unexpected token } in JSON at position
    // 412"), so surfacing it would print bytes out of a file this module has
    // just decided it cannot vouch for — the one thing the module exists to
    // prevent. The path and the sentinel are enough to go and look.
    return { path, deliveryId, shown: {}, withheldCount: WITHHELD_UNPARSEABLE };
  }

  // Valid JSON that is not an object — an array, a bare string, `null` — has no
  // top-level fields to match, so there is nothing an allowlist can approve. It
  // reports as unparseable rather than as "0 withheld", which would read as an
  // empty payload that the tool had successfully understood.
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { path, deliveryId, shown: {}, withheldCount: WITHHELD_UNPARSEABLE };
  }

  // Membership is checked against the allowlist, so an unexpected key can only
  // ever fail to match. Iterating the allowlist and pulling keys off the
  // payload would be equivalent here, but iterating the payload keeps the
  // "every key is classified exactly once" property visible in the loop, which
  // is what makes the withheld count trustworthy.
  const allowed = new Set(allowlist);
  const shown: Record<string, string> = {};
  let withheldCount = 0;

  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (!allowed.has(key)) {
      // The withheld key and value both end here. Neither is stored, counted by
      // name, or referenced anywhere in the returned structure.
      withheldCount += 1;
      continue;
    }
    shown[key] = displayValue(value);
  }

  return { path, deliveryId, shown, withheldCount };
}

/**
 * Audit every payload archived on one UTC day.
 *
 * Reads through `listPayloads` so the audit sees exactly the set of files
 * storage considers published — in particular not the temp files an interrupted
 * write can strand, which are not evidence of anything.
 */
export async function runAudit(
  baseDir: string,
  dateUtc: { year: number; month: number; day: number },
  allowlist: readonly string[] = DEFAULT_ALLOWLIST,
): Promise<AuditView[]> {
  const paths = await listPayloads(baseDir, dateUtc);

  const views: AuditView[] = [];
  for (const path of paths) {
    // Sequential, not `Promise.all`: a day's archive can be large, and an audit
    // that opens every file at once trades a bounded run for an EMFILE.
    views.push(auditPayload(path, await readFile(path), allowlist));
  }

  return views;
}

/**
 * Recover the delivery ID from an archived payload's filename.
 *
 * Storage writes `<deliveryId>.json`, and `<deliveryId>.<n>.json` when that
 * name is taken by an earlier attempt of the same delivery. Both map back to
 * the same ID, so an operator reading an audit of a day with redeliveries sees
 * one delivery attempted twice rather than two unrelated deliveries.
 */
function deliveryIdFromPath(path: string): string {
  // `.json` is what `listPayloads` filters on, so it is normally present; a
  // filename without it is still worth auditing, and keeping it whole is the
  // honest answer about which file was read.
  const name = basename(path).replace(/\.json$/, '');

  // Only an all-digits final segment is a redelivery suffix. Delivery IDs may
  // contain dots (storage.ts permits them), so stripping any trailing segment
  // would corrupt an ID like "dlv.8f3a" into "dlv".
  return name.replace(/\.\d+$/, '');
}

/**
 * Render one allowlisted value for display.
 *
 * `JSON.stringify` rather than `String(...)`: it quotes strings, so a value's
 * boundaries are visible and a payload cannot make its own content look like
 * the tool's output; and it renders objects and arrays as JSON rather than as
 * "[object Object]". An allowlisted field holding structure is unusual but not
 * forbidden, and it stays inside the cap below either way.
 */
function displayValue(value: unknown): string {
  // `undefined` cannot appear in parsed JSON, and a value that stringifies to
  // it would otherwise produce the literal text "undefined" in the output.
  const text = JSON.stringify(value) ?? 'null';

  if (text.length <= MAX_VALUE_CHARS) {
    return text;
  }

  return text.slice(0, MAX_VALUE_CHARS) + ELLIPSIS;
}
