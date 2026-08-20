/*
 * Credential redaction by VALUE, not by path.
 *
 * Why value matching is the only durable fix
 * ------------------------------------------
 * Webhook payloads sometimes echo your own secrets back at you. A provider may
 * include the endpoint's signing secret in a delivery-attempt dump, mirror the
 * `Authorization` header it sent you, or quote an API key inside an error
 * message it generated. If raw bodies are archived (and they should be — see
 * storage.ts on why the exact bytes are the evidence), every one of those
 * deliveries writes a live credential to disk, in a directory whose whole
 * purpose is to be kept for a long time and read by humans during incidents.
 *
 * Rotating the secret does not fix it. The next delivery echoes the *new*
 * value, and now the archive holds both. The leak is a property of the pipeline,
 * not of any particular credential.
 *
 * Path-based redaction — "strip data.auth.token before storing" — does not fix
 * it either. A path list only covers the echo sites someone has already
 * discovered, and it is silently wrong the moment the provider adds a field,
 * renames one, nests the same value one level deeper, or embeds it mid-string
 * ("Bearer <secret>"). You find out you were missing one by finding it in the
 * archive, which is to say: after it has already been written.
 *
 * So this module inverts the question. Instead of asking "which locations hold
 * secrets", it asks "where does this known secret VALUE appear" — any key, any
 * nesting depth, any position inside a longer string, in serialized-and-escaped
 * form as well as raw — and replaces every occurrence before the bytes reach
 * disk. The input is the set of credentials you hold, which you already know,
 * rather than the set of places a vendor might put them, which you do not.
 *
 * Scope, honestly stated
 * ----------------------
 * This catches echoes of secrets you supply. It does not catch a credential
 * this process has never heard of, nor a transformed one (base64'd, hashed,
 * split across two fields). It is a last line of defence in front of the
 * archive, not a general DLP scanner.
 *
 * Dependency-free by design: this sits directly in front of the write path, and
 * the write path should have nothing between it and the filesystem.
 */

/** One credential to scan for. `name` is a label, safe to log; `value` is not. */
export interface Secret {
  /** Short identifier used in the replacement marker, e.g. "endpoint_secret". */
  name: string;
  /** The credential itself. Never logged, never included in return values. */
  value: string;
}

/**
 * Env var name prefixes that mark a variable as credential-bearing.
 *
 * Deliberately broad: a false positive costs one redacted value in an archived
 * payload, a false negative costs a plaintext credential on disk forever.
 */
const DEFAULT_PREFIXES = ['WEBHOOK_', 'SECRET_', 'API_KEY', 'TOKEN_'];

/** Substrings that qualify a variable regardless of how its name starts. */
const NAME_SUBSTRINGS = ['SECRET', 'TOKEN'];

/**
 * Values shorter than this are not scanned for.
 *
 * Two reasons, and the first is the operational one: very short values create
 * false-positive redaction storms. A secret of "test" or "1234" occurs inside
 * ordinary payload content — IDs, amounts, timestamps, words — so redacting
 * every occurrence shreds the payload and destroys exactly the audit value the
 * archive exists for. You would be trading a readable record for a wall of
 * markers. The second reason is that a credential that short is not really a
 * redaction problem at all; it is a different and worse problem, and quietly
 * scanning for it here would hide it behind the appearance of a fix.
 */
const MIN_SECRET_LENGTH = 8;

/**
 * Collect secrets from an env-shaped object.
 *
 * A variable qualifies if its NAME starts with any of `prefixes` (default
 * `DEFAULT_PREFIXES`) or contains "SECRET" or "TOKEN" anywhere. Matching is on
 * the name only — the value is never inspected to guess whether it "looks like"
 * a credential, because that guess is exactly the kind of heuristic that fails
 * on the one key shaped unlike the others.
 *
 * `env` is a parameter rather than a read of `process.env` so that tests can
 * exercise the selection rules against fixed input, and so that no test run can
 * accidentally pull a real credential out of the developer's environment and
 * into an assertion message.
 */
export function secretsFromEnv(
  env: Record<string, string | undefined>,
  prefixes: string[] = DEFAULT_PREFIXES,
): Secret[] {
  const secrets: Secret[] = [];

  for (const [name, value] of Object.entries(env)) {
    // `undefined` is a variable that is not set; an empty string is a variable
    // set to nothing. Neither is a credential, and both are caught by the
    // length floor below, but the type guard has to come first regardless.
    if (typeof value !== 'string') continue;

    const upper = name.toUpperCase();
    const qualifies =
      prefixes.some((prefix) => upper.startsWith(prefix.toUpperCase())) ||
      NAME_SUBSTRINGS.some((needle) => upper.includes(needle));
    if (!qualifies) continue;

    if (value.length < MIN_SECRET_LENGTH) continue;

    secrets.push({ name, value });
  }

  return secrets;
}

/** One literal string to search for, and the secret name it belongs to. */
interface Needle {
  name: string;
  text: string;
}

/**
 * Scan `input` as UTF-8 text and replace every occurrence of every secret's
 * value with `[REDACTED:<name>]`.
 *
 * "Every occurrence" is meant literally: the match is on the byte-text of the
 * payload, so it is found whether the value sits alone as a JSON string value,
 * inside a longer string, in a key rather than a value, at any nesting depth,
 * or in a fragment of the body that is not JSON at all. Nothing here parses the
 * payload — parsing would restrict matching to the shapes the parser
 * understands, and would also re-serialize the body, which storage.ts is
 * explicit about not wanting.
 *
 * Returns the redacted bytes plus a per-secret hit count, so a caller can log
 * THAT redaction happened and how often. Only names and counts are returned;
 * the values never leave this module, because a "we redacted X" log line that
 * quotes X has moved the credential from the archive into the log.
 */
export function redactBuffer(
  input: Buffer,
  secrets: Secret[],
): { output: Buffer; hits: Array<{ name: string; count: number }> } {
  const needles = compileNeedles(secrets);

  // Nothing to scan for: hand back the input untouched. This is not just an
  // optimisation — decoding to a string and re-encoding is lossy for bytes that
  // are not valid UTF-8 (they come back as U+FFFD), so a no-op pass must be a
  // genuine no-op on the buffer rather than a round-trip through text.
  if (needles.length === 0) {
    return { output: input, hits: [] };
  }

  let text = input.toString('utf8');
  const counts = new Map<string, number>();

  for (const needle of needles) {
    // split/join rather than a RegExp built from the secret. Constructing a
    // pattern out of a credential means escaping it correctly for every
    // metacharacter it might contain, and a single missed escape either throws
    // on a malformed pattern or — worse — silently matches something other than
    // the secret. A literal split has no such failure mode.
    const parts = text.split(needle.text);
    const found = parts.length - 1;
    if (found === 0) continue;

    counts.set(needle.name, (counts.get(needle.name) ?? 0) + found);
    text = parts.join(`[REDACTED:${needle.name}]`);
  }

  // No hit means the bytes are unchanged, so return the original buffer rather
  // than a re-encoded copy — same lossiness argument as the early return above.
  if (counts.size === 0) {
    return { output: input, hits: [] };
  }

  const hits = [...counts].map(([name, count]) => ({ name, count }));
  return { output: Buffer.from(text, 'utf8'), hits };
}

/**
 * Build the ordered list of literal strings to search for.
 *
 * Two things happen here, and both are correctness requirements rather than
 * tuning.
 *
 * 1. JSON-escaped forms. A secret containing `"` or `\` — or a control
 *    character, or anything else JSON escapes — does not appear in serialized
 *    JSON the way it appears in memory: the value `a"b` is written as `a\"b`.
 *    Searching only for the raw form therefore misses precisely the secrets
 *    that required escaping, which is a silent miss: the redaction pass reports
 *    zero hits and the credential is archived in plain sight. So each secret
 *    contributes its raw form AND `JSON.stringify(value)` minus the surrounding
 *    quotes. Both are searched, because the payload may be JSON, may be some
 *    other format, and may contain the value in either shape.
 *
 * 2. Longest first. If one secret's value is a substring of another's — an
 *    "extended" key that begins with the old one, a value and its prefixed
 *    variant — replacing the short one first cuts the long one in half. The
 *    marker lands in the middle of it, the long secret's own pass no longer
 *    matches anything, and the remainder is left on disk: a partial credential,
 *    labelled with the wrong name, that reads as if it had been handled.
 *    Sorting by needle length descending means the longest literal that can
 *    match at a position always wins. (Sorting on the needle rather than on the
 *    secret also keeps a secret's own escaped form — always at least as long as
 *    its raw form — ahead of the raw form, for the same reason.)
 */
function compileNeedles(secrets: Secret[]): Needle[] {
  const needles: Needle[] = [];

  for (const secret of secrets) {
    // An empty value is refused: an empty needle splits the text between every
    // character and would turn the whole payload into markers. Note that the
    // `MIN_SECRET_LENGTH` floor is deliberately NOT applied here. It is a
    // heuristic for `secretsFromEnv`, which guesses at which variables are
    // credentials; a caller who hand-builds a `Secret` has asserted that the
    // value is one, and silently declining to redact it would be the same
    // silent miss this module exists to eliminate.
    if (secret.value.length === 0) continue;

    const escaped = JSON.stringify(secret.value).slice(1, -1);

    needles.push({ name: secret.name, text: secret.value });
    if (escaped !== secret.value) {
      needles.push({ name: secret.name, text: escaped });
    }
  }

  // Stable sort, so two needles of equal length keep the caller's order.
  return needles.sort((a, b) => b.text.length - a.text.length);
}

/**
 * Adapter: turn a set of secrets into the filter storage.ts expects.
 *
 * This is the piece that slots into the seam. `StoreOptions.filter` is typed
 * `(payload: Buffer) => Buffer` and runs before any path is touched, so wiring
 * this in gives the guarantee the seam was built for: the unredacted bytes are
 * never handed to an fs call.
 *
 *   await storePayload({ baseDir, deliveryId, rawBody, filter: makeRedactionFilter(secrets) })
 *
 * The needle list is compiled once per filter rather than per delivery, and hit
 * counts are dropped here because the filter signature has no channel for them
 * — a caller that wants to log redactions should call `redactBuffer` directly.
 */
export function makeRedactionFilter(secrets: Secret[]): (payload: Buffer) => Buffer {
  // Snapshot the secrets at construction time. A filter whose behaviour changes
  // because the caller later mutated the array it passed in would make "was
  // this delivery redacted?" depend on when it arrived.
  const snapshot = secrets.map((secret) => ({ name: secret.name, value: secret.value }));

  return (payload: Buffer): Buffer => redactBuffer(payload, snapshot).output;
}
