/*
 * Executable wrapper around the audit module.
 *
 * Split from audit.ts on purpose. Everything that decides what may be shown
 * lives there and is a pure function of (path, bytes, allowlist) — which means
 * the guarantee "withheld content never reaches the output" is testable by
 * calling a function and inspecting its return value, with no process to spawn
 * and no stdout to scrape. What is left here is argument parsing and printing:
 * the part that has no security decisions in it, precisely because the part
 * that does was moved out.
 *
 * Usage:
 *   npx tsx src/audit-cli.ts <baseDir> <YYYY-MM-DD>
 *   npm run build && node dist/audit-cli.js <baseDir> <YYYY-MM-DD>
 *
 * Not `node --experimental-strip-types src/audit-cli.ts`: Node's type stripping
 * removes types but does not rewrite module specifiers, and this repo writes
 * them the way `nodenext` wants for compiled output — `./audit.js`, resolving to
 * `dist/audit.js` after a build. Node asked to run the .ts file directly looks
 * for a `src/audit.js` that does not exist. tsx does the rewrite; tsc produces
 * the file. Both are above.
 */

import { runAudit, type AuditView } from './audit.js';

const USAGE =
  'usage: npx tsx src/audit-cli.ts <baseDir> <YYYY-MM-DD>\n' +
  '       node dist/audit-cli.js <baseDir> <YYYY-MM-DD>   (after npm run build)\n' +
  '\n' +
  'Prints allowlisted fields of the webhook payloads archived on one UTC day.\n' +
  'Fields outside the allowlist are withheld and reported only as a count.';

/** `withheldCount` sentinel from audit.ts for a file that is not a JSON object. */
const WITHHELD_UNPARSEABLE = -1;

/** `YYYY-MM-DD`, matching the UTC partition layout storage.ts writes. */
const DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;

async function main(): Promise<void> {
  // argv[0] is the executable and argv[1] this script; the user's args follow.
  const args = process.argv.slice(2);

  if (args.length !== 2) {
    fail('expected exactly two arguments');
  }

  const baseDir = args[0] as string;
  const dateUtc = parseDate(args[1] as string);

  const views = await runAudit(baseDir, dateUtc);

  // The "nothing archived that day" note goes to stderr, so that piping stdout
  // into another tool yields payload output or nothing at all.
  if (views.length === 0) {
    process.stderr.write(`no payloads archived under ${baseDir} on ${args[1]}\n`);
    return;
  }

  for (const view of views) {
    process.stdout.write(render(view));
  }
}

/**
 * Render one view.
 *
 * Only fields the audit already approved are printed. Nothing here reaches back
 * into the payload, so this function cannot widen what audit.ts decided to
 * disclose — it can only format it.
 */
function render(view: AuditView): string {
  const lines = [view.path, view.deliveryId];

  for (const [key, value] of Object.entries(view.shown)) {
    lines.push(`${key}: ${value}`);
  }

  lines.push(
    view.withheldCount === WITHHELD_UNPARSEABLE
      ? '(unparseable)'
      : `(${view.withheldCount} fields withheld)`,
  );

  // Blank line between views, so consecutive payloads stay visually separate.
  return lines.join('\n') + '\n\n';
}

/** Parse `YYYY-MM-DD` into the UTC parts `runAudit` expects. */
function parseDate(text: string): { year: number; month: number; day: number } {
  const match = DATE_PATTERN.exec(text);
  if (match === null) {
    fail(`expected a date as YYYY-MM-DD, got ${JSON.stringify(text)}`);
  }

  const [, year, month, day] = match;
  return { year: Number(year), month: Number(month), day: Number(day) };
}

/**
 * Print the reason and the usage to stderr, then exit non-zero.
 *
 * Declared as returning `never` so callers can use it as a terminator without
 * the type checker still believing the parsed values might be undefined.
 */
function fail(reason: string): never {
  process.stderr.write(`audit: ${reason}\n\n${USAGE}\n`);
  process.exit(1);
}

// Entry point. Top-level await: the wrapper's whole body is this one call.
await main();
