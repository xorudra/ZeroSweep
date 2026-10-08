import type { ScheduleFrequency } from "./types";

/**
 * Governed cron-like schedule expressions (Prompt 22 §6/§12/§14).
 *
 * A deliberately SMALL, validated subset of cron: five fields
 * (minute hour day-of-month month day-of-week) with `*`, lists, ranges
 * and steps. No seconds field, no @-macros, no names — anything outside
 * the grammar is a validation error, never a silent fallback. Times are
 * evaluated in the schedule's own IANA timezone (§14), never the
 * server's.
 */

export interface CronField {
  values: Set<number>;
  restricted: boolean;
}

export interface ParsedCron {
  minute: CronField;
  hour: CronField;
  dayOfMonth: CronField;
  month: CronField;
  dayOfWeek: CronField;
  expression: string;
}

const FIELD_RANGES: Array<{ min: number; max: number; label: string }> = [
  { min: 0, max: 59, label: "minute" },
  { min: 0, max: 23, label: "hour" },
  { min: 1, max: 31, label: "day-of-month" },
  { min: 1, max: 12, label: "month" },
  { min: 0, max: 7, label: "day-of-week" },
];

function parseField(raw: string, range: { min: number; max: number; label: string }): CronField {
  const values = new Set<number>();
  if (!raw) throw new Error(`cron ${range.label} field is empty`);
  for (const part of raw.split(",")) {
    const stepMatch = /^(.+)\/(\d+)$/.exec(part);
    const base = stepMatch ? stepMatch[1]! : part;
    const step = stepMatch ? Number(stepMatch[2]) : 1;
    if (!Number.isInteger(step) || step < 1) throw new Error(`cron ${range.label}: invalid step in "${part}"`);
    let lo: number; let hi: number;
    if (base === "*") { lo = range.min; hi = range.max; }
    else if (/^\d+$/.test(base)) { lo = Number(base); hi = stepMatch ? range.max : lo; }
    else if (/^\d+-\d+$/.test(base)) { const [a, b] = base.split("-").map(Number); lo = a!; hi = b!; }
    else throw new Error(`cron ${range.label}: unsupported token "${part}"`);
    if (lo < range.min || hi > range.max || lo > hi) {
      throw new Error(`cron ${range.label}: value out of range ${range.min}-${range.max} in "${part}"`);
    }
    for (let v = lo; v <= hi; v += step) values.add(range.label === "day-of-week" && v === 7 ? 0 : v);
  }
  return { values, restricted: raw !== "*" };
}

export function parseCron(expression: string): ParsedCron {
  const fields = expression.trim().split(/\s+/);
  if (fields.length !== 5) {
    throw new Error(`cron expression must have exactly 5 fields (minute hour day-of-month month day-of-week), got ${fields.length}`);
  }
  const [minute, hour, dayOfMonth, month, dayOfWeek] = fields.map((f, i) => parseField(f, FIELD_RANGES[i]!));
  return { minute: minute!, hour: hour!, dayOfMonth: dayOfMonth!, month: month!, dayOfWeek: dayOfWeek!, expression: expression.trim() };
}

export function validateCronExpression(expression: string): string[] {
  try { parseCron(expression); return []; } catch (e) { return [e instanceof Error ? e.message : "invalid cron expression"]; }
}

export function isValidTimezone(timezone: string): boolean {
  try { new Intl.DateTimeFormat("en-US", { timeZone: timezone }); return true; } catch { return false; }
}

/** Default expressions for the named frequencies (§12). */
export function expressionForFrequency(frequency: ScheduleFrequency, custom?: string): string {
  switch (frequency) {
    case "HOURLY": return "0 * * * *";
    case "DAILY": return "0 2 * * *";
    case "WEEKLY": return "0 2 * * 1";
    case "MONTHLY": return "0 2 1 * *";
    case "CUSTOM":
      if (!custom) throw new Error("CUSTOM frequency requires a cron expression");
      return custom;
  }
}

const WEEKDAY_INDEX: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };

interface ZonedParts { minute: number; hour: number; day: number; month: number; weekday: number }

function zonedParts(instant: Date, timezone: string, cache: Map<string, Intl.DateTimeFormat>): ZonedParts {
  let fmt = cache.get(timezone);
  if (!fmt) {
    fmt = new Intl.DateTimeFormat("en-US", {
      timeZone: timezone, minute: "numeric", hour: "numeric", day: "numeric", month: "numeric", weekday: "short", hour12: false,
    });
    cache.set(timezone, fmt);
  }
  const parts = fmt.formatToParts(instant);
  const get = (t: string) => parts.find((p) => p.type === t)?.value ?? "";
  return {
    minute: Number(get("minute")),
    hour: Number(get("hour")) % 24,
    day: Number(get("day")),
    month: Number(get("month")),
    weekday: WEEKDAY_INDEX[get("weekday")] ?? 0,
  };
}

function cronMatches(parsed: ParsedCron, parts: ZonedParts): boolean {
  if (!parsed.minute.values.has(parts.minute)) return false;
  if (!parsed.hour.values.has(parts.hour)) return false;
  if (!parsed.month.values.has(parts.month)) return false;
  const domMatch = parsed.dayOfMonth.values.has(parts.day);
  const dowMatch = parsed.dayOfWeek.values.has(parts.weekday);
  // Vixie-cron semantics: when BOTH day fields are restricted a match
  // on either is enough; otherwise both must match.
  if (parsed.dayOfMonth.restricted && parsed.dayOfWeek.restricted) return domMatch || dowMatch;
  return domMatch && dowMatch;
}

const MAX_MINUTE_STEPS = 1_100_000; // ≈ 2 years of minutes — hard search bound.

/**
 * Next fire instant strictly AFTER `from`, evaluated in `timezone`.
 * Returns null when no fire exists within the search bound.
 */
export function nextCronRun(expression: string, timezone: string, from: Date): Date | null {
  const parsed = parseCron(expression);
  const cache = new Map<string, Intl.DateTimeFormat>();
  const cursor = new Date(from.getTime());
  cursor.setSeconds(0, 0);
  cursor.setMinutes(cursor.getMinutes() + 1);
  for (let i = 0; i < MAX_MINUTE_STEPS; i++) {
    if (cronMatches(parsed, zonedParts(cursor, timezone, cache))) return new Date(cursor.getTime());
    cursor.setMinutes(cursor.getMinutes() + 1);
  }
  return null;
}

/** Consecutive fire instants after `from` (at most `count`). */
export function nextCronRuns(expression: string, timezone: string, from: Date, count: number): Date[] {
  const out: Date[] = [];
  let cursor = from;
  for (let i = 0; i < count; i++) {
    const next = nextCronRun(expression, timezone, cursor);
    if (!next) break;
    out.push(next);
    cursor = next;
  }
  return out;
}

/**
 * Smallest gap between consecutive fires, sampled over the first
 * `samples` runs from a fixed epoch. Used by the frequency guardrail
 * (§13): `* * * * *` yields 1 minute and is refused for real scans.
 */
export function minCronIntervalMinutes(expression: string, timezone: string, samples = 40): number | null {
  const runs = nextCronRuns(expression, timezone, new Date(Date.UTC(2026, 0, 1, 0, 0, 0)), samples);
  if (runs.length < 2) return null;
  let min = Number.POSITIVE_INFINITY;
  for (let i = 1; i < runs.length; i++) {
    min = Math.min(min, (runs[i]!.getTime() - runs[i - 1]!.getTime()) / 60_000);
  }
  return Math.round(min);
}
