import type { BlackoutWindowDef, MaintenanceWindowDef } from "./types";

/**
 * Maintenance & blackout windows (Prompt 22 §15/§16/§101). Scheduled
 * jobs must respect both. A blackout DEFERS the run to the blackout
 * end (the missed-run policy then decides whether it still fires); a
 * maintenance window that excludes the instant defers to the next
 * allowed instant, bounded by the caller's catch-up logic.
 */

export interface WindowEvaluation {
  allowed: boolean;
  reasonCode: "OK" | "BLACKOUT" | "OUTSIDE_MAINTENANCE" | "INSIDE_BLOCKED_HOURS";
  message: string;
  /** When blocked, the earliest instant worth re-checking. */
  deferredUntil?: Date;
  blackoutReason?: string;
}

function zonedClock(instant: Date, timezone: string): { weekday: number; minutes: number } {
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone: timezone, weekday: "short", hour: "numeric", minute: "numeric", hour12: false,
  });
  const parts = fmt.formatToParts(instant);
  const get = (t: string) => parts.find((p) => p.type === t)?.value ?? "";
  const weekdayMap: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  return {
    weekday: weekdayMap[get("weekday")] ?? 0,
    minutes: (Number(get("hour")) % 24) * 60 + Number(get("minute")),
  };
}

function parseTime(value: string): number {
  const m = /^(\d{2}):(\d{2})$/.exec(value);
  if (!m) throw new Error(`invalid HH:MM time "${value}"`);
  const h = Number(m[1]); const min = Number(m[2]);
  if (h > 23 || min > 59) throw new Error(`invalid HH:MM time "${value}"`);
  return h * 60 + min;
}

/** Is `minutes` (local, 0-1439) inside [start,end)? Handles overnight
 *  windows where start > end (e.g. 22:00–06:00). */
function insideWindow(minutes: number, start: number, end: number): boolean {
  if (start === end) return true; // full day
  if (start < end) return minutes >= start && minutes < end;
  return minutes >= start || minutes < end;
}

export function evaluateWindows(
  instant: Date,
  maintenance: MaintenanceWindowDef[],
  blackouts: BlackoutWindowDef[],
): WindowEvaluation {
  for (const b of blackouts) {
    const start = new Date(b.startsAt).getTime();
    const end = new Date(b.endsAt).getTime();
    if (instant.getTime() >= start && instant.getTime() < end) {
      return {
        allowed: false, reasonCode: "BLACKOUT",
        message: `inside blackout window${b.reason ? ` (${b.reason})` : ""} — scheduled runs are deferred (§16)`,
        deferredUntil: new Date(end),
        ...(b.reason ? { blackoutReason: b.reason } : {}),
      };
    }
  }
  for (const w of maintenance) {
    const clock = zonedClock(instant, w.timezone);
    const dayMatches = w.daysOfWeek.length === 0 || w.daysOfWeek.includes(clock.weekday);
    const inside = dayMatches && insideWindow(clock.minutes, parseTime(w.startTime), parseTime(w.endTime));
    if (w.mode === "ALLOWED_HOURS" && !inside) {
      return {
        allowed: false, reasonCode: "OUTSIDE_MAINTENANCE",
        message: `outside the allowed maintenance window (${w.startTime}–${w.endTime} ${w.timezone}) (§15)`,
      };
    }
    if (w.mode === "BLOCKED_HOURS" && inside) {
      return {
        allowed: false, reasonCode: "INSIDE_BLOCKED_HOURS",
        message: `inside blocked scan hours (${w.startTime}–${w.endTime} ${w.timezone}) (§15)`,
      };
    }
  }
  return { allowed: true, reasonCode: "OK", message: "within all windows" };
}

export function validateMaintenanceWindow(w: MaintenanceWindowDef): string[] {
  const errors: string[] = [];
  try { parseTime(w.startTime); } catch (e) { errors.push(e instanceof Error ? e.message : "bad startTime"); }
  try { parseTime(w.endTime); } catch (e) { errors.push(e instanceof Error ? e.message : "bad endTime"); }
  for (const d of w.daysOfWeek) if (!Number.isInteger(d) || d < 0 || d > 6) errors.push(`dayOfWeek ${d} out of range 0-6`);
  try { new Intl.DateTimeFormat("en-US", { timeZone: w.timezone }); } catch { errors.push(`unknown timezone "${w.timezone}"`); }
  return errors;
}

export function validateBlackoutWindow(b: BlackoutWindowDef): string[] {
  const errors: string[] = [];
  const start = new Date(b.startsAt).getTime();
  const end = new Date(b.endsAt).getTime();
  if (Number.isNaN(start) || Number.isNaN(end)) errors.push("blackout window has an invalid date");
  else if (end <= start) errors.push("blackout end must be after start");
  return errors;
}
