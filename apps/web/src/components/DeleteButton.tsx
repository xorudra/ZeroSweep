"use client";

import { useEffect, useRef, useState } from "react";

/**
 * Delete button after Rare UI's delete button (rareui.com, MIT + Commons
 * Clause — a visible credit to rareui.com ships with it on the targets
 * page), adapted to the owner's interaction spec (2026-10-25):
 * click the bin and it DISAPPEARS — Tick and Cross take its place.
 * Cross (or Escape) brings the bin back. Tick confirms: a green check
 * draws where the bin was, then onDeleted fires so the parent can
 * remove the row. No dialog, no accidental deletes.
 */

type State = "rest" | "open" | "confirming" | "done";

function BinIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden>
      <g>
        <path d="M4 6h14" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
        <path d="M9 6V4.5A1.5 1.5 0 0 1 10.5 3h1A1.5 1.5 0 0 1 13 4.5V6" stroke="currentColor" strokeWidth="1.8" />
      </g>
      <path d="M5.5 6h11l-1 13a2 2 0 0 1-2 1.8H8.5a2 2 0 0 1-2-1.8l-1-13Z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
      <path d="M9.5 9.5v6M12.5 9.5v6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none" aria-hidden>
      <path d="M2 7.5 5.5 11 12 3.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function CrossIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 12 12" fill="none" aria-hidden>
      <path d="M2 2l8 8M10 2l-8 8" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

export function DeleteButton({
  label, onConfirm, onDeleted, onError,
}: {
  label: string;
  onConfirm: () => Promise<void>;
  onDeleted?: () => void;
  onError?: (message: string) => void;
}) {
  const [state, setState] = useState<State>("rest");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (state !== "open") return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setState("rest"); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [state]);

  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  async function confirm() {
    setState("confirming");
    try {
      await onConfirm();
      setState("done");
      timer.current = setTimeout(() => onDeleted?.(), 600);
    } catch (err) {
      setState("rest");
      onError?.(err instanceof Error ? err.message : "Could not delete. Please try again.");
    }
  }

  if (state === "done") {
    return (
      <span className="inline-flex items-center text-[#1e7b4f]" aria-label={`${label} deleted`}>
        <svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden>
          <path d="M4 12.5 9.5 18 18 6.5" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </span>
    );
  }

  if (state === "open" || state === "confirming") {
    const disabled = state === "confirming";
    return (
      <span className="inline-flex items-center gap-1.5" role="group" aria-label={`Confirm deleting ${label}`}>
        <button type="button" disabled={disabled} onClick={confirm} aria-label={`Confirm deleting ${label}`}
          className="flex h-[26px] w-[26px] items-center justify-center rounded-full border border-[#1e7b4f] bg-white text-[#1e7b4f] transition-opacity disabled:opacity-50">
          <CheckIcon />
        </button>
        <button type="button" disabled={disabled} onClick={() => setState("rest")} aria-label="Cancel delete"
          className="flex h-[26px] w-[26px] items-center justify-center rounded-full border border-[#e8eaec] bg-white text-[#5d5f60] transition-opacity disabled:opacity-50">
          <CrossIcon />
        </button>
      </span>
    );
  }

  return (
    <button type="button" onClick={() => setState("open")} aria-label={`Delete ${label}`} title={`Delete ${label}`}
      className="inline-flex items-center p-1 text-[#131416] transition-colors hover:text-[#c4242a]">
      <BinIcon />
    </button>
  );
}
