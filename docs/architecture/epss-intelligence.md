# EPSS Intelligence (Prompt 30 §19–§22)

- EPSS points live in `EpssRecord` keyed by (cveId, date): history is **append-only** — a new day adds a point, it never overwrites an earlier one (§20, verified by test at both SDK and API level).
- The current value is the latest dated point; trend = current vs previous point. A material change is |Δ| ≥ 0.1 or crossing the 0.5 line (§22).
- Freshness: a latest point older than 7 days is `STALE` — displayed with its date, never hidden and never silently treated as current (§21).
- **Absence is null.** A CVE with no EPSS record shows "absent" in every surface (API returns `epss: null`, the copilot says no value is stored). EPSS is never defaulted to 0 anywhere in the pipeline.
- EPSS is a probability signal for prioritization — it never changes severity, and the EPSS console states this on the page.
