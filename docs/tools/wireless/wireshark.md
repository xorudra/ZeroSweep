# Wireshark — analyst tool (Prompt 19 §25)

Wireshark is registered as an **ANALYST_TOOL**: a GUI application for
human analysts on their own workstations. It never executes in the
ZeroSweep pipeline, has no adapter, and appears in tool health only with
its governed non-executing state.

Backend automation for capture analysis uses **tshark** with a fixed
platform field set (see tshark.md) — the same dissectors, a governed
surface.
