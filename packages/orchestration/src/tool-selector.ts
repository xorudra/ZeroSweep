import type { ToolRegistry } from "@dsrclone/security-sdk";
import type { RiskLevel, ToolMetadata } from "@dsrclone/security-sdk";
import type { TargetType } from "@dsrclone/types";
import type { StageDefinition } from "./profiles";

/**
 * Tool Selection Engine (Prompt 4 §9–§10). Adapters are selected by required
 * capability, target compatibility, enabled status, health, risk level and
 * policy — never merely because they are installed. Vendor choice is data
 * (preferences), never hardcoded orchestration logic.
 */

export type AdapterPreference = "PRIMARY" | "SECONDARY" | "FALLBACK";

export interface SelectedAdapter {
  slug: string;
  adapterId: string;
  name: string;
  riskLevel: RiskLevel;
  preference: AdapterPreference;
  /** True when this is a simulation adapter standing in for a real tool that
   *  is not implemented yet — plans and UI must label this honestly. */
  simulation: boolean;
  reason: string;
}

export interface ToolSelectionResult {
  stage: string;
  selected: SelectedAdapter[];
  rejected: { slug: string; reason: string }[];
}

export interface ToolSelectionOptions {
  targetType: TargetType;
  /** Adapter slugs that may execute in this phase/deployment. Anything else
   *  can be PLANNED but never selected for execution. */
  executableSlugs: string[];
  /** slug -> preference override from administrator configuration. */
  preferences?: Record<string, AdapterPreference>;
  /** Health by slug (UNKNOWN treated as not selectable for execution). */
  healthBySlug?: Record<string, string>;
  /** Simulation adapter used when no executable adapter covers a stage.
   *  Defaults to the Mock adapter — this phase executes nothing else. */
  simulationSlug?: string;
}

export function selectAdaptersForStage(
  registry: ToolRegistry,
  stage: StageDefinition,
  options: ToolSelectionOptions,
): ToolSelectionResult {
  const rejected: { slug: string; reason: string }[] = [];
  const candidates: ToolMetadata[] = [];

  const pool = stage.requiredCapabilities.length === 0
    ? []
    : registry.query({ targetType: options.targetType }).filter((a) =>
        stage.requiredCapabilities.every((cap) => a.metadata.capabilities.includes(cap)));

  for (const adapter of pool) {
    const m = adapter.metadata;
    if (!options.executableSlugs.includes(m.slug)) {
      rejected.push({ slug: m.slug, reason: "adapter is catalog metadata only — not executable in this phase" });
      continue;
    }
    const health = options.healthBySlug?.[m.slug] ?? "HEALTHY";
    if (health === "UNAVAILABLE" || health === "MISCONFIGURED") {
      rejected.push({ slug: m.slug, reason: `adapter health is ${health}` });
      continue;
    }
    if (m.riskLevel === "RESTRICTED") {
      rejected.push({ slug: m.slug, reason: "RESTRICTED adapters are never auto-selected" });
      continue;
    }
    candidates.push(m);
  }

  const selected: SelectedAdapter[] = candidates.map((m, i) => ({
    slug: m.slug,
    adapterId: m.id,
    name: m.name,
    riskLevel: m.riskLevel,
    preference: options.preferences?.[m.slug] ?? (i === 0 ? "PRIMARY" : "FALLBACK"),
    simulation: m.executionMode === "MOCK",
    reason: `capability match: ${stage.requiredCapabilities.join(", ")}`,
  }));

  // Platform-internal stages (authorization, normalization, …) need no tool.
  if (stage.requiredCapabilities.length === 0) {
    return { stage: stage.type, selected, rejected };
  }

  // No executable adapter covers this stage yet: fall back to the simulation
  // adapter so the pipeline can be validated end-to-end. Clearly labelled.
  if (selected.length === 0) {
    const simSlug = options.simulationSlug ?? "mock";
    const sim = registry.resolve(simSlug);
    if (sim && sim.metadata.supportedTargetTypes.includes(options.targetType)) {
      selected.push({
        slug: sim.metadata.slug,
        adapterId: sim.metadata.id,
        name: sim.metadata.name,
        riskLevel: sim.metadata.riskLevel,
        preference: "FALLBACK",
        simulation: true,
        reason: "no executable adapter implements this stage yet — simulation adapter validates the pipeline",
      });
    }
  }
  return { stage: stage.type, selected, rejected };
}
