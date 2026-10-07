import { CAPABILITIES, FORBIDDEN_INPUT_FIELDS, TOOL_CATEGORIES, type ToolMetadata } from "../adapter/adapter.types";
import { InvalidAdapterMetadataError } from "../adapter/adapter.errors";

const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/**
 * Metadata validation run at registration time (Prompt 3 §19). A registry
 * that accepts garbage metadata would let the orchestrator select tools it
 * knows nothing about — so registration fails loudly instead.
 */
export function validateAdapterMetadata(m: ToolMetadata): void {
  const fail = (msg: string): never => { throw new InvalidAdapterMetadataError(`${m?.slug ?? "<unknown>"}: ${msg}`); };
  if (!m || typeof m !== "object") fail("metadata missing");
  if (!m.id) fail("id is required");
  if (!SLUG_RE.test(m.slug ?? "")) fail("slug must be lowercase kebab-case");
  if (!m.name) fail("name is required");
  if (!m.description) fail("description is required");
  if (!TOOL_CATEGORIES.includes(m.category)) fail(`unknown category ${String(m.category)}`);
  if (!m.adapterVersion) fail("adapterVersion is required");
  if (!Array.isArray(m.supportedTargetTypes) || m.supportedTargetTypes.length === 0) fail("supportedTargetTypes must be non-empty");
  if (!Array.isArray(m.capabilities)) fail("capabilities must be an array");
  for (const c of m.capabilities) if (!CAPABILITIES.includes(c)) fail(`unknown capability ${String(c)}`);
  if (!(m.defaultTimeoutSeconds > 0)) fail("defaultTimeoutSeconds must be > 0");
  if (m.maxTimeoutSeconds < m.defaultTimeoutSeconds) fail("maxTimeoutSeconds must be >= defaultTimeoutSeconds");
  for (const f of m.inputSchema ?? []) {
    if (FORBIDDEN_INPUT_FIELDS.includes(f.name as never)) fail(`input field "${f.name}" is forbidden — adapters never accept raw commands`);
    if (!f.name) fail("input field name is required");
  }
  if (m.riskLevel === "RESTRICTED" && !m.requiresApproval) fail("RESTRICTED tools must require approval");
}
