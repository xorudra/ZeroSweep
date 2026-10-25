#!/usr/bin/env node
/**
 * Tool documentation generator (Prompt 40 §157/§158): renders
 * docs/tools/<slug>.md + index from the SEEDED tool catalog in the
 * database — the registry is the source of truth, so docs can never
 * drift from what the platform actually knows. Each page documents
 * purpose, category, license, installation model, worker requirement,
 * input/output and availability. NO offensive playbooks are generated
 * (§158): intrusive/restricted tools document governance only.
 *
 * Usage: DATABASE_URL=... node scripts/docs/generate-tool-docs.mjs
 */
import { createRequire } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

// @prisma/client lives in the database package's dependency tree.
const require = createRequire(new URL("../../packages/database/package.json", import.meta.url));
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();
const outDir = resolve(process.cwd(), "docs/tools");
mkdirSync(outDir, { recursive: true });

const tools = await prisma.tool.findMany({ orderBy: { slug: "asc" }, include: { adapters: true } });
const index = ["# Tool Documentation", "", "Generated from the ZeroSweep Tool Registry (seeded catalog). Regenerate with `node scripts/docs/generate-tool-docs.mjs`.", "", "| Tool | Category | License | Risk | Availability |", "|---|---|---|---|---|"];

for (const tool of tools) {
  const adapter = tool.adapters?.[0];
  const availability = !tool.installed ? "NOT_CONFIGURED" : tool.healthStatus === "HEALTHY" ? "CONFIGURED" : "UNAVAILABLE";
  index.push(`| [${tool.name}](${tool.slug}.md) | ${tool.category} | ${tool.licenseType} | ${tool.riskLevel} | ${availability} |`);
  const commercial = tool.licenseType === "COMMERCIAL" || tool.licenseType === "ADMIN_PROVIDED";
  const lines = [
    `# ${tool.name}`,
    "",
    tool.description ?? "",
    "",
    `- **Slug:** \`${tool.slug}\``,
    `- **Category:** ${tool.category}`,
    `- **License:** ${tool.licenseType}${commercial ? " — customer/administrator-supplied license required; ZeroSweep never bundles commercial licenses (§122–§126)" : ""}`,
    `- **Risk level:** ${tool.riskLevel}`,
    `- **Requires approval:** ${tool.requiresApproval ? "yes" : "no"}`,
    `- **Availability:** ${availability}`,
    "",
    "## Installation",
    "",
    commercial
      ? "Installed and licensed by the customer/administrator in their own environment; ZeroSweep connects through its governed adapter only when configured."
      : "Provided through the platform's isolated worker images or the governed adapter runtime; a missing binary reports UNAVAILABLE honestly.",
    "",
    "## Worker requirement",
    "",
    adapter ? `Execution mode: ${adapter.executionMode}; network policy: ${adapter.networkPolicy}; default timeout: ${adapter.defaultTimeout}s.` : "No adapter registered.",
    "",
    "## Input / Output",
    "",
    adapter
      ? `Supported targets: ${(adapter.supportedTargets ?? []).join(", ") || "—"}. Capabilities: ${(adapter.capabilities ?? []).join(", ") || "—"}. Output format: ${adapter.outputFormat}; parser: ${adapter.parser}. Outputs are normalized into the platform finding model by the adapter — raw tool output is never presented as a finding.`
      : "No adapter input/output contract registered.",
    "",
    "## Governance",
    "",
    "Execution always requires a verified target, an approved assessment, in-scope assets and policy clearance. Intrusive/exploit-class capabilities remain policy-excluded regardless of plan or license (§16).",
    "",
  ];
  writeFileSync(resolve(outDir, `${tool.slug}.md`), lines.join("\n"));
}

writeFileSync(resolve(outDir, "index.md"), index.join("\n") + "\n");
console.log(`Generated ${tools.length} tool docs in docs/tools/`);
await prisma.$disconnect();
