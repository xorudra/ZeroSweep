import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

/**
 * Tool catalog seed — metadata entries for the tools DSRclone will integrate
 * through adapters in later phases. No commands are stored or executed.
 * Commercial tools are marked ADMIN_PROVIDED: the administrator supplies the
 * installation/license; DSRclone does not redistribute them.
 */
const TOOLS: Array<{
  slug: string; name: string; category: "RECON" | "WEB" | "NETWORK" | "API" | "MOBILE" | "CLOUD" | "CONTAINER" | "SOURCE_CODE" | "BINARY" | "WIRELESS" | "REPORTING";
  riskLevel: "PASSIVE" | "LOW" | "MODERATE" | "INTRUSIVE" | "RESTRICTED";
  licenseType: "OPEN_SOURCE" | "COMMERCIAL" | "EXTERNAL_API" | "ADMIN_PROVIDED";
  requiresApproval?: boolean;
}> = [
  { slug: "subfinder", name: "Subfinder", category: "RECON", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE" },
  { slug: "amass", name: "Amass", category: "RECON", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE" },
  { slug: "httpx", name: "httpx", category: "RECON", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
  { slug: "naabu", name: "Naabu", category: "RECON", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
  { slug: "nuclei", name: "Nuclei", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE" },
  { slug: "katana", name: "Katana", category: "WEB", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
  { slug: "ffuf", name: "ffuf", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE" },
  { slug: "owasp-zap", name: "OWASP ZAP", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE" },
  { slug: "nikto", name: "Nikto", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE" },
  { slug: "whatweb", name: "WhatWeb", category: "WEB", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
  { slug: "wpscan", name: "WPScan", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE" },
  { slug: "testssl", name: "testssl.sh", category: "WEB", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
  { slug: "burp-suite-professional", name: "Burp Suite Professional", category: "WEB", riskLevel: "MODERATE", licenseType: "ADMIN_PROVIDED", requiresApproval: true },
  { slug: "nmap", name: "Nmap", category: "NETWORK", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
  { slug: "rustscan", name: "RustScan", category: "NETWORK", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
  { slug: "masscan", name: "Masscan", category: "NETWORK", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE" },
  { slug: "nessus-professional", name: "Nessus Professional", category: "NETWORK", riskLevel: "MODERATE", licenseType: "ADMIN_PROVIDED", requiresApproval: true },
  { slug: "schemathesis", name: "Schemathesis", category: "API", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE" },
  { slug: "jwt-tool", name: "jwt_tool", category: "API", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE" },
  { slug: "trivy", name: "Trivy", category: "CONTAINER", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
  { slug: "grype", name: "Grype", category: "CONTAINER", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
  { slug: "checkov", name: "Checkov", category: "CLOUD", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
  { slug: "prowler", name: "Prowler", category: "CLOUD", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true },
  { slug: "semgrep", name: "Semgrep", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
  { slug: "gitleaks", name: "Gitleaks", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
  { slug: "mobsf", name: "MobSF", category: "MOBILE", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
  { slug: "ghidra", name: "Ghidra", category: "BINARY", riskLevel: "LOW", licenseType: "OPEN_SOURCE" },
];

async function main(): Promise<void> {
  for (const t of TOOLS) {
    await prisma.tool.upsert({
      where: { slug: t.slug },
      update: { name: t.name, category: t.category, riskLevel: t.riskLevel, licenseType: t.licenseType, requiresApproval: t.requiresApproval ?? false },
      create: { slug: t.slug, name: t.name, category: t.category, riskLevel: t.riskLevel, licenseType: t.licenseType, requiresApproval: t.requiresApproval ?? false },
    });
  }
  // The one adapter that exists in this phase: the safe mock.
  const mock = await prisma.tool.upsert({
    where: { slug: "mock" },
    update: {},
    create: {
      slug: "mock", name: "Mock Security Adapter (TEST ONLY)", category: "REPORTING",
      description: "Exercises the pipeline end-to-end. Performs no network activity and produces no findings.",
      riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", installed: true, healthStatus: "HEALTHY",
    },
  });
  await prisma.toolAdapter.upsert({
    where: { toolId_adapterVersion: { toolId: mock.id, adapterVersion: "1.0.0" } },
    update: {},
    create: {
      toolId: mock.id, adapterVersion: "1.0.0", executionMode: "MOCK",
      supportedTargets: ["DOMAIN", "WEB_APPLICATION"], capabilities: [], outputFormat: "JSON",
      parser: "json", defaultTimeout: 5, networkPolicy: "NO_NETWORK",
    },
  });
  console.log(`Seeded ${TOOLS.length + 1} tool catalog entries (metadata only)`);
}

main().catch((e) => { console.error(e); process.exit(1); }).finally(() => prisma.$disconnect());
