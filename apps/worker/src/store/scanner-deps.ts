import { prisma } from "@dsrclone/database";
import {
  EnvEndpointResolver, EnvSecretResolver, HttpScannerTransport,
  type ConnectorDeps, type ScannerInstanceProvider, type ScannerInstanceRecord,
  type ScannerProduct, type SessionProfileProvider, type SessionProfileRecord,
} from "@dsrclone/security-sdk";

/**
 * Prisma-backed connector dependencies for the production worker
 * (Prompt 8 §15–§17): scanner instances are read from the ScannerInstance
 * table (admin-registered metadata only), endpoints resolve from server
 * configuration (DSRCLONE_SCANNER_ENDPOINTS), and secrets resolve from the
 * worker's environment by reference name. No secret value is ever loaded
 * into a record, a log line or a queue payload.
 */

const SLUG_BY_PRODUCT: Record<ScannerProduct, string> = {
  ZAP: "owasp-zap", BURP: "burp-suite-professional", CAIDO: "caido",
};

type InstanceRow = {
  id: string; organizationId: string; workspaceId: string | null; name: string;
  endpointReference: string; deploymentType: string; credentialReference: string | null;
  declaredCapabilities: unknown; detectedCapabilities: unknown; healthStatus: string;
  version: string | null; licenseState: string | null; enabled: boolean; createdBy: string;
  createdAt: Date; updatedAt: Date; tool: { slug: string };
};

function toRecord(row: InstanceRow): ScannerInstanceRecord {
  const product = (Object.entries(SLUG_BY_PRODUCT).find(([, slug]) => slug === row.tool.slug)?.[0] ?? "ZAP") as ScannerProduct;
  return {
    id: row.id,
    organizationId: row.organizationId,
    ...(row.workspaceId ? { workspaceId: row.workspaceId } : {}),
    toolSlug: row.tool.slug,
    product,
    name: row.name,
    endpointReference: row.endpointReference,
    deploymentType: row.deploymentType as ScannerInstanceRecord["deploymentType"],
    ...(row.credentialReference ? { credentialReference: row.credentialReference } : {}),
    declaredCapabilities: (Array.isArray(row.declaredCapabilities) ? row.declaredCapabilities : []) as ScannerInstanceRecord["declaredCapabilities"],
    detectedCapabilities: (Array.isArray(row.detectedCapabilities) ? row.detectedCapabilities : []) as ScannerInstanceRecord["detectedCapabilities"],
    healthStatus: row.healthStatus as ScannerInstanceRecord["healthStatus"],
    ...(row.version ? { version: row.version } : {}),
    ...(row.licenseState ? { licenseState: row.licenseState } : {}),
    enabled: row.enabled,
    createdBy: row.createdBy,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export class PrismaScannerInstanceProvider implements ScannerInstanceProvider {
  /** Plan-time snapshots are synchronous by contract; the cache is
   *  refreshed by every async read this provider performs. */
  private cache: ScannerInstanceRecord[] = [];

  private remember(records: ScannerInstanceRecord[]): void {
    for (const r of records) {
      const idx = this.cache.findIndex((c) => c.id === r.id);
      if (idx >= 0) this.cache[idx] = r; else this.cache.push(r);
    }
  }

  async listEnabled(product: ScannerProduct): Promise<ScannerInstanceRecord[]> {
    const rows = await prisma.scannerInstance.findMany({
      where: { enabled: true, tool: { slug: SLUG_BY_PRODUCT[product] } },
      include: { tool: { select: { slug: true } } },
      orderBy: { createdAt: "asc" },
    });
    const records = (rows as unknown as InstanceRow[]).map(toRecord);
    this.remember(records);
    return records;
  }

  async getById(id: string): Promise<ScannerInstanceRecord | null> {
    const row = await prisma.scannerInstance.findUnique({
      where: { id },
      include: { tool: { select: { slug: true } } },
    });
    const record = row ? toRecord(row as unknown as InstanceRow) : null;
    if (record) this.remember([record]);
    return record;
  }

  snapshot(): ScannerInstanceRecord[] {
    return [...this.cache];
  }
}

export class PrismaSessionProfileProvider implements SessionProfileProvider {
  async getById(id: string): Promise<SessionProfileRecord | null> {
    const row = await prisma.sessionProfile.findUnique({ where: { id } });
    if (!row) return null;
    return {
      id: row.id,
      workspaceId: row.workspaceId,
      name: row.name,
      type: row.type as SessionProfileRecord["type"],
      ...(row.credentialReference ? { credentialReference: row.credentialReference } : {}),
      ...(row.cookiePolicy ? { cookiePolicy: row.cookiePolicy as SessionProfileRecord["cookiePolicy"] } : {}),
      ...(row.headerPolicy ? { headerPolicy: row.headerPolicy as SessionProfileRecord["headerPolicy"] } : {}),
      ...(row.validation ? { validation: row.validation as SessionProfileRecord["validation"] } : {}),
      createdBy: row.createdBy,
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
    };
  }
}

/** Production connector dependencies for the worker process. */
export function prismaScannerDeps(): ConnectorDeps {
  return {
    instances: new PrismaScannerInstanceProvider(),
    endpoints: new EnvEndpointResolver(),
    secrets: new EnvSecretResolver(),
    sessions: new PrismaSessionProfileProvider(),
    transport: new HttpScannerTransport(),
  };
}
