import { z } from "zod";

export const workspaceQuerySchema = z.object({ workspaceId: z.string().uuid().optional() }).passthrough();

export const dateRangeSchema = z.object({
  days: z.coerce.number().int().min(1).max(365).default(90),
}).passthrough();

export const searchRequestSchema = z.object({
  query: z.string().max(512).default(""),
  filters: z.record(z.unknown()).optional(),
  sort: z.enum(["relevance", "risk", "severity", "recent", "oldest", "criticality"]).default("relevance"),
  cursor: z.string().max(256).optional(),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  group: z.coerce.boolean().default(false),
});

export const savedQuerySchema = z.object({
  name: z.string().min(1).max(120),
  queryText: z.string().min(1).max(512),
  filters: z.record(z.unknown()).optional(),
  visibility: z.enum(["PRIVATE", "WORKSPACE"]).default("PRIVATE"),
});

export const ingestBatchSchema = z.object({
  events: z.array(z.record(z.unknown())).min(1).max(500),
});

export const exportSchema = z.object({
  kind: z.enum(["SEARCH", "VIEW"]),
  query: z.string().max(512).optional(),
  view: z.enum(["OVERVIEW", "FINDINGS", "ASSETS", "ATTACK_SURFACE", "RISK", "DEVSECOPS", "CLOUD", "IDENTITY", "GRC"]).optional(),
  format: z.enum(["CSV", "JSON"]).default("JSON"),
});

export const aiAskSchema = z.object({ question: z.string().min(3).max(500) });

export const retentionPolicySchema = z.object({
  eventRetentionDays: z.number().int().min(30).max(3650).optional(),
  searchDocRetentionDays: z.number().int().min(30).max(3650).optional(),
  snapshotRetentionDays: z.number().int().min(30).max(3650).optional(),
  restrictedEventRetentionDays: z.number().int().min(30).max(3650).optional(),
});

export const reindexSchema = z.object({ documentType: z.string().max(40).optional() });

export const signalStatusSchema = z.object({ status: z.enum(["OPEN", "ACKNOWLEDGED", "RESOLVED", "SUPPRESSED"]) });

export const snapshotSchema = z.object({
  view: z.enum(["OVERVIEW", "FINDINGS", "ASSETS", "ATTACK_SURFACE", "RISK", "DEVSECOPS", "CLOUD", "IDENTITY", "GRC"]),
});
