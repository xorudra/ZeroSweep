import { Inject, Injectable } from "@nestjs/common";
import {
  computeFacets, evaluateDsl, makeSnippet, matchedFields, parseSecurityQueryDsl,
  queryTokens, suggestValues, type DslNode,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { allowedClassifications } from "../permissions";
import { criticalityRank, docToDslRecord, severityRank } from "../helpers";

export interface SearchRequestInput {
  query: string;
  sort?: string;
  cursor?: string;
  pageSize?: number;
  group?: boolean;
}

interface DocRow {
  id: string; documentType: string; resourceId: string; title: string; summary: string;
  searchableText: string; facets: unknown; classification: string;
  riskScore: number | null; severity: string | null; updatedAt: Date;
}

const MAX_CANDIDATES = 1000; // §37 result-window bound at the provider layer

/**
 * Enterprise security search (Prompt 27 §19–§31).
 *
 * Authorization happens BEFORE retrieval: the Prisma query itself is
 * constrained to the caller's organization + workspace + allowed
 * classifications (§23/§24) — there is no code path that fetches
 * globally and filters afterwards. The DSL text is parsed into a
 * typed AST and evaluated in memory over those scoped rows (§35);
 * plain text falls back to token AND-matching (§125: hostile input
 * is inert data).
 */
@Injectable()
export class SearchService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async search(user: RequestUser, workspace: { id: string }, input: SearchRequestInput) {
    const allowed = allowedClassifications(user);
    const where = {
      organizationId: user.organizationId, workspaceId: workspace.id,
      classification: { in: allowed },
    } as never;
    const docs = (await this.prisma.securitySearchDocument.findMany({
      where, orderBy: { updatedAt: "desc" }, take: MAX_CANDIDATES,
    })) as unknown as DocRow[];

    const queryText = (input.query ?? "").trim();
    let ast: DslNode | null = null;
    let interpretedAs: "DSL" | "TEXT" = "TEXT";
    let rejectedReason: string | undefined;
    if (queryText) {
      const parsed = parseSecurityQueryDsl(queryText);
      if ("ast" in parsed && hasFieldClause(parsed.ast)) { ast = parsed.ast; interpretedAs = "DSL"; }
      else if ("rejected" in parsed) rejectedReason = parsed.rejected;
    }
    const terms = queryTokens(queryText);

    const scored: Array<{ doc: DocRow; why: string[] }> = [];
    for (const doc of docs) {
      const record = docToDslRecord(doc);
      if (ast) {
        if (!evaluateDsl(ast, record)) continue;
        scored.push({ doc, why: matchedFields(ast, record) });
      } else {
        if (terms.length && !terms.every((t) => doc.searchableText.includes(t))) continue;
        scored.push({ doc, why: terms.map((t) => `text contains "${t}"`) });
      }
    }

    const sort = input.sort ?? "relevance";
    const sorted = [...scored].sort((a, b) => compareDocs(a, b, sort));
    const facets = computeFacets(sorted.map((s) => s.doc), facetOf);
    const groups: Record<string, number> = {};
    for (const s of sorted) groups[s.doc.documentType] = (groups[s.doc.documentType] ?? 0) + 1;

    // Cursor pagination (§29): the cursor is the last document id of
    // the previous page within this deterministic ordering.
    const pageSize = Math.min(input.pageSize ?? 25, 100);
    let start = 0;
    if (input.cursor) {
      const idx = sorted.findIndex((s) => s.doc.id === input.cursor);
      if (idx >= 0) start = idx + 1;
    }
    const page = sorted.slice(start, start + pageSize);
    const results = page.map(({ doc, why }) => ({
      documentId: doc.id, documentType: doc.documentType, resourceId: doc.resourceId,
      title: doc.title, summary: doc.summary,
      snippet: makeSnippet(`${doc.title} ${doc.summary}`, terms.length ? terms : extractAstTerms(ast)),
      classification: doc.classification, severity: doc.severity, riskScore: doc.riskScore,
      updatedAt: doc.updatedAt, whyMatched: why,
    }));

    // §110: search executions are audited with identifiers/counts only.
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "SECURITY_SEARCH_EXECUTED", resourceType: "SecuritySearch",
      metadata: { resultCount: sorted.length, interpretedAs, sort, pageSize },
    });

    return {
      results, total: sorted.length,
      nextCursor: start + pageSize < sorted.length ? (page[page.length - 1]?.doc.id ?? null) : null,
      facets, groups: input.group ? groups : undefined, groupCounts: groups,
      interpretedAs, ...(rejectedReason && interpretedAs === "TEXT" ? { dslNote: rejectedReason } : {}),
      classificationCeiling: allowed[allowed.length - 1],
    };
  }

  /**
   * §31 suggestions — values drawn ONLY from documents already scoped
   * to the caller's tenant + classification ceiling, so a suggestion
   * can never leak a cross-tenant name (§127).
   */
  async suggestions(user: RequestUser, workspace: { id: string }, prefix: string, kind?: string) {
    const allowed = allowedClassifications(user);
    const docs = (await this.prisma.securitySearchDocument.findMany({
      where: { organizationId: user.organizationId, workspaceId: workspace.id, classification: { in: allowed } } as never,
      take: 500,
    })) as unknown as DocRow[];
    const values: string[] = [];
    for (const doc of docs) {
      const f = (doc.facets ?? {}) as Record<string, unknown>;
      if (!kind || kind === "asset") { if (f.assetHost) values.push(String(f.assetHost)); if (doc.documentType === "ASSET") values.push(doc.title); }
      if (!kind || kind === "cve") { if (f.cve) values.push(String(f.cve)); }
      if (!kind || kind === "cwe") { if (f.cwe) values.push(String(f.cwe)); }
      if (!kind || kind === "technology") { for (const t of (f.technologies as string[]) ?? []) values.push(t); }
      if (!kind || kind === "repository") { if (f.repository) values.push(String(f.repository)); }
      if (!kind || kind === "control") { if (f.control) values.push(String(f.control)); }
    }
    return { suggestions: suggestValues(values, prefix ?? "", 10) };
  }
}

function hasFieldClause(node: DslNode): boolean {
  if (node.kind === "FIELD_FILTER" || node.kind === "RANGE" || node.kind === "DATE_RANGE") return true;
  if (node.kind === "AND" || node.kind === "OR") return node.children.some(hasFieldClause);
  if (node.kind === "NOT") return hasFieldClause(node.child);
  return false;
}

function extractAstTerms(node: DslNode | null): string[] {
  if (!node) return [];
  if (node.kind === "TERM") return [node.value];
  if (node.kind === "AND" || node.kind === "OR") return node.children.flatMap(extractAstTerms);
  if (node.kind === "NOT") return extractAstTerms(node.child);
  return [];
}

function facetOf(doc: DocRow): Record<string, string | null | undefined> {
  const f = (doc.facets ?? {}) as Record<string, unknown>;
  return {
    severity: doc.severity ?? (f.severity as string) ?? null,
    status: (f.status as string) ?? null,
    documentType: doc.documentType,
    cwe: (f.cwe as string) ?? null,
    cve: (f.cve as string) ?? null,
    source: (f.source as string) ?? null,
    classification: doc.classification,
    internetExposed: typeof f.internetExposed === "boolean" ? String(f.internetExposed) : null,
    verified: typeof f.verified === "boolean" ? String(f.verified) : null,
    kev: typeof f.kev === "boolean" ? String(f.kev) : null,
  };
}

function compareDocs(a: { doc: DocRow; why: string[] }, b: { doc: DocRow; why: string[] }, sort: string): number {
  const byId = a.doc.id < b.doc.id ? -1 : 1;
  switch (sort) {
    case "risk": return (b.doc.riskScore ?? -1) - (a.doc.riskScore ?? -1) || byId;
    case "severity": return severityRank(b.doc.severity) - severityRank(a.doc.severity) || byId;
    case "recent": return b.doc.updatedAt.getTime() - a.doc.updatedAt.getTime() || byId;
    case "oldest": return a.doc.updatedAt.getTime() - b.doc.updatedAt.getTime() || byId;
    case "criticality": {
      const ca = criticalityRank(((a.doc.facets ?? {}) as Record<string, unknown>).criticality as string);
      const cb = criticalityRank(((b.doc.facets ?? {}) as Record<string, unknown>).criticality as string);
      return cb - ca || byId;
    }
    default: // relevance: more matched clauses first, then risk
      return b.why.length - a.why.length || (b.doc.riskScore ?? -1) - (a.doc.riskScore ?? -1) || byId;
  }
}
