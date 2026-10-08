/**
 * GraphQL test-generation bounds (Prompt 32 §59/§184).
 *
 * The platform ANALYSES GraphQL operations and generates only bounded
 * defensive test queries. Depth, complexity, alias count and batch
 * size are computed from the operation text with a conservative
 * tokenizer and enforced against hard limits BEFORE anything is sent —
 * an over-limit test is never generated, so the scanner can never
 * become the resource-exhaustion attack it is checking for.
 */

export const GRAPHQL_TEST_LIMITS = {
  maxDepth: 7,
  maxComplexity: 200,
  maxAliases: 10,
  maxBatchSize: 5,
  maxFields: 100,
} as const;

export interface GraphqlOperationMetrics {
  depth: number;
  fields: number;
  aliases: number;
  complexity: number;
  operations: number;
}

/** Conservative structural metrics: braces drive depth; field tokens
 *  are identifiers at selection level; aliases are `name:` prefixes. */
export function measureGraphqlOperation(text: string): GraphqlOperationMetrics {
  const withoutStrings = text.replace(/"(?:\\.|[^"\\])*"/g, '""');
  let depth = 0;
  let maxDepth = 0;
  let fields = 0;
  let aliases = 0;
  let operations = 0;
  const tokens = withoutStrings.match(/[{}()]|[A-Za-z_][A-Za-z0-9_]*|:/g) ?? [];
  let prev = "";
  for (const tok of tokens) {
    if (tok === "{") { depth += 1; maxDepth = Math.max(maxDepth, depth); }
    else if (tok === "}") { depth = Math.max(0, depth - 1); }
    else if (tok === ":") { aliases += 1; }
    else if (/^(query|mutation|subscription)$/.test(tok) && depth === 0) { operations += 1; }
    else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(tok) && depth >= 1 && prev !== ":") { fields += 1; }
    prev = tok;
  }
  // Complexity: fields weighted by nesting (a cheap, explainable proxy).
  const complexity = fields * Math.max(1, maxDepth);
  return { depth: maxDepth, fields, aliases, complexity, operations: Math.max(1, operations) };
}

export interface GraphqlBoundResult {
  allowed: boolean;
  metrics: GraphqlOperationMetrics;
  violations: string[];
}

/** §184: an excessive-complexity test request is rejected at generation. */
export function boundGraphqlTest(text: string, batchSize = 1): GraphqlBoundResult {
  const metrics = measureGraphqlOperation(text);
  const violations: string[] = [];
  if (metrics.depth > GRAPHQL_TEST_LIMITS.maxDepth) violations.push(`depth ${metrics.depth} exceeds limit ${GRAPHQL_TEST_LIMITS.maxDepth}`);
  if (metrics.complexity > GRAPHQL_TEST_LIMITS.maxComplexity) violations.push(`complexity ${metrics.complexity} exceeds limit ${GRAPHQL_TEST_LIMITS.maxComplexity}`);
  if (metrics.aliases > GRAPHQL_TEST_LIMITS.maxAliases) violations.push(`aliases ${metrics.aliases} exceed limit ${GRAPHQL_TEST_LIMITS.maxAliases}`);
  if (metrics.fields > GRAPHQL_TEST_LIMITS.maxFields) violations.push(`fields ${metrics.fields} exceed limit ${GRAPHQL_TEST_LIMITS.maxFields}`);
  if (batchSize > GRAPHQL_TEST_LIMITS.maxBatchSize) violations.push(`batch size ${batchSize} exceeds limit ${GRAPHQL_TEST_LIMITS.maxBatchSize}`);
  if (metrics.operations > 1 && batchSize <= 1) violations.push("multiple operations in one document are not generated as a test");
  return { allowed: violations.length === 0, metrics, violations };
}

/** §58 defensive check categories the GraphQL service may report. */
export const GRAPHQL_DEFENSIVE_CHECKS = [
  "INTROSPECTION_EXPOSURE",
  "SCHEMA_VISIBILITY",
  "AUTHORIZATION_INCONSISTENCY",
  "QUERY_DEPTH_CONTROLS",
  "COMPLEXITY_CONTROLS",
  "ERROR_LEAKAGE",
] as const;
export type GraphqlDefensiveCheck = (typeof GRAPHQL_DEFENSIVE_CHECKS)[number];
