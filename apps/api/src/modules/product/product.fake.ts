/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * In-memory Prisma fake for Prompt 40 product tests. Supports the query
 * shapes the product services use: equality / in / gte / gt / lte / lt /
 * OR where clauses, orderBy, take, the include shapes for
 * subscription→planVersion(→plan, →entitlements), unique-constraint
 * enforcement on the idempotency-critical tables, and $transaction
 * serialized through a mutex (mirroring the Serializable production
 * path used by quota reservations).
 */

type Row = Record<string, any>;
let seq = 0;

const UNIQUE_KEYS: Record<string, string[][]> = {
  user: [["email"], ["normalizedEmail"]],
  organization: [["slug"]],
  usageEvent: [["idempotencyKey"]],
  billingEvent: [["provider", "externalEventId"]],
  billingInvoiceReference: [["provider", "externalInvoiceId"]],
  quotaReservation: [["organizationId", "dimension", "reference"]],
  productLicense: [["licenseId"]],
  organizationOnboarding: [["organizationId"]],
  emailVerificationToken: [["tokenHash"]],
  planVersion: [["planId", "version"]],
  planEntitlement: [["planVersionId", "featureKey"]],
  productPlan: [["code"]],
  membership: [["userId", "organizationId"]],
};

function matches(row: Row, where: Row = {}): boolean {
  return Object.entries(where).every(([k, v]) => {
    if (k === "OR") return (v as Row[]).some((sub) => matches(row, sub));
    if (k === "AND") return (v as Row[]).every((sub) => matches(row, sub));
    if (v === null || typeof v !== "object" || v instanceof Date) return row[k] === v || (v instanceof Date && row[k] instanceof Date && row[k].getTime() === v.getTime());
    const cond = v as Row;
    if (Array.isArray(cond.in)) return cond.in.includes(row[k]);
    if (cond.gte !== undefined) return new Date(row[k]).getTime() >= new Date(cond.gte).getTime();
    if (cond.gt !== undefined) return new Date(row[k]).getTime() > new Date(cond.gt).getTime();
    if (cond.lte !== undefined) return new Date(row[k]).getTime() <= new Date(cond.lte).getTime();
    if (cond.lt !== undefined) return new Date(row[k]).getTime() < new Date(cond.lt).getTime();
    return true;
  });
}

export function makeTable(db: any, name: string, rows: Row[] = []) {
  const table: any = {
    rows,
    async findFirst(args: { where?: Row; orderBy?: Row; include?: Row } = {}) {
      const found = table.findManySync(args);
      return found[0] ?? null;
    },
    async findUnique(args: { where?: Row; include?: Row } = {}) {
      const found = rows.find((r) => matches(r, args.where));
      return found ? table.withInclude(found, args.include) : null;
    },
    async findMany(args: { where?: Row; orderBy?: Row; take?: number; include?: Row; select?: Row } = {}) {
      return table.findManySync(args);
    },
    findManySync(args: { where?: Row; orderBy?: Row; take?: number; include?: Row; select?: Row } = {}) {
      let found = rows.filter((r) => matches(r, args.where));
      if (args.orderBy) {
        const [field, dir] = Object.entries(args.orderBy)[0] as [string, string];
        found = [...found].sort((a, b) => {
          const av = new Date(a[field]).getTime() || a[field];
          const bv = new Date(b[field]).getTime() || b[field];
          return dir === "desc" ? (bv > av ? 1 : -1) : (av > bv ? 1 : -1);
        });
      }
      if (args.take) found = found.slice(0, args.take);
      return found.map((r) => table.withInclude(r, args.include, args.select));
    },
    withInclude(row: Row, include?: Row, select?: Row) {
      let out = { ...row };
      if (select) {
        out = {};
        for (const k of Object.keys(select)) out[k] = row[k];
      }
      if (!include) return out;
      if (include.planVersion && row.planVersionId) {
        const pv = db.planVersion.rows.find((r: Row) => r.id === row.planVersionId);
        out.planVersion = pv ? db.planVersion.withInclude(pv, include.planVersion === true ? undefined : include.planVersion.include) : null;
      }
      if (include.plan && row.planId) {
        out.plan = db.productPlan.rows.find((r: Row) => r.id === row.planId) ?? null;
      }
      if (include.entitlements && name === "planVersion") {
        out.entitlements = db.planEntitlement.rows.filter((r: Row) => r.planVersionId === row.id);
      }
      return out;
    },
    async count(args: { where?: Row } = {}) {
      return rows.filter((r) => matches(r, args.where)).length;
    },
    async create(args: { data: Row }) {
      for (const keys of UNIQUE_KEYS[name] ?? []) {
        if (keys.some((k) => args.data[k] === undefined)) continue;
        if (rows.some((r) => keys.every((k) => r[k] === args.data[k]))) {
          const err: any = new Error("Unique constraint failed");
          err.code = "P2002";
          throw err;
        }
      }
      const row = { id: `${name}-${++seq}`, createdAt: new Date(), updatedAt: new Date(), ...args.data };
      rows.push(row);
      return row;
    },
    async update(args: { where: Row; data: Row }) {
      const row = rows.find((r) => matches(r, args.where));
      if (!row) throw new Error("not found");
      Object.assign(row, args.data);
      return row;
    },
    async upsert(args: { where: Row; create: Row; update: Row }) {
      const row = rows.find((r) => matches(r, args.where));
      if (row) { Object.assign(row, args.update); return row; }
      return table.create({ data: args.create });
    },
  };
  return table;
}

export function makeProductDb() {
  const db: any = {};
  const tables = [
    "user", "organization", "workspace", "membership", "emailVerificationToken",
    "productPlan", "planVersion", "planEntitlement", "subscription", "productTrial",
    "organizationOnboarding", "usageEvent", "usageAggregate", "quotaPolicy",
    "quotaOverride", "quotaReservation", "billingEvent", "billingInvoiceReference",
    "productLicense", "supportAccessSession", "deploymentRegion",
    "productAnalyticsEvent", "abuseSignalRecord", "auditLog", "asset", "scan",
    "report", "integration", "finding", "workerNode", "tool",
  ];
  for (const t of tables) db[t] = makeTable(db, t, []);
  let chain: Promise<unknown> = Promise.resolve();
  db.$transaction = (fn: (tx: any) => Promise<unknown>) => {
    const run = chain.then(() => fn(db));
    chain = run.catch(() => undefined);
    return run;
  };
  return db;
}

/** Seed an ACTIVE plan + version + entitlements into the fake. */
export async function seedPlan(db: any, code: string, productMode: string, entitlements: Array<{ featureKey: string; enabled: boolean; limit?: number | null }>, quotas: Record<string, number | null> = {}) {
  const plan = await db.productPlan.create({ data: { code, name: code, description: "test", status: "ACTIVE", productMode } });
  const version = await db.planVersion.create({ data: { planId: plan.id, version: 1, quotas } });
  for (const e of entitlements) {
    await db.planEntitlement.create({ data: { planVersionId: version.id, featureKey: e.featureKey, enabled: e.enabled, limit: e.limit ?? null } });
  }
  return { plan, version };
}
