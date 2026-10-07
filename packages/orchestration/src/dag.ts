import type { StageDefinition, StageType } from "./profiles";

/**
 * DAG construction + validation (Prompt 4 §5–§6). A scan plan is a directed
 * acyclic graph of stages — never one giant sequential script. Invalid plans
 * are rejected BEFORE anything is queued.
 */

export interface DagNode extends StageDefinition {
  id: string; // == type (stage types are unique within a plan)
}

export interface DagValidationError {
  code: "CYCLE" | "MISSING_DEPENDENCY" | "DUPLICATE_STAGE" | "MISSING_REQUIRED_STAGE" | "UNKNOWN_STAGE";
  message: string;
  stage?: string;
}

export interface ValidatedDag {
  nodes: DagNode[];
  byId: Map<string, DagNode>;
  /** Topological layers: stages in the same layer may run concurrently. */
  layers: string[][];
}

const REQUIRED_STAGES: StageType[] = ["AUTHORIZATION_CHECK", "SCOPE_VALIDATION"];

export function buildDag(defs: StageDefinition[]): { dag?: ValidatedDag; errors: DagValidationError[] } {
  const errors: DagValidationError[] = [];
  const byId = new Map<string, DagNode>();

  for (const def of defs) {
    if (byId.has(def.type)) {
      errors.push({ code: "DUPLICATE_STAGE", message: `Duplicate stage id in plan: ${def.type}`, stage: def.type });
      continue;
    }
    byId.set(def.type, { ...def, id: def.type });
  }
  for (const required of REQUIRED_STAGES) {
    if (!byId.has(required)) {
      errors.push({ code: "MISSING_REQUIRED_STAGE", message: `Required stage missing from plan: ${required}`, stage: required });
    }
  }
  for (const node of byId.values()) {
    for (const dep of node.dependencies) {
      if (!byId.has(dep)) {
        errors.push({ code: "MISSING_DEPENDENCY", message: `Stage ${node.type} depends on unknown stage ${dep}`, stage: node.type });
      }
    }
  }
  if (errors.length > 0) return { errors };

  // Kahn's algorithm — layer by layer; leftovers mean a cycle.
  const indegree = new Map<string, number>();
  const dependents = new Map<string, string[]>();
  for (const node of byId.values()) {
    indegree.set(node.id, node.dependencies.length);
    for (const dep of node.dependencies) {
      dependents.set(dep, [...(dependents.get(dep) ?? []), node.id]);
    }
  }
  const layers: string[][] = [];
  let ready = [...byId.values()].filter((n) => indegree.get(n.id) === 0).map((n) => n.id);
  let visited = 0;
  while (ready.length > 0) {
    layers.push(ready);
    visited += ready.length;
    const next: string[] = [];
    for (const id of ready) {
      for (const dependent of dependents.get(id) ?? []) {
        const d = (indegree.get(dependent) ?? 0) - 1;
        indegree.set(dependent, d);
        if (d === 0) next.push(dependent);
      }
    }
    ready = next;
  }
  if (visited !== byId.size) {
    const inCycle = [...byId.keys()].filter((id) => (indegree.get(id) ?? 0) > 0);
    errors.push({ code: "CYCLE", message: `Dependency cycle detected among stages: ${inCycle.join(", ")}`, stage: inCycle[0] });
    return { errors };
  }
  return { dag: { nodes: [...byId.values()], byId, layers }, errors: [] };
}

/** Stages whose dependencies have all reached a satisfying terminal state. */
export function readyStages(
  dag: ValidatedDag,
  statusByStage: ReadonlyMap<string, string>,
): DagNode[] {
  const satisfied = (s: string | undefined) => s === "COMPLETED" || s === "PARTIAL" || s === "SKIPPED";
  return dag.nodes.filter((node) => {
    const status = statusByStage.get(node.id) ?? "PENDING";
    // Runnable states: PENDING (not yet classified), BLOCKED (waiting on
    // dependencies that are now satisfied) and READY (deps already satisfied).
    if (status !== "PENDING" && status !== "BLOCKED" && status !== "READY") return false;
    return node.dependencies.every((dep) => satisfied(statusByStage.get(dep)));
  });
}

/** True when every stage is in a terminal state. */
export function isDagComplete(statusByStage: ReadonlyMap<string, string>): boolean {
  const terminal = new Set(["COMPLETED", "PARTIAL", "FAILED", "SKIPPED", "CANCELLED"]);
  return [...statusByStage.values()].every((s) => terminal.has(s));
}
