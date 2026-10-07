import { describe, expect, it } from "vitest";
import { buildDag, readyStages, isDagComplete } from "./dag";
import { STAGE_LIBRARY, resolveTemplate, type StageDefinition } from "./profiles";

const def = (type: string, dependencies: string[]): StageDefinition => ({
  ...STAGE_LIBRARY[type as keyof typeof STAGE_LIBRARY],
  type: type as StageDefinition["type"],
  dependencies: dependencies as StageDefinition["dependencies"],
});

describe("DAG construction & validation (§5–§6)", () => {
  it("builds the WEB_BASELINE DAG in dependency order with parallel layers", () => {
    const { dag, errors } = buildDag(resolveTemplate("WEB_BASELINE"));
    expect(errors).toEqual([]);
    expect(dag).toBeDefined();
    const layerOf = new Map<string, number>();
    dag!.layers.forEach((layer, i) => layer.forEach((id) => layerOf.set(id, i)));
    expect(layerOf.get("AUTHORIZATION_CHECK")).toBeLessThan(layerOf.get("SCOPE_VALIDATION")!);
    expect(layerOf.get("HTTP_DISCOVERY")).toBeLessThan(layerOf.get("TECHNOLOGY_DETECTION")!);
    expect(layerOf.get("HTTP_DISCOVERY")).toBeLessThan(layerOf.get("CRAWLING")!);
    // TECHNOLOGY_DETECTION and CRAWLING are independent — same layer, both feed ENDPOINT_DISCOVERY
    expect(layerOf.get("TECHNOLOGY_DETECTION")).toBe(layerOf.get("CRAWLING"));
    expect(layerOf.get("ENDPOINT_DISCOVERY")).toBeGreaterThan(layerOf.get("CRAWLING")!);
    expect(layerOf.get("REPORT_GENERATION")).toBe(dag!.layers.length - 1);
  });

  it("rejects dependency cycles", () => {
    const defs = [
      def("AUTHORIZATION_CHECK", ["SCOPE_VALIDATION"]),
      def("SCOPE_VALIDATION", ["AUTHORIZATION_CHECK"]),
    ];
    const { dag, errors } = buildDag(defs);
    expect(dag).toBeUndefined();
    expect(errors.some((e) => e.code === "CYCLE")).toBe(true);
  });

  it("rejects missing dependencies, duplicates and missing required stages", () => {
    expect(buildDag([def("AUTHORIZATION_CHECK", []), def("SCOPE_VALIDATION", ["NOPE" as never])]).errors.some((e) => e.code === "MISSING_DEPENDENCY")).toBe(true);
    expect(buildDag([def("AUTHORIZATION_CHECK", []), def("AUTHORIZATION_CHECK", [])]).errors.some((e) => e.code === "DUPLICATE_STAGE")).toBe(true);
    expect(buildDag([def("PASSIVE_RECON", [])]).errors.some((e) => e.code === "MISSING_REQUIRED_STAGE")).toBe(true);
  });

  it("computes ready stages from dependency satisfaction only", () => {
    const { dag } = buildDag(resolveTemplate("PASSIVE_RECON"));
    const status = new Map<string, string>(dag!.nodes.map((n) => [n.id, "PENDING"]));
    expect(readyStages(dag!, status).map((n) => n.id)).toEqual(["AUTHORIZATION_CHECK"]);
    status.set("AUTHORIZATION_CHECK", "COMPLETED");
    expect(readyStages(dag!, status).map((n) => n.id)).toEqual(["SCOPE_VALIDATION"]);
    status.set("SCOPE_VALIDATION", "FAILED");
    expect(readyStages(dag!, status)).toEqual([]); // failed dependency never readies dependents
    expect(isDagComplete(status)).toBe(false);
  });
});
