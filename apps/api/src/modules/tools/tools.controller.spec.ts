import { NotFoundException } from "@nestjs/common";
import { ToolsController } from "./tools.controller";
import { ROLES_KEY } from "../../common/decorators/auth.decorators";

/**
 * Tool management API (Prompt 3 §42): metadata endpoints only. These tests
 * pin two guarantees: (1) there is NO execution surface on this controller,
 * (2) write access stays behind OWNER/ADMIN roles (global JWT + Roles
 * guards cover authentication for every route).
 */
describe("ToolsController", () => {
  const toolRow = { id: "t1", slug: "nuclei", name: "Nuclei", category: "WEB", healthStatus: "UNKNOWN", installed: false, adapters: [{ capabilities: ["VULNERABILITY_SCANNING"] }] };
  const make = (rows: unknown[] = [toolRow]) => {
    const calls: Array<{ model: string; args: unknown }> = [];
    const prisma = {
      tool: {
        findMany: async (args: unknown) => { calls.push({ model: "tool.findMany", args }); return rows; },
        findFirst: async () => rows[0] ?? null,
        update: async (args: unknown) => { calls.push({ model: "tool.update", args }); return rows[0]; },
      },
      toolAdapter: { findMany: async () => [{ capabilities: ["SAST"] }, { capabilities: ["SAST", "HTTP_PROBING"] }] },
    };
    return { ctrl: new ToolsController(prisma as never), calls };
  };

  it("lists tools with adapters and applies validated filters", async () => {
    const { ctrl, calls } = make();
    const res = await ctrl.list({ category: "WEB", enabled: "true" });
    expect(res).toHaveLength(1);
    const args = calls[0]!.args as { where: Record<string, unknown>; include: unknown };
    expect(args.where.category).toBe("WEB");
    expect(args.where.enabled).toBe(true);
    expect(args.include).toEqual({ adapters: true });
  });

  it("rejects an invalid category filter at the trust boundary", async () => {
    const { ctrl } = make();
    await expect(ctrl.list({ category: "DROP TABLE" })).rejects.toThrow();
  });

  it("exposes the static category taxonomy and deduped capabilities", async () => {
    const { ctrl } = make();
    expect(await ctrl.categories()).toContain("ACTIVE_DIRECTORY");
    expect(await ctrl.capabilities()).toEqual(["HTTP_PROBING", "SAST"]);
  });

  it("returns one tool by id or slug, and 404s when missing", async () => {
    const { ctrl } = make();
    expect((await ctrl.get("nuclei")).slug).toBe("nuclei");
    const empty = new ToolsController({ tool: { findFirst: async () => null }, toolAdapter: { findMany: async () => [] } } as never);
    await expect(empty.get("nope")).rejects.toBeInstanceOf(NotFoundException);
    await expect(empty.health("nope")).rejects.toBeInstanceOf(NotFoundException);
  });

  it("health returns status metadata only", async () => {
    const { ctrl } = make();
    const h = await ctrl.health("nuclei");
    expect(h).toMatchObject({ slug: "nuclei", healthStatus: "UNKNOWN" });
  });

  it("has no execution endpoint and restricts PATCH to OWNER/ADMIN", () => {
    const proto = ToolsController.prototype as unknown as Record<string, unknown>;
    const methods = Object.getOwnPropertyNames(proto).filter((n) => n !== "constructor");
    expect(methods.sort()).toEqual(["capabilities", "categories", "get", "health", "list", "update"]);
    expect(methods.some((m) => /exec|run|command|scan/i.test(m))).toBe(false);
    const roles = Reflect.getMetadata(ROLES_KEY, ToolsController.prototype.update) as string[];
    expect(roles).toEqual(["OWNER", "ADMIN"]);
    // Read endpoints carry no role restriction beyond the global JWT guard —
    // any authenticated org member may browse the catalog.
    expect(Reflect.getMetadata(ROLES_KEY, ToolsController.prototype.list)).toBeUndefined();
  });
});
