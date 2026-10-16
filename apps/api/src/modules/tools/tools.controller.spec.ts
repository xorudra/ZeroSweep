import { ForbiddenException, NotFoundException } from "@nestjs/common";
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
    const admin = { id: "u-a", email: "a@x.io", organizationId: "org-1", role: "ADMIN" } as const;
    const h = await ctrl.health("nuclei", admin as never);
    // Prompt 7: nuclei is now an IMPLEMENTED adapter, so live probe health
    // wins over the stored catalog value for privileged callers — binary
    // absent on this host means an honest UNAVAILABLE, never a faked
    // HEALTHY (§49).
    expect(h).toMatchObject({ slug: "nuclei", healthStatus: "UNAVAILABLE" });
  });

  it("health does NOT live-probe or leak host detail to non-privileged callers", async () => {
    const { ctrl } = make();
    const viewer = { id: "u-v", email: "v@x.io", organizationId: "org-1", role: "VIEWER" } as const;
    for (const u of [viewer as never, undefined]) {
      const h = await ctrl.health("nuclei", u) as Record<string, unknown>;
      // Stored catalog health only: no live probe, no version/path detail.
      expect(h).toMatchObject({ slug: "nuclei", healthStatus: "UNKNOWN", installed: false });
      expect(h).not.toHaveProperty("detail");
      expect(h).not.toHaveProperty("version");
    }
  });

  it("template policy endpoint exposes the governed catalog, OWNER/ADMIN only (§4/§47)", () => {
    const { ctrl } = make();
    const policy = ctrl.templatePolicy();
    expect(policy.snapshot.version).toBeTruthy();
    const byId = Object.fromEntries(policy.templates.map((t) => [t.id, t.classification]));
    expect(byId["http-missing-security-headers"]).toBe("SAFE");
    expect(byId["sqli-error-based"]).toBe("INTRUSIVE");
    expect(byId["default-login-check"]).toBe("DISABLED");
    expect(policy.selectionRules.neverAutomated).toEqual(["INTRUSIVE", "DISABLED"]);
    const roles = Reflect.getMetadata(ROLES_KEY, ToolsController.prototype.templatePolicy) as string[];
    expect(roles).toEqual(["OWNER", "ADMIN"]);
  });

  it("has no execution endpoint and restricts PATCH to platform administrators", async () => {
    const proto = ToolsController.prototype as unknown as Record<string, unknown>;
    const methods = Object.getOwnPropertyNames(proto).filter((n) => n !== "constructor");
    expect(methods.sort()).toEqual(["capabilities", "categories", "get", "health", "list", "templatePolicy", "update"]);
    expect(methods.some((m) => /exec|run|command|scan/i.test(m))).toBe(false);
    // The Tool row is global: tenant OWNER/ADMIN roles must NOT flip it.
    // Only the deployment platform-admin flag authorizes the mutation.
    expect(Reflect.getMetadata(ROLES_KEY, ToolsController.prototype.update)).toBeUndefined();
    const { ctrl, calls } = make();
    const tenantAdmin = { id: "u-ta", email: "ta@x.io", organizationId: "org-1", role: "ADMIN" } as const;
    const tenantOwner = { id: "u-to", email: "to@x.io", organizationId: "org-1", role: "OWNER" } as const;
    await expect(ctrl.update("nuclei", { enabled: false }, tenantAdmin as never)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(ctrl.update("nuclei", { enabled: false }, tenantOwner as never)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(ctrl.update("nuclei", { enabled: false }, undefined)).rejects.toBeInstanceOf(ForbiddenException);
    expect(calls.some((c) => c.model === "tool.update")).toBe(false);
    const platformAdmin = { id: "u-pa", email: "pa@x.io", organizationId: "org-1", role: "VIEWER", isPlatformAdmin: true } as const;
    await expect(ctrl.update("nuclei", { enabled: false }, platformAdmin as never)).resolves.toBeTruthy();
    expect(calls.some((c) => c.model === "tool.update")).toBe(true);
    // Read endpoints carry no role restriction beyond the global JWT guard —
    // any authenticated org member may browse the catalog.
    expect(Reflect.getMetadata(ROLES_KEY, ToolsController.prototype.list)).toBeUndefined();
  });
});
