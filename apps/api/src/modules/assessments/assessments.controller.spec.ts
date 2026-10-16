import { BadRequestException } from "@nestjs/common";
import { AssessmentsController } from "./assessments.controller";

/**
 * Regression: create() must tenant-bind a client-supplied scopeId to
 * the verified target + workspace. A foreign scopeId is rejected and
 * never persisted (it would otherwise disclose the foreign scope's
 * rules via GET and act as scan authorization downstream).
 */

const user = { id: "u-1", email: "r@example.com", organizationId: "org-1", role: "OWNER" as const };
const TARGET_ID = "11111111-1111-4111-8111-111111111111";
const OWN_SCOPE_ID = "22222222-2222-4222-8222-222222222222";
const FOREIGN_SCOPE_ID = "33333333-3333-4333-8333-333333333333";

function makeController() {
  const created: Array<Record<string, unknown>> = [];
  const prisma = {
    target: {
      findFirst: async () => ({ id: TARGET_ID, workspaceId: "ws-1" }),
    },
    scope: {
      findFirst: async (args: { where: Record<string, unknown> }) =>
        args.where.id === OWN_SCOPE_ID && args.where.targetId === TARGET_ID && args.where.workspaceId === "ws-1"
          ? { id: OWN_SCOPE_ID }
          : null,
    },
    assessment: {
      create: async (args: { data: Record<string, unknown> }) => {
        const row = { id: "as-1", ...args.data };
        created.push(row);
        return row;
      },
    },
  };
  const audit = { record: async () => undefined };
  const controller = new AssessmentsController(prisma as never, audit as never);
  return { controller, created };
}

const body = (scopeId?: string) => ({
  name: "Engagement",
  targetId: TARGET_ID,
  profile: "SOURCE_BASELINE",
  ...(scopeId ? { scopeId } : {}),
});

describe("AssessmentsController.create scopeId tenant binding", () => {
  it("rejects a foreign scopeId and persists nothing", async () => {
    const { controller, created } = makeController();
    await expect(controller.create(user, body(FOREIGN_SCOPE_ID))).rejects.toBeInstanceOf(BadRequestException);
    expect(created).toHaveLength(0);
  });

  it("accepts a scopeId that belongs to the target in the same workspace", async () => {
    const { controller, created } = makeController();
    const out = await controller.create(user, body(OWN_SCOPE_ID));
    expect((out as Record<string, unknown>).scopeId).toBe(OWN_SCOPE_ID);
    expect(created).toHaveLength(1);
    expect(created[0]?.status).toBe("PENDING_APPROVAL");
  });

  it("creates a PENDING_APPROVAL assessment when no scopeId is supplied", async () => {
    const { controller, created } = makeController();
    const out = await controller.create(user, body());
    expect((out as Record<string, unknown>).status).toBe("PENDING_APPROVAL");
    expect(created).toHaveLength(1);
  });
});
