import { BadRequestException } from "@nestjs/common";
import { ClientAdminController } from "./client-portal.controller";
import { ClientPortalService } from "./client-portal.service";

/**
 * Prompt 39 RC1 regression tests for finding RC1-H1: malformed admin
 * bodies on the client-portal admin API surfaced as HTTP 500 (unguarded
 * `input.slug.toLowerCase()`) instead of the platform's standard 400
 * validation error (§195/§227). The controller now validates every admin
 * POST body with zod at the trust boundary, and the service re-checks
 * its required fields defensively.
 */

const USER = { id: "u-1", organizationId: "org-1", email: "rudra@example.com", role: "OWNER" } as never;

function makeController() {
  const calls: { method: string; args: unknown[] }[] = [];
  const portal = {
    createClient: jest.fn(async (...args: unknown[]) => { calls.push({ method: "createClient", args }); return { id: "c-1" }; }),
    createEngagement: jest.fn(async (...args: unknown[]) => { calls.push({ method: "createEngagement", args }); return { id: "e-1" }; }),
    bindPortalUser: jest.fn(async (...args: unknown[]) => { calls.push({ method: "bindPortalUser", args }); return { id: "b-1" }; }),
    publishFinding: jest.fn(async (...args: unknown[]) => { calls.push({ method: "publishFinding", args }); return { id: "p-1" }; }),
    unpublishFinding: jest.fn(async (...args: unknown[]) => { calls.push({ method: "unpublishFinding", args }); return { id: "p-2" }; }),
  };
  const prisma = { workspace: { findFirst: jest.fn(async () => ({ id: "ws-1" })) } };
  const controller = new ClientAdminController(prisma as never, portal as never);
  return { controller, portal, calls };
}

describe("ClientAdminController input validation (RC1-H1 regression)", () => {
  it("missing slug is a 400, never a 500, and never reaches the service", async () => {
    const { controller, portal } = makeController();
    await expect(controller.createClient(USER, { name: "Rudra Retail" })).rejects.toBeInstanceOf(BadRequestException);
    await expect(controller.createClient(USER, {})).rejects.toBeInstanceOf(BadRequestException);
    await expect(controller.createClient(USER, undefined)).rejects.toBeInstanceOf(BadRequestException);
    await expect(controller.createClient(USER, { name: "X", slug: 42 })).rejects.toBeInstanceOf(BadRequestException);
    await expect(controller.createClient(USER, { name: "X", slug: "x", contactEmail: "not-an-email" })).rejects.toBeInstanceOf(BadRequestException);
    expect(portal.createClient).not.toHaveBeenCalled();
  });

  it("a valid client body passes through unchanged", async () => {
    const { controller, calls } = makeController();
    const res = await controller.createClient(USER, { name: "Rudra Retail", slug: "rudra-retail" });
    expect(res).toEqual({ id: "c-1" });
    expect(calls[0]!.method).toBe("createClient");
    expect(calls[0]!.args[2]).toEqual({ name: "Rudra Retail", slug: "rudra-retail" });
  });

  it("engagement, bind and publish bodies are validated the same way", async () => {
    const { controller, portal } = makeController();
    await expect(controller.createEngagement(USER, { name: "Eng" })).rejects.toBeInstanceOf(BadRequestException);
    await expect(controller.bind(USER, { userId: "u-9" })).rejects.toBeInstanceOf(BadRequestException);
    await expect(controller.publish(USER, "e-1", {})).rejects.toBeInstanceOf(BadRequestException);
    await expect(controller.unpublish(USER, "e-1", { findingId: "" })).rejects.toBeInstanceOf(BadRequestException);
    expect(portal.createEngagement).not.toHaveBeenCalled();
    expect(portal.bindPortalUser).not.toHaveBeenCalled();
    expect(portal.publishFinding).not.toHaveBeenCalled();
  });
});

describe("ClientPortalService defensive validation (RC1-H1 regression)", () => {
  it("createClient with a missing slug throws BadRequest, not TypeError", async () => {
    const prisma = { clientOrganization: { findFirst: jest.fn(async () => null), create: jest.fn(async () => ({ id: "c" })) } };
    const audit = { record: jest.fn(async () => undefined) };
    const service = new ClientPortalService(prisma as never, audit as never);
    await expect(service.createClient(USER as never, "ws-1", { name: "X" } as never)).rejects.toBeInstanceOf(BadRequestException);
    await expect(service.createClient(USER as never, "ws-1", { slug: "x" } as never)).rejects.toBeInstanceOf(BadRequestException);
    await expect(service.createEngagement(USER as never, "ws-1", { clientOrganizationId: "c-1" } as never)).rejects.toBeInstanceOf(BadRequestException);
  });
});
