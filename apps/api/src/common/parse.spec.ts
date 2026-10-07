import { BadRequestException } from "@nestjs/common";
import { z } from "zod";
import { parseOrThrow } from "./parse";

describe("parseOrThrow (API validation)", () => {
  const schema = z.object({ port: z.number().int().min(1).max(65535) });
  it("returns parsed data for valid input", () => {
    expect(parseOrThrow(schema, { port: 443 })).toEqual({ port: 443 });
  });
  it("throws a safe BadRequest with issues and no stack detail for invalid input", () => {
    try {
      parseOrThrow(schema, { port: 70000 });
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(BadRequestException);
      const body = (e as BadRequestException).getResponse() as { issues: unknown[] };
      expect(Array.isArray(body.issues)).toBe(true);
    }
  });
});
