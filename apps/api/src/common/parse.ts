import { BadRequestException } from "@nestjs/common";
import type { ZodSchema } from "zod";

/** Validate untrusted input at the trust boundary; errors are safe messages,
 *  never stack traces or internals. */
export function parseOrThrow<T>(schema: ZodSchema<T>, data: unknown): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    throw new BadRequestException({
      message: "Validation failed",
      issues: result.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
    });
  }
  return result.data;
}
