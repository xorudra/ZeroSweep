import { PrismaClient } from "@prisma/client";

/** Single reusable Prisma client (global-cached to survive dev hot reloads). */
const globalForPrisma = globalThis as unknown as { dsrclonePrisma?: PrismaClient };

export const prisma: PrismaClient =
  globalForPrisma.dsrclonePrisma ??
  new PrismaClient({ log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"] });

if (process.env.NODE_ENV !== "production") globalForPrisma.dsrclonePrisma = prisma;

export * from "@prisma/client";
