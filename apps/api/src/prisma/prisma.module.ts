import { Global, Module } from "@nestjs/common";
import { prisma } from "@dsrclone/database";

export const PRISMA = Symbol("PRISMA_CLIENT");
export type PrismaClientLike = typeof prisma;

@Global()
@Module({
  providers: [{ provide: PRISMA, useValue: prisma }],
  exports: [PRISMA],
})
export class PrismaModule {}
