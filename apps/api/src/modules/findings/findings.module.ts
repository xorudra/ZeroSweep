import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { FindingsController } from "./findings.controller";
@Module({ imports: [AuditModule], controllers: [FindingsController] })
export class FindingsModule {}
