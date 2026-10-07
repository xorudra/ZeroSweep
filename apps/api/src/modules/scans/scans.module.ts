import { Module } from "@nestjs/common";
import { ScansController } from "./scans.controller";
@Module({ controllers: [ScansController] })
export class ScansModule {}
