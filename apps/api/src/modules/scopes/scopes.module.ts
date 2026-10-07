import { Module } from "@nestjs/common";
import { ScopesController } from "./scopes.controller";
@Module({ controllers: [ScopesController] })
export class ScopesModule {}
