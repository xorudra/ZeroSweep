import { Module } from "@nestjs/common";
import { ScansController } from "./scans.controller";
import { AssetsModule } from "../assets/assets.module";

@Module({ imports: [AssetsModule], controllers: [ScansController] })
export class ScansModule {}
