import { Module } from "@nestjs/common";
import { AssessmentsController } from "./assessments.controller";
@Module({ controllers: [AssessmentsController] })
export class AssessmentsModule {}
