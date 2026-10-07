import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { Capability, ToolCategory } from "../adapter/adapter.types";
import type { TargetType } from "@dsrclone/types";

export interface RegistryQuery {
  category?: ToolCategory;
  capability?: Capability;
  targetType?: TargetType;
  enabledOnly?: boolean;
}

export type { SecurityToolAdapter };
