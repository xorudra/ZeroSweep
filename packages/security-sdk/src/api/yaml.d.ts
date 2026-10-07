/**
 * Minimal local typings for the js-yaml subset the importers use
 * (the workspace has no @types/js-yaml). Only `load` / `loadAll` with
 * a restricted schema are ever called — see import-security.ts and
 * cloudnative/yaml-safe.ts for the safety rules.
 */
declare module "js-yaml" {
  export interface LoadOptions {
    schema?: unknown;
    json?: boolean;
    onWarning?: (warning: Error) => void;
  }
  export const JSON_SCHEMA: unknown;
  export const FAILSAFE_SCHEMA: unknown;
  export function load(input: string, options?: LoadOptions): unknown;
  export function loadAll(input: string, options?: LoadOptions): unknown[];
}
