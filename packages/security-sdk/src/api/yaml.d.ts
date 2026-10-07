/**
 * Minimal local typings for the js-yaml subset the API importers use
 * (the workspace has no @types/js-yaml). Only `load` with a restricted
 * schema is ever called — see import-security.ts for the safety rules.
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
}
