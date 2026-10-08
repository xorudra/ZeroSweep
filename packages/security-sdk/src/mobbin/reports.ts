/**
 * Prompt 35 §127/§128 — mobile & binary report definitions.
 *
 * Reports render through the Prompt 20 reporting substrate from
 * immutable redacted snapshots; these definitions fix the report
 * kinds and the mandatory §128 content outline so a report can
 * never omit its authorization, methodology, tools/versions,
 * coverage or limitations.
 */
export const MOBBIN_REPORT_KINDS = [
  "ANDROID_APPLICATION_SECURITY",
  "IOS_APPLICATION_SECURITY",
  "MOBILE_VAPT",
  "MOBILE_MASVS_ASSESSMENT",
  "BINARY_SECURITY_ASSESSMENT",
  "NATIVE_LIBRARY_HARDENING",
  "MOBILE_VERIFICATION",
  "EXECUTIVE_MOBILE_SECURITY",
] as const;
export type MobbinReportKind = (typeof MOBBIN_REPORT_KINDS)[number];

/** §128: mandatory sections, in order, for every mobile/binary
 *  report. Coverage and limitations are mandatory — a report that
 *  hides its gaps is a dishonest report (§124). */
export const MOBBIN_REPORT_SECTIONS = [
  "APPLICATION_AND_ARTIFACT_IDENTITY", // app + artifact hash + version/build
  "AUTHORIZATION",
  "METHODOLOGY",
  "TOOLS_AND_VERSIONS",
  "STATIC_COVERAGE",
  "DYNAMIC_COVERAGE",
  "LIMITATIONS",
  "FINDINGS",
  "EVIDENCE",
  "RISK",
  "REMEDIATION",
  "VERIFICATION",
] as const;

export function mobbinReportDefinition(kind: string): { kind: MobbinReportKind; sections: readonly string[] } | null {
  if (!(MOBBIN_REPORT_KINDS as readonly string[]).includes(kind)) return null;
  return { kind: kind as MobbinReportKind, sections: MOBBIN_REPORT_SECTIONS };
}
