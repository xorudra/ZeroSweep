/**
 * Prompt 18 — commercial reverse-engineering connectors (§36–§39).
 *
 * IDA and Binary Ninja are OPTIONAL, separately licensed products.
 * ZeroSweep never bundles them, never bypasses licensing and never
 * depends on them for baseline coverage (§96): without a transport
 * the connectors report NOT_INSTALLED; with an installation but no
 * license they report LICENSE_UNAVAILABLE; only a licensed,
 * reachable instance is READY. Imported reports pass through the
 * SAME bounded parser + normalization as Ghidra output — a connector
 * is an import path, not a trust bypass (§38/§96).
 */
import type { ParsedBinary } from "./types";
import { emptyParsedBinary, type BinaryConnectorDeps, type CommercialLicenseState, INERT_BINARY_DEPS } from "./types";
import { parseBinaryGhidraReport } from "./parsers-binary";

abstract class CommercialBinaryConnector {
  abstract readonly slug: string;
  abstract readonly name: string;
  protected abstract transport(): BinaryConnectorDeps["transports"]["ida"];

  constructor(protected readonly deps: BinaryConnectorDeps = INERT_BINARY_DEPS) {}

  /** §37: explicit license state — never inferred, never optimistic. */
  async licenseState(): Promise<CommercialLicenseState> {
    const t = this.transport();
    if (!t) return "NOT_INSTALLED";
    try {
      return await t.licenseState();
    } catch {
      return "LICENSE_UNAVAILABLE";
    }
  }

  async healthCheck(): Promise<{ status: string; detail?: string }> {
    const state = await this.licenseState();
    switch (state) {
      case "READY":
        return { status: "READY", detail: `${this.name} connector READY (licensed instance provisioned)` };
      case "LICENSE_UNAVAILABLE":
        return { status: "LICENSE_UNAVAILABLE", detail: `${this.name} is installed but no valid license is available — connector disabled, baseline analysis unaffected (§96)` };
      case "INSTALLED":
        return { status: "INSTALLED", detail: `${this.name} installation detected; license state not yet verified` };
      default:
        return { status: "NOT_CONFIGURED", detail: `${this.name} is not installed/provisioned on this node — an optional commercial connector (§36–§39); open-source baseline coverage is unaffected` };
    }
  }

  /** Import an analysis report produced by the licensed tool for a
   *  REGISTERED artifact. Fails closed unless the connector is READY. */
  async importReport(artifactId: string): Promise<ParsedBinary> {
    const state = await this.licenseState();
    if (state !== "READY") return emptyParsedBinary({ connectorUnavailable: 1 });
    const artifact = await this.deps.artifacts.getArtifact(artifactId);
    if (!artifact) return emptyParsedBinary({ artifactUnknown: 1 });
    const t = this.transport();
    if (!t) return emptyParsedBinary({ connectorUnavailable: 1 });
    const report = await t.fetchReport(artifact.sha256);
    if (!report) return emptyParsedBinary({ reportMissing: 1 });
    return parseBinaryGhidraReport(report, {
      toolSlug: this.slug, artifactId: artifact.id,
      artifactHash: artifact.sha256, artifactName: artifact.name,
    });
  }
}

/** §36–§38: IDA connector — licensed installations only, approved
 *  idalib/headless use, IDAPython never accepted from the API. */
export class IdaConnector extends CommercialBinaryConnector {
  readonly slug = "ida";
  readonly name = "IDA";
  protected transport() { return this.deps.transports.ida; }
}

/** §39: Binary Ninja connector — API availability is part of the
 *  license state; export/import follows the same report schema. */
export class BinaryNinjaConnector extends CommercialBinaryConnector {
  readonly slug = "binary-ninja";
  readonly name = "Binary Ninja";
  protected transport() { return this.deps.transports.binaryNinja; }
}
