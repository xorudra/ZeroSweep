import { Injectable } from "@nestjs/common";
import { UnconfiguredIntegrationTransport, type IntegrationTransport } from "@dsrclone/security-sdk";

/**
 * Transport factory seam. The production implementation ALWAYS
 * returns the deliberately unconfigured transport: no provider
 * endpoints or credentials are wired in this deployment, so every
 * live provider operation honestly reports NOT_CONFIGURED instead of
 * fabricating connectivity (the pattern of Prompts 13/14/15/20).
 * Tests substitute fixture transports serving recorded payloads.
 */
export type IntegrationRow = Record<string, unknown> & { type: string };

@Injectable()
export class IntegrationTransportFactory {
  forIntegration(integration: IntegrationRow): IntegrationTransport {
    return new UnconfiguredIntegrationTransport(integration.type);
  }
}

/** Secret reference resolution seam (mirrors the Prompt 23 §48/§67
 *  semantics): `env:<VAR>` references resolve against the process
 *  environment, which the deployment's secret manager populates. Any
 *  other reference is unresolvable in this layer and dependent
 *  features honestly report NOT_CONFIGURED. Secret VALUES are never
 *  stored, logged, or returned by any API. */
@Injectable()
export class IntegrationSecretResolver {
  resolve(reference: string | null | undefined): string | null {
    if (!reference) return null;
    if (reference.startsWith("env:")) {
      return process.env[reference.slice(4)] ?? null;
    }
    return null;
  }
}
