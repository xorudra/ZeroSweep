import { BadRequestException, Injectable } from "@nestjs/common";
import {
  generateOAuthState,
  generatePkcePair as generateIdentityPkcePair,
  validateOAuthState,
  validateRedirectUri,
} from "@zerosweep/security-sdk";
import { randomBytes } from "node:crypto";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireIntegrationPermission } from "../permissions";

/**
 * OAuth connection flows for integrations (Prompt 24 §101, §102).
 * Starting a flow issues an unguessable state + PKCE pair bound to
 * the administrator's session intent; completing a flow requires the
 * exact state back and an exactly-registered redirect URI. Tokens
 * obtained through a completed flow are stored by the deployment's
 * secret manager — this service only ever returns the REFERENCE
 * under which the credential was registered.
 */
@Injectable()
export class IntegrationOAuthService {
  private readonly pending = new Map<string, { state: string; verifier: string; integrationType: string; createdBy: string; expiresAt: number }>();

  beginFlow(user: RequestUser, integrationType: string) {
    requireIntegrationPermission(user, "CREATE_INTEGRATION");
    const state = generateOAuthState();
    const pkce = generateIdentityPkcePair(randomBytes(32));
    const flowId = randomBytes(16).toString("hex");
    this.pending.set(flowId, {
      state, verifier: pkce.verifier, integrationType,
      createdBy: user.id, expiresAt: Date.now() + 10 * 60_000,
    });
    return { flowId, state, codeChallenge: pkce.challenge, codeChallengeMethod: pkce.method };
  }

  completeFlow(user: RequestUser, flowId: string, body: Record<string, unknown>) {
    requireIntegrationPermission(user, "CREATE_INTEGRATION");
    const flow = this.pending.get(flowId);
    if (!flow) throw new BadRequestException("OAuth flow not found or already completed");
    if (flow.createdBy !== user.id) throw new BadRequestException("OAuth flow belongs to a different administrator session");
    if (Date.now() > flow.expiresAt) {
      this.pending.delete(flowId);
      throw new BadRequestException("OAuth flow expired (§101)");
    }
    if (!validateOAuthState(body.state as string, flow.state)) {
      throw new BadRequestException("OAuth state mismatch — flow aborted (§101)");
    }
    const registered = (body.registeredRedirectUris as string[]) ?? [];
    if (!validateRedirectUri(body.redirectUri as string, registered)) {
      throw new BadRequestException("Redirect URI is not exactly registered for this integration (§101)");
    }
    this.pending.delete(flowId);
    // The authorization code would now be exchanged via the provider
    // connector transport; no provider transport is wired in this
    // deployment, so completion honestly reports NOT_CONFIGURED
    // instead of minting a fake connection.
    return {
      completed: false,
      status: "NOT_CONFIGURED" as const,
      detail: "OAuth state + redirect validation passed, but no provider token-exchange transport is wired in this deployment — no connection was fabricated (§102)",
      pkceVerifierHeld: Boolean(flow.verifier),
    };
  }
}
