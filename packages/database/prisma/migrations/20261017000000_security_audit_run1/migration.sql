-- Security audit 2026-10-16 (run-1 remediation), additive only:
-- SamlProviderConfig.acsUrl — operator-configured SP ACS URL. The SAML
-- Recipient/Destination expectation is always this configured value,
-- never request input (saml-acs-recipient-attacker-controlled).

ALTER TABLE "SamlProviderConfig" ADD COLUMN "acsUrl" TEXT NOT NULL DEFAULT '';
