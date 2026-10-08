# SAML Security (Prompt 23)

The SAML validator is deliberately narrow — everything outside the
accepted profile is rejected, not ignored:

- XXE/DTD constructs (DOCTYPE, ENTITY, SYSTEM) are rejected BEFORE
  parsing; document size is capped; only predefined XML entities decode.
- Signatures: enveloped `rsa-sha256` only, SHA-256 digests only,
  inclusive C14N (REC-xml-c14n-20010315) only. Unsigned responses,
  tampered assertions, wrong keys and algorithm substitutions fail.
- The Reference must identify the Assertion; issuer must equal the
  configured IdP entity ID; audience must equal the SP entity ID;
  recipient must equal the ACS URL; `InResponseTo` must match a live
  SP-initiated request; NotBefore/NotOnOrAfter enforced with a small
  clock-skew window.
- Assertion IDs are consumed once (replay table, §55).
- Digest/signature are computed over the platform's own canonicalizer,
  validated end-to-end against fixture IdP responses
  (`buildSignedResponse`). Encrypted assertions: NOT_SUPPORTED.
