# ldapsearch

**Posture:** DEFENSIVE — typed queries only (Prompt 15)

The ldapsearch adapter issues platform-generated typed queries only
(§14/§41): a fixed query-kind catalog (domain info, users, groups,
computers, trusts, password policy, GPO metadata) with fixed filters
and attribute sets, LDAPS preferred, paged and size/time bounded.
Raw filters, custom base DNs and any credential-shaped configuration
key are refused by the adapter's configuration validation; filter
and DN values are RFC 4515/4514-escaped (§114).
