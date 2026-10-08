# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.0-rc.1 (DSRclone RC1) | ✅ current release candidate |
| < 1.0.0 (phase builds) | ❌ pre-release development snapshots |

## Reporting a vulnerability

DSRclone is an authorized security-assessment platform; we take
reports about the platform itself seriously.

- **Contact:** open a private security advisory on the GitHub
  repository (`github.com/xorudra/dsrclone/security/advisories`), or
  email the maintainer at the address listed on the repository
  owner's GitHub profile. (Placeholder by design — replace with the
  operating organization's security contact before public launch.)
- Include: affected version/commit, component, reproduction steps,
  and impact. Please do not include real credentials, real target
  data, or third-party personal data in a report.
- **Do not** open a public issue for a suspected vulnerability, and
  do not test against systems you are not authorized to assess.

## Responsible disclosure

We follow coordinated disclosure: we will acknowledge a report,
investigate, and fix or document the issue before public discussion,
and we ask reporters to give us a reasonable window to do so. Reports
that respect authorization boundaries and user privacy are welcomed
and will be credited with the reporter's consent.

## Scope notes

- Findings produced **by** DSRclone about a customer's authorized
  targets belong to that customer's engagement, not to this policy.
- Deliberate design properties (governed offensive-tool descriptors,
  NOT_CONFIGURED transports, fixture-only verification data) are
  documented in `docs/release/rc1-audit.md` and are not
  vulnerabilities.
