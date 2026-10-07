/**
 * Prompt 15 — fixture directory data (§104–§115).
 *
 * ALL data here is fictional documentation data for the invented
 * domain `corp.example` (example TLD, invented SIDs). No fixture ever
 * describes a real directory. The credential-leak fixture marker
 * (FIXTURE_CREDENTIAL_MARKER) is planted inside secret-shaped
 * attributes precisely so the §113 test can prove the pipeline strips
 * it: the marker must appear NOWHERE in normalized output.
 */
import type { DirectoryDomainRecord } from "./types";
import type { DirectoryCollectionTransport } from "./inventory";

export const FIXTURE_DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330";
export const FIXTURE_DC01_SID = `${FIXTURE_DOMAIN_SID}-1001`;
export const FIXTURE_DC02_SID = `${FIXTURE_DOMAIN_SID}-1002`;
export const FIXTURE_FILE01_SID = `${FIXTURE_DOMAIN_SID}-1003`;
export const FIXTURE_WEB01_SID = `${FIXTURE_DOMAIN_SID}-1004`;
export const FIXTURE_ALICE_SID = `${FIXTURE_DOMAIN_SID}-1101`;
export const FIXTURE_SVCWEB_SID = `${FIXTURE_DOMAIN_SID}-1102`;
export const FIXTURE_STALE_SID = `${FIXTURE_DOMAIN_SID}-1103`;
export const FIXTURE_PREAUTH_SID = `${FIXTURE_DOMAIN_SID}-1104`;
export const FIXTURE_ADMIN_SID = `${FIXTURE_DOMAIN_SID}-1105`;
export const FIXTURE_DAVE_SID = `${FIXTURE_DOMAIN_SID}-1106`;
export const FIXTURE_EVE_SID = `${FIXTURE_DOMAIN_SID}-1107`;
export const FIXTURE_KRBTGT_SID = `${FIXTURE_DOMAIN_SID}-502`;
export const FIXTURE_GROUP_B_SID = `${FIXTURE_DOMAIN_SID}-1201`; // "App Operators" (§107 Group B)
export const FIXTURE_HELPDESK_SID = `${FIXTURE_DOMAIN_SID}-1202`;
export const FIXTURE_DA_SID = `${FIXTURE_DOMAIN_SID}-512`; // Domain Admins
export const FIXTURE_CYCLE_A_SID = `${FIXTURE_DOMAIN_SID}-1301`;
export const FIXTURE_CYCLE_B_SID = `${FIXTURE_DOMAIN_SID}-1302`;

/** The §113 tripwire: planted in secret-shaped fixture attributes;
 *  must never survive normalization. */
export const FIXTURE_CREDENTIAL_MARKER = "Fixture-Password-Marker-123";
export const FIXTURE_NT_HASH_PAIR = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0";

const now = Date.now();
const daysAgo = (d: number) => Math.floor((now - d * 86400_000) / 1000);

/** BloodHound/SharpHound-shaped export for corp.example (§106/§107). */
export const FIXTURE_BLOODHOUND_EXPORT: Record<string, unknown> = {
  users: [
    {
      ObjectIdentifier: FIXTURE_ALICE_SID,
      Properties: {
        name: "ALICE@CORP.EXAMPLE", samaccountname: "alice", displayname: "Alice (fixture user A)",
        enabled: true, lastlogontimestamp: daysAgo(2), passwordlastset: daysAgo(30),
      },
    },
    {
      ObjectIdentifier: FIXTURE_SVCWEB_SID,
      Properties: {
        name: "SVC-WEB@CORP.EXAMPLE", samaccountname: "svc-web", displayname: "Web service account (fixture)",
        enabled: true, hasspn: true, serviceprincipalnames: ["HTTP/web.corp.example"],
        pwdneverexpires: true, lastlogontimestamp: daysAgo(1), passwordlastset: daysAgo(400),
        // §113 tripwires: secret-shaped attributes that MUST be stripped.
        userpassword: FIXTURE_CREDENTIAL_MARKER,
        nthash: FIXTURE_NT_HASH_PAIR,
      },
    },
    {
      ObjectIdentifier: FIXTURE_STALE_SID,
      Properties: {
        name: "BOB-STALE@CORP.EXAMPLE", samaccountname: "bob-stale", displayname: "Stale account (fixture)",
        enabled: true, lastlogontimestamp: daysAgo(400), passwordlastset: daysAgo(400),
      },
    },
    {
      ObjectIdentifier: FIXTURE_PREAUTH_SID,
      Properties: {
        name: "CAROL@CORP.EXAMPLE", samaccountname: "carol", displayname: "Preauth-disabled account (fixture)",
        enabled: true, dontreqpreauth: true, lastlogontimestamp: daysAgo(3), passwordlastset: daysAgo(60),
      },
    },
    {
      ObjectIdentifier: FIXTURE_ADMIN_SID,
      Properties: {
        name: "RUDRA@CORP.EXAMPLE", samaccountname: "rudra", displayname: "Rudra (fixture admin)",
        enabled: true, lastlogontimestamp: daysAgo(1), passwordlastset: daysAgo(20),
      },
    },
    {
      ObjectIdentifier: FIXTURE_DAVE_SID,
      Properties: {
        name: "DAVE@CORP.EXAMPLE", samaccountname: "dave", displayname: "Helpdesk user (fixture)",
        enabled: true, lastlogontimestamp: daysAgo(5), passwordlastset: daysAgo(45),
      },
    },
    {
      ObjectIdentifier: FIXTURE_EVE_SID,
      Properties: {
        name: "EVE@CORP.EXAMPLE", samaccountname: "eve", displayname: "Cycle group user (fixture)",
        enabled: true, lastlogontimestamp: daysAgo(4), passwordlastset: daysAgo(40),
      },
    },
    {
      ObjectIdentifier: FIXTURE_KRBTGT_SID,
      Properties: {
        name: "KRBTGT@CORP.EXAMPLE", samaccountname: "krbtgt", displayname: "KRBTGT (fixture)",
        enabled: false, passwordlastset: daysAgo(800),
      },
    },
  ],
  groups: [
    {
      ObjectIdentifier: FIXTURE_GROUP_B_SID,
      Properties: { name: "APP OPERATORS@CORP.EXAMPLE" },
      Members: [{ ObjectIdentifier: FIXTURE_ALICE_SID, ObjectType: "User" }],
    },
    {
      ObjectIdentifier: FIXTURE_DA_SID,
      Properties: { name: "DOMAIN ADMINS@CORP.EXAMPLE" },
      Members: [
        { ObjectIdentifier: FIXTURE_ADMIN_SID, ObjectType: "User" },
        { ObjectIdentifier: FIXTURE_HELPDESK_SID, ObjectType: "Group" },
      ],
    },
    {
      ObjectIdentifier: FIXTURE_HELPDESK_SID,
      Properties: { name: "HELPDESK@CORP.EXAMPLE" },
      Members: [{ ObjectIdentifier: FIXTURE_DAVE_SID, ObjectType: "User" }],
    },
    {
      // §108 cycle: Cycle A ↔ Cycle B nest into each other.
      ObjectIdentifier: FIXTURE_CYCLE_A_SID,
      Properties: { name: "CYCLE A@CORP.EXAMPLE" },
      Members: [
        { ObjectIdentifier: FIXTURE_CYCLE_B_SID, ObjectType: "Group" },
        { ObjectIdentifier: FIXTURE_EVE_SID, ObjectType: "User" },
      ],
    },
    {
      ObjectIdentifier: FIXTURE_CYCLE_B_SID,
      Properties: { name: "CYCLE B@CORP.EXAMPLE" },
      Members: [{ ObjectIdentifier: FIXTURE_CYCLE_A_SID, ObjectType: "Group" }],
    },
    {
      ObjectIdentifier: `${FIXTURE_DOMAIN_SID}-516`,
      Properties: { name: "DOMAIN CONTROLLERS@CORP.EXAMPLE" },
      Members: [
        { ObjectIdentifier: FIXTURE_DC01_SID, ObjectType: "Computer" },
        { ObjectIdentifier: FIXTURE_DC02_SID, ObjectType: "Computer" },
      ],
    },
  ],
  computers: [
    {
      ObjectIdentifier: FIXTURE_DC01_SID,
      Properties: {
        name: "DC01.CORP.EXAMPLE", operatingsystem: "Windows Server 2022", enabled: true,
        services: { ldapPresent: true, ldapsPresent: true, ldapSigningRequired: false, ldapChannelBinding: "never", smb1Enabled: true, smbSigningRequired: false },
      },
      Sessions: { Results: [{ UserId: FIXTURE_ALICE_SID, ComputerId: FIXTURE_DC01_SID }] },
    },
    {
      // §107 "Critical Computer C": a domain controller that Group B
      // administers.
      ObjectIdentifier: FIXTURE_DC02_SID,
      Properties: { name: "DC02.CORP.EXAMPLE", operatingsystem: "Windows Server 2022", enabled: true },
      LocalAdmins: { Results: [{ ObjectIdentifier: FIXTURE_GROUP_B_SID, ObjectType: "Group" }] },
    },
    {
      ObjectIdentifier: FIXTURE_FILE01_SID,
      Properties: { name: "FILE01.CORP.EXAMPLE", operatingsystem: "Windows Server 2019", enabled: true },
    },
    {
      ObjectIdentifier: FIXTURE_WEB01_SID,
      Properties: {
        name: "WEB01.CORP.EXAMPLE", operatingsystem: "Windows Server 2022", enabled: true,
        unconstraineddelegation: true,
      },
    },
  ],
  domains: [
    {
      ObjectIdentifier: FIXTURE_DOMAIN_SID,
      Properties: {
        name: "CORP.EXAMPLE", functionallevel: "2016",
        passwordpolicy: { minPasswordLength: 7, lockoutThreshold: 0 },
      },
      Trusts: [
        {
          TargetDomainName: "partner.example", TargetDomainSid: "S-1-5-21-5555555555-6666666666-7777777777",
          IsTransitive: true, TrustDirection: 3, TrustType: 2, SidFilteringEnabled: false, SelectiveAuthentication: false,
        },
      ],
    },
  ],
  ous: [
    {
      ObjectIdentifier: `${FIXTURE_DOMAIN_SID}-OU1`,
      Properties: { name: "Servers", distinguishedname: "OU=Servers,DC=corp,DC=example" },
      Links: [{ GUID: `${FIXTURE_DOMAIN_SID}-GPO1` }],
    },
  ],
  gpos: [
    {
      ObjectIdentifier: `${FIXTURE_DOMAIN_SID}-GPO1`,
      Properties: { name: "{31B2F340-016D-11D2-945F-00C04FB984F9}", displayname: "Default Domain Policy (fixture)" },
    },
  ],
};

/** ACL-edge variant of the fixture (§67): a non-privileged group holds
 *  GENERIC_ALL over the Domain Admins group (an ACE on the DA group). */
export const FIXTURE_CONTRACTORS_SID = `${FIXTURE_DOMAIN_SID}-1401`;
export const FIXTURE_BLOODHOUND_ACL_EXPORT: Record<string, unknown> = (() => {
  const clone = JSON.parse(JSON.stringify(FIXTURE_BLOODHOUND_EXPORT)) as Record<string, unknown>;
  const groups = clone.groups as Record<string, unknown>[];
  const da = groups.find((g) => g.ObjectIdentifier === FIXTURE_DA_SID);
  if (da) {
    da.Aces = [{ PrincipalSID: FIXTURE_CONTRACTORS_SID, PrincipalType: "Group", RightName: "GenericAll", IsInherited: false }];
  }
  groups.push({
    ObjectIdentifier: FIXTURE_CONTRACTORS_SID,
    Properties: { name: "EXTERNAL CONTRACTORS@CORP.EXAMPLE" },
    Members: [],
  });
  return clone;
})();

/** PingCastle XML report fixture (§109): one krbtgt rule that maps to
 *  the canonical AD_KRBTGT_OLD rule, one zero-point rule (no finding). */
export const FIXTURE_PINGCASTLE_XML = `<?xml version="1.0" encoding="utf-8"?>
<PingCastleData>
  <HealthcheckData DomainName="corp.example" GlobalScore="55">
    <DomainFQDN>corp.example</DomainFQDN>
    <RiskRules>
      <HealthcheckRiskRule>
        <Category>Privileged Accounts</Category>
        <Title>KRBTGT password age</Title>
        <Model>P_Krbtgt</Model>
        <Points>40</Points>
        <Description>The krbtgt password has not been changed for a long time (fixture report).</Description>
        <TechnicalExplanation>Fixture technical explanation for the krbtgt rotation rule.</TechnicalExplanation>
        <Recommendation>Rotate the krbtgt password twice.</Recommendation>
      </HealthcheckRiskRule>
      <HealthcheckRiskRule>
        <Category>Network</Category>
        <Title>Auditing is enabled</Title>
        <Model>P_AuditEnabled</Model>
        <Points>0</Points>
        <Description>Positive observation (fixture) — zero points, never a finding.</Description>
      </HealthcheckRiskRule>
    </RiskRules>
  </HealthcheckData>
</PingCastleData>`;

/** SMB fixture (§110): a readable share, a writable anonymous share and
 *  a restricted share + SMB1/signing metadata. No file content exists
 *  in this fixture because contents are never collected (§44). */
export const FIXTURE_SMBMAP_JSON: Record<string, unknown> = {
  hosts: [
    {
      host: "FILE01.CORP.EXAMPLE",
      shares: [
        { name: "Public", permissions: "READ, WRITE", anonymous: true },
        { name: "Finance", permissions: "NO ACCESS" },
        { name: "Archive", permissions: "READ ONLY" },
      ],
    },
  ],
};

export const FIXTURE_ENUM4LINUX_JSON: Record<string, unknown> = {
  target: "FILE01.CORP.EXAMPLE",
  smb: { dialect: "SMB 1.0", signing_required: false },
  shares: [{ name: "Public" }, { name: "Finance" }],
};

/** AD CS fixture (§111): an ESC1-style template + a CA with the ESC6
 *  edit flag + one clean template. */
export const FIXTURE_CERTIPY_JSON: Record<string, unknown> = {
  "Certificate Authorities": {
    "0": {
      "CA Name": "Corp Issuing CA (fixture)",
      "DNS Name": "DC01.CORP.EXAMPLE",
      "Edit Flags": "EDITF_ATTRIBUTESUBJECTALTNAME2",
      "Web Enrollment": "Disabled",
    },
  },
  "Certificate Templates": {
    "0": {
      "Template Name": "VulnTemplate (fixture)",
      "Certificate Authorities": ["Corp Issuing CA (fixture)"],
      "Enabled": true,
      "Enrollee Supplies Subject": true,
      "Extended Key Usage": ["1.3.6.1.5.5.7.3.2"],
      "Manager Approval Required": false,
      "Authorized Signatures Required": 0,
      "Enrollment Permissions": { broadLowPrivilegedEnrollment: true },
    },
    "1": {
      "Template Name": "Standard User (fixture)",
      "Certificate Authorities": ["Corp Issuing CA (fixture)"],
      "Enabled": true,
      "Enrollee Supplies Subject": false,
      "Extended Key Usage": ["1.3.6.1.5.5.7.3.2"],
      "Manager Approval Required": true,
      "Authorized Signatures Required": 0,
    },
  },
};

/** §115 hostile directory strings: markup, terminal escapes, bidi
 *  controls and an oversized name — all must be stored/displayed
 *  safely (stripped + bounded). */
export const FIXTURE_HOSTILE_USER: Record<string, unknown> = {
  ObjectIdentifier: `${FIXTURE_DOMAIN_SID}-1999`,
  Properties: {
    name: "HOSTILE@CORP.EXAMPLE",
    samaccountname: "hostile",
    displayname: "<script>alert(1)</script>\u001b[31mRED\u202e<script>",
    enabled: true,
    description: "x".repeat(20000),
  },
};

export const FIXTURE_DOMAIN_RECORD: DirectoryDomainRecord = {
  id: "fixture-domain-1",
  dnsName: "corp.example",
  netbiosName: "CORP",
  domainSid: FIXTURE_DOMAIN_SID,
  functionalLevel: "2016",
  credentialReference: "vault:fixtures/ad/corp-example",
  identityKind: "READ_ONLY_DOMAIN",
  dcHosts: ["DC01.CORP.EXAMPLE", "DC02.CORP.EXAMPLE"],
};

/** A previous-snapshot variant for drift tests (§80): in the PREVIOUS
 *  snapshot Helpdesk was NOT yet nested into Domain Admins and the
 *  partner.example trust did not exist — so diffing previous → current
 *  yields NEW_PRIVILEGED_MEMBER (dave) and NEW_TRUST (partner.example). */
export function fixturePreviousBloodHoundExport(): Record<string, unknown> {
  const clone = JSON.parse(JSON.stringify(FIXTURE_BLOODHOUND_EXPORT)) as Record<string, unknown>;
  const groups = clone.groups as Record<string, unknown>[];
  const da = groups.find((g) => g.ObjectIdentifier === FIXTURE_DA_SID);
  if (da) da.Members = [{ ObjectIdentifier: FIXTURE_ADMIN_SID, ObjectType: "User" }];
  const domains = clone.domains as Record<string, unknown>[];
  (domains[0] as Record<string, unknown>).Trusts = [];
  return clone;
}

/** Deterministic fixture transport (§104): returns the recorded
 *  collection; performs no network I/O and no mutation, ever. */
export function createFixtureDirectoryTransport(
  data: import("./types").NormalizedDirectoryData,
  versions: Record<string, string> = { fixture: "1.0.0" },
): DirectoryCollectionTransport {
  return {
    async collect() {
      return { data, collectorVersions: versions, findingsCount: 0, sessionsDropped: 0, mutationCalls: [] };
    },
  };
}
