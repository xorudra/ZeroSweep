import { BadRequestException, ForbiddenException, NotFoundException } from "@nestjs/common";
import { FIXTURE_AP_WPA2, FIXTURE_PCAP_BYTES, FIXTURE_PCAP_SHA256 } from "@dsrclone/security-sdk";
import { WirelessSecurityService } from "./wireless-security.service";

/**
 * Prompt 19 §77–§96 API discipline: environments/sensors/captures
 * are tenant-isolated; captures are proven from MAGIC BYTES and
 * deduped by SHA-256 (§26/§27); raw capture references are
 * permission-gated + audited per access (§30); ordinary AP views
 * mask BSSIDs (§73) and stations are pseudonymized (§90); scans are
 * gated on a VERIFIED target; active-tool and command-shaped lab
 * requests are refused + audited (§93); observed networks never
 * become verified targets (§94).
 */

const owner = { id: "u-1", email: "r@example.com", organizationId: "org-1", role: "OWNER" as const };
const engineer = { id: "u-5", email: "e@example.com", organizationId: "org-1", role: "SECURITY_ENGINEER" as const };
const analyst = { id: "u-4", email: "a@example.com", organizationId: "org-1", role: "ANALYST" as const };
const viewer = { id: "u-3", email: "v@example.com", organizationId: "org-1", role: "VIEWER" as const };
const foreign = { id: "u-2", email: "x@example.com", organizationId: "org-2", role: "OWNER" as const };

interface State {
  targets: Array<Record<string, unknown>>;
  environments: Array<Record<string, unknown>>;
  scopes: Array<Record<string, unknown>>;
  sensors: Array<Record<string, unknown>>;
  accessPoints: Array<Record<string, unknown>>;
  stations: Array<Record<string, unknown>>;
  observations: Array<Record<string, unknown>>;
  history: Array<Record<string, unknown>>;
  captures: Array<Record<string, unknown>>;
  profiles: Array<Record<string, unknown>>;
  events: Array<Record<string, unknown>>;
  drift: Array<Record<string, unknown>>;
  sessions: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  planScopes: Array<Record<string, unknown>>;
  assessments: Array<Record<string, unknown>>;
  audits: Array<Record<string, unknown>>;
}

function freshState(): State {
  return {
    targets: [
      { id: "t-wl", workspaceId: "ws-1", name: "HQ wireless", type: "WIRELESS_LAB", value: "env-1", verified: true, status: "VERIFIED" },
      { id: "t-wl2", workspaceId: "ws-1", name: "Lab wireless", type: "WIRELESS_LAB", value: "env-2", verified: false, status: "DRAFT" },
    ],
    environments: [
      { id: "env-1", workspaceId: "ws-1", name: "HQ wireless", locationLabel: "HQ", environment: "CORPORATE", criticality: "HIGH", authorizationId: "authz-1", status: "ACTIVE", createdBy: "u-1", createdAt: new Date(0) },
      { id: "env-2", workspaceId: "ws-1", name: "Lab wireless", locationLabel: null, environment: "LAB", criticality: "LOW", authorizationId: null, status: "ACTIVE", createdBy: "u-1", createdAt: new Date(0) },
    ],
    scopes: [
      { id: "wsc-1", environmentId: "env-1", bssidAllowlist: [FIXTURE_AP_WPA2], ssidAllowlist: ["example-corp-wifi"], channelAllowlist: [6], frequencyBands: ["2.4GHZ"], maxCaptureDurationSeconds: 3600, approvedInterfaces: ["wlan1"] },
    ],
    sensors: [
      { id: "sen-1", workspaceId: "ws-1", environmentId: "env-1", name: "sensor-hq-1", host: null, adapter: "ALFA", driver: null, interfaceName: "wlan1", supportedBands: ["2.4GHZ"], monitorModeCapable: true, health: "UNKNOWN", status: "REGISTERED", lastSeen: null, createdAt: new Date(0) },
      { id: "sen-2", workspaceId: "ws-1", environmentId: "env-1", name: "sensor-rogue-iface", host: null, adapter: null, driver: null, interfaceName: "wlan9", supportedBands: [], monitorModeCapable: false, health: "UNKNOWN", status: "REGISTERED", lastSeen: null, createdAt: new Date(0) },
    ],
    accessPoints: [
      { id: "ap-1", workspaceId: "ws-1", environmentId: "env-1", bssid: FIXTURE_AP_WPA2, ssid: "example-corp-wifi", ssidHidden: false, vendor: "Aruba Networks", channel: 6, frequencyMhz: 2437, band: "2.4GHZ", securityMode: "WPA2", encryption: "CCMP", authentication: "PSK", pmf: "UNKNOWN", wpsAdvertised: false, signalDbm: -42, approvedStatus: "APPROVED", firstSeen: new Date(0), lastSeen: new Date(0) },
    ],
    stations: [
      { id: "sta-row-1", workspaceId: "ws-1", environmentId: "env-1", addressFingerprint: "sta-b488d9c80fbd7a51", rawAddress: null, accessPointId: "ap-1", associatedBssid: FIXTURE_AP_WPA2, signalDbm: -48, source: "kismet", firstSeen: new Date(0), lastSeen: new Date(0) },
    ],
    observations: [], history: [],
    captures: [
      { id: "cap-1", workspaceId: "ws-1", environmentId: "env-1", sensorId: "sen-1", name: "survey-1.pcap", sha256: FIXTURE_PCAP_SHA256, format: "PCAP", sizeBytes: BigInt(FIXTURE_PCAP_BYTES.length), startTime: null, endTime: null, channels: [6], artifactReference: "s3://protected/cap-1", status: "APPROVED", sanitizationStatus: "SANITIZED", analysisArtifacts: {}, createdBy: "u-1", createdAt: new Date(0) },
    ],
    profiles: [], events: [], drift: [], sessions: [], findings: [],
    planScopes: [], assessments: [], audits: [],
  };
}

const WORKSPACES = [
  { id: "ws-1", organizationId: "org-1", deletedAt: null, createdAt: new Date(0) },
  { id: "ws-2", organizationId: "org-2", deletedAt: null, createdAt: new Date(0) },
];

let seq = 100;
function fakePrisma(state: State) {
  const matchValue = (actual: unknown, expected: unknown): boolean => {
    if (expected === undefined) return true;
    if (expected !== null && typeof expected === "object") {
      const e = expected as Record<string, unknown>;
      if (Array.isArray(e.in)) return e.in.includes(actual);
      if (typeof e.contains === "string") return typeof actual === "string" && actual.toLowerCase().includes((e.contains as string).toLowerCase());
    }
    return actual === expected;
  };
  const match = (row: Record<string, unknown>, where: Record<string, unknown> = {}) =>
    Object.entries(where).every(([k, v]) => matchValue(row[k], v));
  const model = (rows: Array<Record<string, unknown>>, prefix: string) => ({
    findMany: async (args: { where?: Record<string, unknown> } = {}) => rows.filter((r) => match(r, args.where)),
    findFirst: async (args: { where?: Record<string, unknown> } = {}) => rows.find((r) => match(r, args.where)) ?? null,
    findUnique: async (args: { where: Record<string, unknown> }) => {
      if (typeof args.where.id === "string") return rows.find((r) => r.id === args.where.id) ?? null;
      return null;
    },
    count: async (args: { where?: Record<string, unknown> } = {}) => rows.filter((r) => match(r, args.where)).length,
    create: async (args: { data: Record<string, unknown> }) => {
      const row = { id: `${prefix}-${++seq}`, createdAt: new Date(0), ...args.data };
      rows.push(row);
      return row;
    },
    update: async (args: { where: { id: string }; data: Record<string, unknown> }) => {
      const row = rows.find((r) => r.id === args.where.id);
      if (row) Object.assign(row, args.data);
      return row;
    },
    updateMany: async (args: { where?: Record<string, unknown>; data: Record<string, unknown> }) => {
      let n = 0;
      for (const row of rows) if (match(row, args.where)) { Object.assign(row, args.data); n++; }
      return { count: n };
    },
  });
  return {
    workspace: {
      findFirst: async (args: { where: { organizationId: string } }) =>
        WORKSPACES.find((w) => w.organizationId === args.where.organizationId) ?? null,
    },
    target: model(state.targets, "t"),
    wirelessEnvironment: model(state.environments, "env"),
    wirelessScope: model(state.scopes, "wsc"),
    wirelessSensor: model(state.sensors, "sen"),
    wirelessAccessPoint: model(state.accessPoints, "ap"),
    wirelessStation: model(state.stations, "sta"),
    wirelessObservation: model(state.observations, "obs"),
    wirelessAccessPointHistory: model(state.history, "hist"),
    wirelessCapture: model(state.captures, "cap"),
    approvedWirelessProfile: model(state.profiles, "prof"),
    wirelessSecurityEvent: model(state.events, "evt"),
    wirelessDriftEvent: model(state.drift, "drift"),
    wirelessScanSession: model(state.sessions, "sess"),
    finding: model(state.findings, "f"),
    scope: model(state.planScopes, "scp"),
    assessment: model(state.assessments, "eng"),
  };
}

function makeService(state: State) {
  const prisma = fakePrisma(state);
  const audit = { record: async (e: Record<string, unknown>) => { state.audits.push(e); } };
  const orchestration = { startScan: async () => ({ scanId: "scan-1", status: "QUEUED" }) };
  return new WirelessSecurityService(prisma as never, audit as never, orchestration as never);
}

describe("Prompt 19 API — environments & gated scans (§77/§94/§95)", () => {
  it("creates an environment with a sanitized scope and an UNVERIFIED registration target", async () => {
    const state = freshState();
    const svc = makeService(state);
    const res = await svc.createEnvironment(engineer, {
      name: "Branch office", environment: "OFFICE", criticality: "MEDIUM",
      scope: { bssidAllowlist: ["AA-BB-CC-DD-EE-FF"], ssidAllowlist: ["corp\u001b[31m-evil"], channelAllowlist: [6], frequencyBands: ["2.4GHZ"], maxCaptureDurationSeconds: 3600, approvedInterfaces: ["wlan1"] },
    });
    expect(res.id).toBeTruthy();
    const target = state.targets.find((t) => t.value === res.id);
    expect(target?.type).toBe("WIRELESS_LAB");
    expect(target?.verified).toBe(false); // §94: never auto-verified
    const scope = state.scopes.find((s) => s.environmentId === res.id);
    expect(scope?.bssidAllowlist).toEqual(["aa:bb:cc:dd:ee:ff"]);
    expect((scope?.ssidAllowlist as string[])[0]).not.toContain("[31m");
    expect(state.audits.some((a) => a.action === "WIRELESS_ENVIRONMENT_CREATED")).toBe(true);
  });

  it("refuses scans for unverified environments and runs gated scans for verified ones", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.startScan(owner, "env-2", { profile: "WIRELESS_PASSIVE_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
    state.planScopes.push({ id: "scp-1", workspaceId: "ws-1", targetId: "t-wl", name: "wireless scope", rules: {} });
    state.assessments.push({
      id: "eng-1", workspaceId: "ws-1", targetId: "t-wl", scopeId: "scp-1", profile: "WIRELESS_PASSIVE_BASELINE",
      status: "APPROVED", createdBy: "u-creator", approvedBy: "u-approver",
    });
    const started = await svc.startScan(owner, "env-1", { profile: "WIRELESS_PASSIVE_BASELINE" });
    expect((started as { scanId?: string }).scanId).toBe("scan-1");
    expect(state.sessions.some((s) => s.environmentId === "env-1")).toBe(true);
    expect(state.audits.some((a) => a.action === "WIRELESS_SCAN_STARTED")).toBe(true);
  });

  it("scan start refuses when no pre-approved assessment exists — and mints neither scope nor assessment", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.startScan(owner, "env-1", { profile: "WIRELESS_PASSIVE_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
    expect(state.planScopes).toHaveLength(0);
    expect(state.assessments).toHaveLength(0);
    expect(state.sessions).toHaveLength(0);
  });

  it("tenant isolation: org B cannot read org A's environment (§95)", async () => {
    const svc = makeService(freshState());
    await expect(svc.getEnvironment(foreign, "env-1")).rejects.toBeInstanceOf(NotFoundException);
    const list = await svc.listEnvironments(foreign);
    expect(list.items).toHaveLength(0);
  });

  it("RBAC: a VIEWER cannot create environments (§79)", async () => {
    const svc = makeService(freshState());
    await expect(svc.createEnvironment(viewer, { name: "x", environment: "CORPORATE", criticality: "LOW" })).rejects.toBeInstanceOf(ForbiddenException);
  });
});

describe("Prompt 19 API — captures (§26/§27/§30/§83–§85)", () => {
  it("accepts a capture proven from magic bytes, dedupes by SHA-256, audits the upload", async () => {
    const state = freshState();
    state.captures = [];
    const svc = makeService(state);
    const res = await svc.uploadCapture(analyst, {
      environmentId: "env-1", name: "survey.pcap", contentBase64: FIXTURE_PCAP_BYTES.toString("base64"),
      expectedSha256: FIXTURE_PCAP_SHA256,
    });
    expect(res.format).toBe("PCAP");
    expect(res.sha256).toBe(FIXTURE_PCAP_SHA256);
    const dup = await svc.uploadCapture(analyst, {
      environmentId: "env-1", name: "renamed.pcapng", contentBase64: FIXTURE_PCAP_BYTES.toString("base64"),
    });
    expect(dup.alreadyRegistered).toBe(true);
    expect(state.audits.some((a) => a.action === "WIRELESS_CAPTURE_UPLOADED")).toBe(true);
  });

  it("refuses a hash mismatch and unproven content (§26/§83/§84)", async () => {
    const svc = makeService(freshState());
    await expect(svc.uploadCapture(owner, {
      environmentId: "env-1", name: "x.pcap", contentBase64: FIXTURE_PCAP_BYTES.toString("base64"),
      expectedSha256: "0".repeat(64),
    })).rejects.toBeInstanceOf(BadRequestException);
    await expect(svc.uploadCapture(owner, {
      environmentId: "env-1", name: "x.pcap", contentBase64: Buffer.from("not a capture at all......").toString("base64"),
    })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("gates the raw artifact reference by permission and audits elevated access (§30)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const ordinary = await svc.getCapture(analyst, "cap-1");
    expect(ordinary.artifactReference).toBeNull();
    const elevated = await svc.getCapture(owner, "cap-1");
    expect(elevated.artifactReference).toBe("s3://protected/cap-1");
    expect(state.audits.some((a) => a.action === "WIRELESS_CAPTURE_ACCESSED")).toBe(true);
  });
});

describe("Prompt 19 API — sensors, AP views, lab policy (§12/§73/§90/§93)", () => {
  it("approves only sensors whose interface is in the environment's approved list (§12)", async () => {
    const svc = makeService(freshState());
    const ok = await svc.approveSensor(engineer, "sen-1");
    expect(ok.status).toBe("ACTIVE");
    await expect(svc.approveSensor(engineer, "sen-2")).rejects.toBeInstanceOf(BadRequestException);
  });

  it("masks BSSIDs for ordinary users and pseudonymizes stations (§73/§90)", async () => {
    const svc = makeService(freshState());
    const list = await svc.listAccessPoints(analyst);
    expect(list.items[0]?.bssid).toBe("00:0b:86:**:**:**");
    const full = await svc.listAccessPoints(owner);
    expect(full.items[0]?.bssid).toBe(FIXTURE_AP_WPA2);
    const detail = await svc.getAccessPoint(analyst, "ap-1");
    expect(detail.stations[0]?.addressFingerprint).toMatch(/^sta-/);
    expect(JSON.stringify(detail.stations)).not.toContain("rawAddress");
  });

  it("refuses command-shaped and active-tool lab requests + audits both (§93)", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.requestLabValidation(engineer, {
      environmentId: "env-2", justification: "lab check", deauthCommand: "aireplay-ng --deauth 10",
    })).rejects.toBeInstanceOf(BadRequestException);
    await expect(svc.requestLabValidation(engineer, {
      environmentId: "env-2", justification: "lab check", requestedTool: "wifite",
    })).rejects.toBeInstanceOf(BadRequestException);
    expect(state.audits.filter((a) => a.action === "WIRELESS_ACTIVE_TOOL_BLOCKED")).toHaveLength(2);
  });

  it("evaluates a clean lab request honestly: BLOCKED until §65 facts exist, never executed", async () => {
    const state = freshState();
    const svc = makeService(state);
    const res = await svc.requestLabValidation(engineer, { environmentId: "env-2", justification: "quarterly lab validation" });
    expect(res.status).toBe("BLOCKED");
    expect(res.reasons.length).toBeGreaterThan(0);
    expect(state.audits.some((a) => a.action === "WIRELESS_LAB_VALIDATION_REQUESTED")).toBe(true);
  });

  it("tool health is honest: wifite/hcxdumptool DISABLED, kismet instance NOT_CONFIGURED (§80)", async () => {
    const svc = makeService(freshState());
    const tools = await svc.listTools(owner);
    const bySlug = new Map(tools.items.map((t) => [t.slug, t]));
    expect(bySlug.get("wifite")?.health).toBe("DISABLED");
    expect(bySlug.get("hcxdumptool")?.health).toBe("DISABLED");
    expect(bySlug.get("wireshark")?.kind).toBe("ANALYST_TOOL");
    expect(tools.prohibitedAutomationNote).toContain("PROHIBITED AUTOMATION");
  });
});
