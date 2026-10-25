import { describe, expect, it } from "vitest";
import {
  ARJUN_JSON, FFUF_JSON, FEROX_JSONL, GOBUSTER_TEXT, WFUZZ_JSON,
  FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  createReconAdapters, createWebDiscoveryAdapters, reconHealthBySlug, type FixtureResponse,
} from "@zerosweep/security-sdk";
import { StageExecutor, EXECUTABLE_SLUGS } from "./executors/stage-executor";
import { DagRunner } from "./consumers/dag-runner";
import { FakeStore } from "./testing/fake-store";

/**
 * Prompt 6 end-to-end scenarios (§56–§57, §60): the REAL web-discovery
 * adapters (ffuf, Feroxbuster, Gobuster, Wfuzz, Arjun) run the full
 * pipeline against RECORDED FIXTURE OUTPUT of the §56 controlled test
 * application — no binary executes, no network is touched, no live target
 * exists. Fixtures use example.com only.
 */

const SUBFINDER = '{"host":"api.example.com","input":"example.com","source":"crtsh"}';
const DNSX = '{"host":"api.example.com","a":["93.184.216.34"],"status_code":"NOERROR"}';
const HTTPX = '{"url":"https://example.com","host":"example.com","port":443,"scheme":"https","status_code":200,"title":"Home","webserver":"nginx","tech":["nginx"],"a":["93.184.216.34"]}';
const WHATWEB = JSON.stringify([{ target: "https://example.com/", http_status: 200, plugins: { nginx: { version: ["1.24.0"] }, WordPress: { version: ["6.4.2"], certainty: 100 } } }]);
const KATANA = [
  '{"request":{"method":"GET","endpoint":"https://example.com/"},"response":{"status_code":200}}',
  '{"request":{"method":"GET","endpoint":"https://example.com/search?q=shoes"},"response":{"status_code":200}}',
].join("\n");

function fullFixtures(): Record<string, FixtureResponse> {
  return {
    subfinder: { stdout: SUBFINDER, version: "2.6.6" },
    amass: { stdout: "", version: "4.2.0" },
    assetfinder: { stdout: "api.example.com\n" },
    findomain: { stdout: "api.example.com\n" },
    dnsx: { stdout: DNSX, version: "1.2.2" },
    gau: { stdout: "https://example.com/old-page?ref=home" },
    waybackurls: { stdout: "https://example.com/older-page" },
    httpx: { stdout: HTTPX, version: "1.6.9" },
    whatweb: { stdout: WHATWEB, version: "0.5.5" },
    katana: { stdout: KATANA, version: "1.1.0" },
    ffuf: { stdout: FFUF_JSON, version: "2.1.0" },
    feroxbuster: { stdout: FEROX_JSONL, version: "2.0.4" },
    gobuster: { stdout: GOBUSTER_TEXT, version: "3.6" },
    wfuzz: { stdout: WFUZZ_JSON, version: "2.4.5" },
    arjun: { stdout: ARJUN_JSON },
  };
}

function makeWorld(
  fixtures: Record<string, FixtureResponse>,
  profile: "WEB_BASELINE" | "WEB_COMPREHENSIVE",
  execFixtures: Record<string, FixtureResponse> = fixtures,
) {
  const planRegistry = new ToolRegistry();
  planRegistry.register(new MockSecurityAdapter());
  planRegistry.register(new LocalEchoAdapter());
  const planAdapters = [...createReconAdapters(new FixtureToolRunner(fixtures)), ...createWebDiscoveryAdapters(new FixtureToolRunner(fixtures))];
  for (const a of planAdapters) planRegistry.register(a);
  const store = new FakeStore(profile, {
    planRegistry,
    healthBySlug: reconHealthBySlug(planAdapters),
    executableSlugs: [...EXECUTABLE_SLUGS],
    targetType: "WEB_APPLICATION",
  });
  const runner = new FixtureToolRunner(execFixtures);
  const execRegistry = new ToolRegistry();
  execRegistry.register(new MockSecurityAdapter());
  execRegistry.register(new LocalEchoAdapter());
  for (const a of createReconAdapters(runner)) execRegistry.register(a);
  for (const a of createWebDiscoveryAdapters(runner)) execRegistry.register(a);
  const executor = new StageExecutor(execRegistry, store);
  return { runner, store, dag: new DagRunner(store, executor) };
}

describe("Prompt 6 web-discovery E2E — WEB_COMPREHENSIVE (fixtures)", () => {
  it("runs content + parameter discovery end-to-end: provenance, classification, scope, zero findings", async () => {
    const { runner, store, dag } = makeWorld(fullFixtures(), "WEB_COMPREHENSIVE");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.stages.get("CONTENT_DISCOVERY")).toBe("COMPLETED");
    expect(store.stages.get("PARAMETER_DISCOVERY")).toBe("COMPLETED");
    expect(store.stages.get("WEB_SURFACE_NORMALIZATION")).toBe("COMPLETED");

    // All five Prompt 6 adapters actually executed (wfuzz twice: content
    // stage uses its CONTENT template, parameter stage its PARAMETER one).
    const executed = [...store.executions.values()].map((e) => `${e.stageType}:${e.adapterSlug}`);
    for (const slug of ["ffuf", "feroxbuster", "gobuster"]) expect(executed).toContain(`CONTENT_DISCOVERY:${slug}`);
    expect(executed).toContain("PARAMETER_DISCOVERY:arjun");
    expect(executed).toContain("PARAMETER_DISCOVERY:wfuzz");
    const wfuzzCalls = runner.calls.filter((c) => c.executable === "wfuzz");
    expect(wfuzzCalls.some((c) => c.args.some((a) => a.includes("FUZZ=zerosweep")))).toBe(true); // parameter template
    expect(wfuzzCalls.some((c) => c.args.some((a) => a.endsWith("/FUZZ")))).toBe(true); // content template
    // Wordlists enter plans only as governed container paths (§11).
    const ffufCall = runner.calls.find((c) => c.executable === "ffuf")!;
    expect(ffufCall.args).toContain("/wordlists/builtin/common-directories-standard.txt");
    expect(ffufCall.args.join(" ")).not.toMatch(/\/home\/|\/etc\/|\.\.\//);

    // Provenance (§26): /admin was reported by ffuf + feroxbuster
    // (trailing-slash form merged, §21) + gobuster. Per-execution rows are
    // appended by the store (the Prisma store upserts them into ONE row);
    // the provenance union across rows must carry all three tools.
    const admins = store.endpoints.filter((e) => e.url.replace(/\/$/, "") === "https://example.com/admin");
    expect(admins.length).toBeGreaterThanOrEqual(1);
    const adminSources = new Set(admins.flatMap((e) => e.sources));
    expect([...adminSources]).toEqual(expect.arrayContaining(["ffuf", "feroxbuster", "gobuster"]));
    expect(admins.every((e) => e.classification === "SENSITIVE_ROUTE")).toBe(true); // label only (§42)
    expect(admins.every((e) => e.endpointType === "PAGE" || e.endpointType === "DIRECTORY")).toBe(true); // /admin vs /admin/ forms (§21/§22)
    expect(admins.some((e) => e.statusCode === 200)).toBe(true);

    // API classification (§41) and JS inventory (§44).
    expect(store.endpoints.find((e) => e.url === "https://example.com/api/users")!.endpointType).toBe("API");
    expect(store.endpoints.find((e) => e.url === "https://example.com/assets/app.js")!.endpointType).toBe("STATIC");

    // Out-of-scope redirect: recorded ON the endpoint, never followed and
    // never promoted into a probed endpoint of its own (§20/§23/§40).
    const promo = store.endpoints.find((e) => e.url === "https://example.com/promo")!;
    expect(promo.redirectLocation).toBe("https://thirdparty.example.net/promo");
    expect(store.endpoints.some((e) => e.url === "https://thirdparty.example.net/promo")).toBe(false);

    // Parameters (§27/§30): the `id` parameter on /search was found by BOTH
    // Arjun and Wfuzz — provenance unions at the inventory level; values
    // never appear anywhere.
    const searchParams = store.parameters.filter((p) => p.endpointUrl === "https://example.com/search");
    expect(searchParams.map((p) => p.name).sort()).toEqual(expect.arrayContaining(["id", "page", "q", "sort"]));
    const idSources = new Set(searchParams.filter((p) => p.name === "id").flatMap((p) => p.sources));
    expect([...idSources].sort()).toEqual(["arjun", "wfuzz"]);
    expect(JSON.stringify(store.parameters)).not.toContain("zerosweep=1");
    const apiParams = store.parameters.filter((p) => p.endpointUrl === "https://example.com/api/users");
    expect(apiParams.map((p) => p.name).sort()).toEqual(["limit", "offset"]);

    // Discovery produces inventory, never vulnerabilities (§47/§63).
    expect(store.findings.every((f) => f.isMock)).toBe(true);
    expect(store.reportPending).toBe(true);
  });

  it("one content tool failing degrades CONTENT_DISCOVERY to PARTIAL — the rest of the surface still lands (§60)", async () => {
    const failing = fullFixtures();
    failing.feroxbuster = { stdout: "", exitCode: 2 }; // ran and failed hard
    const { store, dag } = makeWorld(fullFixtures(), "WEB_COMPREHENSIVE", failing);
    const result = await dag.run("scan-1");
    expect(result.status).toBe("PARTIAL"); // scan completes with partial data (§60)
    expect(store.stages.get("CONTENT_DISCOVERY")).toBe("PARTIAL");
    expect(store.endpoints.some((e) => e.url === "https://example.com/login")).toBe(true); // ffuf data landed
    expect(store.stages.get("PARAMETER_DISCOVERY")).toBe("COMPLETED");
  });
});

describe("Prompt 6 web-discovery E2E — WEB_BASELINE (fixtures)", () => {
  it("baseline does SMALL single-adapter content discovery and no parameter stage (§48)", async () => {
    const { runner, store, dag } = makeWorld(fullFixtures(), "WEB_BASELINE");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    const contentExecs = [...store.executions.values()].filter((e) => e.stageType === "CONTENT_DISCOVERY");
    expect(contentExecs).toHaveLength(1);
    expect(contentExecs[0]!.adapterSlug).toBe("ffuf");
    const ffufCall = runner.calls.find((c) => c.executable === "ffuf")!;
    expect(ffufCall.args).toContain("/wordlists/builtin/common-directories-small.txt");
    expect(store.stages.has("PARAMETER_DISCOVERY")).toBe(false);
    expect(store.endpoints.some((e) => e.url === "https://example.com/admin")).toBe(true);
  });
});
