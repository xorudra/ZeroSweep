import { describe, expect, it } from "vitest";
import {
  FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  createReconAdapters, reconHealthBySlug, type FixtureResponse,
} from "@dsrclone/security-sdk";
import { StageExecutor, EXECUTABLE_SLUGS } from "./executors/stage-executor";
import { DagRunner } from "./consumers/dag-runner";
import { FakeStore } from "./testing/fake-store";

/**
 * Prompt 5 end-to-end scenarios (§62): the real recon adapters run the full
 * pipeline against RECORDED FIXTURE OUTPUT injected through the ToolRunner —
 * no binary executes, no network is touched, no live target exists. The
 * FixtureToolRunner also records every invocation, which lets these tests
 * prove scope discipline (out-of-scope hosts are never handed downstream).
 */

const SUBFINDER = [
  '{"host":"api.example.com","input":"example.com","source":"crtsh"}',
  '{"host":"API.Example.com","input":"example.com","source":"rapiddns"}',
  '{"host":"dev.example.com","input":"example.com","source":"crtsh"}',
  '{"host":"evil.vendor.example.net","input":"example.com","source":"crtsh"}',
].join("\n");
const AMASS = [
  '{"name":"api.example.com","domain":"example.com","addresses":[{"ip":"93.184.216.34"}],"tag":"dns","source":"DNS"}',
  '{"name":"mail.example.com","domain":"example.com","addresses":[{"ip":"93.184.216.35"}],"tag":"dns","source":"DNS"}',
].join("\n");
const DNSX = [
  '{"host":"api.example.com","a":["93.184.216.34"],"status_code":"NOERROR"}',
  '{"host":"www.example.com","a":["93.184.216.35"],"status_code":"NOERROR"}',
  '{"host":"nxprobe-deadbeef.example.com","a":["203.0.113.99"],"status_code":"NOERROR"}',
  '{"host":"dev.example.com","status_code":"NXDOMAIN"}',
].join("\n");
const GAU = [
  "https://example.com/product?id=123&lang=en",
  "https://example.com/login?next=/home&token=abc123secretvalue",
  "https://thirdparty.example.net/tracker?ref=example",
].join("\n");
const WAYBACK = "https://example.com/old-page?ref=home";
const HTTPX = [
  '{"url":"https://api.example.com","host":"api.example.com","port":443,"scheme":"https","status_code":200,"title":"API Root","webserver":"nginx","tech":["nginx","HSTS"],"a":["93.184.216.34"]}',
  '{"url":"https://www.example.com","host":"www.example.com","port":443,"scheme":"https","status_code":301,"location":"https://login.thirdparty.example.net/","a":["93.184.216.35"]}',
].join("\n");
const WHATWEB = JSON.stringify([{ target: "https://www.example.com/", http_status: 200, plugins: { nginx: { version: ["1.24.0"] }, WordPress: { version: ["6.4.2"], certainty: 100 } } }]);
const KATANA = [
  '{"request":{"method":"GET","endpoint":"https://example.com/"},"response":{"status_code":200}}',
  '{"request":{"method":"POST","endpoint":"https://example.com/search?q=shoes&page=2"},"response":{"status_code":200}}',
].join("\n");

function fullFixtures(): Record<string, FixtureResponse> {
  return {
    subfinder: { stdout: SUBFINDER, version: "2.6.6" },
    amass: { stdout: AMASS, version: "4.2.0" },
    assetfinder: { stdout: "api.example.com\nstaging.example.com\n" },
    findomain: { stdout: "api.example.com\nblog.example.com\n" },
    dnsx: { stdout: DNSX, version: "1.2.2" },
    gau: { stdout: GAU },
    waybackurls: { stdout: WAYBACK },
    httpx: { stdout: HTTPX, version: "1.6.9" },
    whatweb: { stdout: WHATWEB, version: "0.5.5" },
    katana: { stdout: KATANA, version: "1.1.0" },
  };
}

function makeWorld(
  planFixtures: Record<string, FixtureResponse>,
  profile: "PASSIVE_RECON" | "WEB_BASELINE",
  targetType: "DOMAIN" | "WEB_APPLICATION" = "DOMAIN",
  execFixtures: Record<string, FixtureResponse> = planFixtures,
) {
  // Plan-time and worker-time registries are separate instances on purpose:
  // a tool can be healthy when the plan is built and gone when the worker
  // runs (and vice versa) — §56 is about exactly that gap.
  const planRegistry = new ToolRegistry();
  planRegistry.register(new MockSecurityAdapter());
  planRegistry.register(new LocalEchoAdapter());
  const planAdapters = createReconAdapters(new FixtureToolRunner(planFixtures));
  for (const a of planAdapters) planRegistry.register(a);
  const store = new FakeStore(profile, {
    planRegistry,
    healthBySlug: reconHealthBySlug(planAdapters),
    executableSlugs: [...EXECUTABLE_SLUGS],
    targetType,
  });
  const runner = new FixtureToolRunner(execFixtures);
  const execRegistry = new ToolRegistry();
  execRegistry.register(new MockSecurityAdapter());
  execRegistry.register(new LocalEchoAdapter());
  for (const a of createReconAdapters(runner)) execRegistry.register(a);
  const executor = new StageExecutor(execRegistry, store);
  return { runner, store, dag: new DagRunner(store, executor) };
}

describe("Prompt 5 recon E2E — PASSIVE_RECON with real adapters (fixtures)", () => {
  it("completes: 4 subdomain sources → dnsx → historical URLs; provenance merges, scope holds, zero findings", async () => {
    const { runner, store, dag } = makeWorld(fullFixtures(), "PASSIVE_RECON");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect([...store.stages.values()].every((s) => s === "COMPLETED")).toBe(true);

    // Every selected adapter of every stage actually executed.
    const executedSlugs = [...store.executions.values()].map((e) => e.adapterSlug);
    for (const slug of ["subfinder", "amass", "assetfinder", "findomain", "dnsx", "gau", "waybackurls"]) {
      expect(executedSlugs).toContain(slug);
    }

    // Provenance: api.example.com was reported by all four discovery tools.
    const apiSources = new Set(store.assets.filter((a) => a.host === "api.example.com").flatMap((a) => a.sources));
    expect([...apiSources]).toEqual(expect.arrayContaining(["subfinder", "amass", "assetfinder", "findomain"]));

    // Out-of-scope discovery recorded with its verdict + dedicated event…
    expect(store.assets.find((a) => a.host === "evil.vendor.example.net")?.scopeStatus).toBe("OUT_OF_SCOPE");
    expect(store.events.some((e) => e.type === "asset.out_of_scope")).toBe(true);

    // …and NEVER handed to the active DNS stage (§23/§26): dnsx stdin holds
    // in-scope hosts plus the wildcard probe only.
    const dnsxCall = runner.calls.find((c) => c.executable === "dnsx" && c.args.length > 0)!;
    expect(dnsxCall.stdin).toContain("api.example.com");
    expect(dnsxCall.stdin).not.toContain("evil.vendor.example.net");
    expect(dnsxCall.stdin).toMatch(/nxprobe-[0-9a-f]{8}\.example\.com/);

    // Historical URLs: parameter NAMES kept, sensitive VALUES never stored.
    const login = store.endpoints.find((e) => e.url.includes("/login"))!;
    expect(login.parameterNames).toEqual(["next", "token"]);
    expect(login.url).not.toContain("abc123secretvalue");
    expect(login.url).toContain("token=REDACTED");
    // Third-party historical URL is an OUT_OF_SCOPE reference (§12).
    expect(store.endpoints.find((e) => e.url.includes("thirdparty"))?.scopeStatus).toBe("OUT_OF_SCOPE");

    // Recon produces inventory only — zero findings in the whole scan (§47).
    expect(store.findings).toHaveLength(0);
    expect(store.reportPending).toBe(true);
  });

  it("one discovery tool failing degrades the stage to PARTIAL; the rest of the data still lands (§55)", async () => {
    const fixtures = fullFixtures();
    fixtures.amass = { stdout: "", exitCode: 2 }; // tool ran and failed hard
    const { store, dag } = makeWorld(fixtures, "PASSIVE_RECON");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("PARTIAL");
    expect(store.stages.get("PASSIVE_RECON")).toBe("PARTIAL");
    expect(store.stages.get("DNS_RESOLUTION")).toBe("COMPLETED");
    // Assets from the surviving tools were still persisted.
    expect(store.assets.some((a) => a.host === "api.example.com")).toBe(true);
    expect(store.findings).toHaveLength(0);
  });

  it("an unavailable tool is skipped, not failed: stage completes degraded (§56)", async () => {
    // findomain was healthy at plan time but its binary is gone on the
    // worker that picks the scan up — the DAG must degrade, not crash.
    const execFixtures = fullFixtures();
    delete execFixtures.findomain;
    const { store, dag } = makeWorld(fullFixtures(), "PASSIVE_RECON", "DOMAIN", execFixtures);
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect([...store.executions.keys()].some((k) => k.includes("findomain"))).toBe(false);
    expect(store.events.some((e) => e.type === "tool.failed" && (e.payload as { reasonCode?: string }).reasonCode === "TOOL_UNAVAILABLE")).toBe(true);
    expect(store.assets.some((a) => a.host === "blog.example.com")).toBe(false); // findomain-only host absent
    expect(store.assets.some((a) => a.host === "api.example.com")).toBe(true);
  });
});

describe("Prompt 5 recon E2E — WEB_BASELINE web surface (fixtures)", () => {
  it("httpx services + whatweb technologies + katana endpoints land as inventory; redirect target stays a reference", async () => {
    const { store, dag } = makeWorld(fullFixtures(), "WEB_BASELINE", "WEB_APPLICATION");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");

    const api = store.services.find((s) => s.host === "api.example.com")!;
    expect(api).toMatchObject({ port: 443, statusCode: 200, title: "API Root", server: "nginx" });
    // Asset HTTP status is derived from its service (§43 column).
    expect(store.assets.find((a) => a.host === "api.example.com")?.httpStatus).toBe(200);

    const techNames = store.technologies.map((t) => t.name);
    expect(techNames).toContain("WordPress");
    expect(techNames).toContain("nginx");
    expect(store.technologies.find((t) => t.name === "WordPress")).toMatchObject({ version: "6.4.2", category: "CMS" });

    const search = store.endpoints.find((e) => e.url.includes("/search"))!;
    expect(search.method).toBe("POST");
    expect(search.parameterNames).toEqual(["page", "q"]);

    // §30: the third-party redirect target is an OUT_OF_SCOPE endpoint
    // reference — never an asset, never a service.
    expect(store.assets.some((a) => a.host === "login.thirdparty.example.net")).toBe(false);
    expect(store.services.some((s) => s.host === "login.thirdparty.example.net")).toBe(false);
    expect(store.endpoints.find((e) => e.url.includes("login.thirdparty"))?.scopeStatus).toBe("OUT_OF_SCOPE");

    // Only the labelled simulation finding from the mock fallback stages —
    // recon adapters themselves produced none (§47).
    expect(store.findings.every((f) => f.isMock)).toBe(true);
  });
});
