import { execFile } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { delimiter, join } from "node:path";

/**
 * Tool execution boundary (Prompt 5 §3, Prompt 3 §11). Adapters never spawn
 * processes directly and NEVER through a shell: a runner receives an
 * executable name plus a validated argument array. Two implementations:
 *
 * - ProcessToolRunner — administrator-managed trusted binaries found on
 *   PATH (or, in container deployments, the tool image's entrypoint). It
 *   never downloads anything and never executes a path supplied by a user.
 * - FixtureToolRunner — deterministic canned output for tests. It makes the
 *   entire recon pipeline testable with zero network and zero binaries, and
 *   records every invocation so tests can prove scope gating (e.g. dnsx was
 *   only ever handed in-scope hosts).
 */

export interface ToolRunRequest {
  executable: string;
  args: string[];
  stdin?: string;
  timeoutSeconds: number;
  maxOutputBytes?: number;
}

export interface ToolRunResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
}

export interface ToolProbe {
  available: boolean;
  version?: string;
  path?: string;
}

export interface ToolRunner {
  /** Synchronous PATH lookup — used at plan time for honest health. */
  findExecutable(executable: string): string | null;
  /** Availability + best-effort version detection (--version style probe). */
  probe(executable: string, versionArgs: string[]): Promise<ToolProbe>;
  run(request: ToolRunRequest): Promise<ToolRunResult>;
}

const VERSION_RE = /(\d+\.\d+(?:\.\d+)?(?:[-.][a-z0-9]+)?)/i;

export function parseVersionOutput(output: string): string | undefined {
  for (const line of output.split(/\r?\n/)) {
    const m = line.match(VERSION_RE);
    if (m) return m[1];
  }
  return undefined;
}

/** Pure PATH scan (no process spawn): the honest availability primitive. */
export function findExecutableInPath(executable: string, pathEnv: string | undefined = process.env.PATH): string | null {
  if (!executable || executable.includes("/") || executable.includes("\\")) return null;
  for (const dir of (pathEnv ?? "").split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, executable);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch { /* keep looking */ }
  }
  return null;
}

export class ProcessToolRunner implements ToolRunner {
  findExecutable(executable: string): string | null {
    return findExecutableInPath(executable);
  }

  async probe(executable: string, versionArgs: string[]): Promise<ToolProbe> {
    const path = this.findExecutable(executable);
    if (!path) return { available: false };
    if (versionArgs.length === 0) return { available: true, path };
    const result = await this.run({ executable, args: versionArgs, timeoutSeconds: 10, maxOutputBytes: 64 * 1024 });
    const version = parseVersionOutput(`${result.stdout}\n${result.stderr}`);
    return { available: true, path, ...(version ? { version } : {}) };
  }

  run(request: ToolRunRequest): Promise<ToolRunResult> {
    return new Promise((resolve) => {
      const child = execFile(
        request.executable,
        request.args,
        {
          shell: false, // hard rule: argument arrays only, never a shell string
          timeout: request.timeoutSeconds * 1000,
          maxBuffer: request.maxOutputBytes ?? 16 * 1024 * 1024,
          env: { ...process.env },
        },
        (error, stdout, stderr) => {
          const err = error as (Error & { killed?: boolean; code?: number | string; signal?: string }) | null;
          resolve({
            stdout: stdout?.toString() ?? "",
            stderr: stderr?.toString() ?? "",
            exitCode: err ? (typeof err.code === "number" ? err.code : null) : 0,
            timedOut: Boolean(err && (err.signal === "SIGTERM" || /timed out/i.test(err.message))),
          });
        },
      );
      if (request.stdin !== undefined) child.stdin?.end(request.stdin);
      else child.stdin?.end();
    });
  }
}

export interface FixtureResponse {
  stdout: string;
  stderr?: string;
  exitCode?: number;
  timedOut?: boolean;
  version?: string;
}

/**
 * Test runner: canned responses keyed by executable name. Executables absent
 * from the fixture map report UNAVAILABLE — tests opt tools in explicitly,
 * exactly like a real deployment where the binary is not installed.
 */
export class FixtureToolRunner implements ToolRunner {
  readonly calls: ToolRunRequest[] = [];
  private readonly fixtures: Map<string, FixtureResponse>;

  constructor(fixtures: Record<string, FixtureResponse> = {}) {
    this.fixtures = new Map(Object.entries(fixtures));
  }

  setFixture(executable: string, response: FixtureResponse): void {
    this.fixtures.set(executable, response);
  }

  findExecutable(executable: string): string | null {
    return this.fixtures.has(executable) ? `/fixture/bin/${executable}` : null;
  }

  async probe(executable: string, _versionArgs: string[]): Promise<ToolProbe> {
    const fixture = this.fixtures.get(executable);
    if (!fixture) return { available: false };
    return { available: true, path: `/fixture/bin/${executable}`, version: fixture.version ?? "0.0.0-fixture" };
  }

  async run(request: ToolRunRequest): Promise<ToolRunResult> {
    this.calls.push(request);
    const fixture = this.fixtures.get(request.executable);
    if (!fixture) return { stdout: "", stderr: `fixture: ${request.executable} not installed`, exitCode: 127, timedOut: false };
    return {
      stdout: fixture.stdout,
      stderr: fixture.stderr ?? "",
      exitCode: fixture.exitCode ?? 0,
      timedOut: fixture.timedOut ?? false,
    };
  }
}
