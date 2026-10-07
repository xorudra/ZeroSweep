/**
 * Port profiles (Prompt 10 §27/§28): administrator-managed NAMED sets.
 * Plans reference a profile id — never a raw port string — and FULL_TCP
 * is never the default. Custom port sets arrive as validated structured
 * input (number arrays through the adapter input schema), never as CLI
 * text (§13/§82).
 */

export interface PortProfile {
  id: string;
  name: string;
  description: string;
  transport: "tcp" | "udp";
  ports: number[];
  /** Broad profiles require explicit profile/admin selection (§27). */
  broad: boolean;
}

const WEB = [80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 10000];
const COMMON = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
  1723, 3306, 3389, 5900, 8000, 8080, 8443,
];
const STANDARD = [
  ...new Set([
    ...COMMON,
    20, 69, 123, 161, 389, 636, 873, 1433, 1521, 2049, 2181, 2375, 2376,
    2379, 2483, 2484, 3128, 3260, 4369, 5000, 5432, 5601, 5672, 5901, 5985,
    5986, 6000, 6379, 6443, 7001, 8009, 8081, 8086, 8088, 8090, 8180, 8222,
    8333, 8500, 8888, 9000, 9001, 9042, 9090, 9100, 9200, 9300, 9418, 9999,
    10000, 10250, 11211, 15672, 27017, 27018, 61616,
  ]),
].sort((a, b) => a - b);
const UDP_SMALL = [53, 67, 68, 69, 123, 161, 500, 514, 520, 631, 1900, 4500, 5353];

export const PORT_PROFILES: PortProfile[] = [
  { id: "WEB_COMMON", name: "Web Common", description: "HTTP/HTTPS and common web-service ports only.", transport: "tcp", ports: WEB, broad: false },
  { id: "COMMON_SERVICES", name: "Common Services", description: "The most common infrastructure services (mail, SSH, databases, remote admin).", transport: "tcp", ports: COMMON, broad: false },
  { id: "STANDARD", name: "Standard", description: "A broad curated service set (~75 ports) for baseline/comprehensive assessments.", transport: "tcp", ports: STANDARD, broad: false },
  { id: "FULL_TCP", name: "Full TCP (1–65535)", description: "Every TCP port. NEVER a default; requires explicit profile selection and policy allowance (§27).", transport: "tcp", ports: [], broad: true },
  { id: "UDP_SMALL", name: "UDP Small", description: "Small approved UDP set (§28): broad UDP scanning stays disabled by default.", transport: "udp", ports: UDP_SMALL, broad: false },
];

export const DEFAULT_PORT_PROFILE_ID = "COMMON_SERVICES";

export function portProfileById(id: string): PortProfile | undefined {
  return PORT_PROFILES.find((p) => p.id === id);
}

/** Port list for a profile. FULL_TCP expands to the literal range
 *  expression the tools accept ("1-65535") — generated HERE from the
 *  governed profile, never from user text. */
export function portSpecForProfile(profile: PortProfile): string {
  if (profile.id === "FULL_TCP") return "1-65535";
  return profile.ports.join(",");
}

/** Validate a structured custom port set (§27): integers in range,
 *  deduped, sorted, count-capped. Returns null on any violation. */
export function validateCustomPorts(input: unknown, maxPorts = 1000): number[] | null {
  if (!Array.isArray(input) || input.length === 0 || input.length > maxPorts) return null;
  const out = new Set<number>();
  for (const v of input) {
    if (typeof v !== "number" || !Number.isInteger(v) || v < 1 || v > 65535) return null;
    out.add(v);
  }
  return [...out].sort((a, b) => a - b);
}
