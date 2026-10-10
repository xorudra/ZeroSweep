import { clientIp } from "./request-id.middleware";

/**
 * Launch Safety A10: rate-limit keys must be the LAST X-Forwarded-For
 * hop (the address the platform edge actually observed). The first XFF
 * entry is client-supplied; keying on it would let an attacker rotate
 * fake identities and defeat every per-IP cap, while keying on the
 * socket address collapses all hosted callers into the shared edge IP.
 */
describe("clientIp (A10 rate-limit keying)", () => {
  it("uses the last X-Forwarded-For entry, never the client-supplied first", () => {
    const req = {
      headers: { "x-forwarded-for": "1.2.3.4, 203.0.113.9, 198.51.100.7" },
      ip: "10.0.0.1",
    };
    expect(clientIp(req)).toBe("198.51.100.7");
  });

  it("uses a single XFF entry as-is", () => {
    expect(clientIp({ headers: { "x-forwarded-for": "203.0.113.9" }, ip: "10.0.0.1" })).toBe("203.0.113.9");
  });

  it("handles an array-valued XFF header", () => {
    expect(clientIp({ headers: { "x-forwarded-for": ["1.2.3.4", "203.0.113.9"] }, ip: "10.0.0.1" })).toBe("203.0.113.9");
  });

  it("falls back to the socket address when no XFF header exists (direct traffic)", () => {
    expect(clientIp({ headers: {}, ip: "192.0.2.5" })).toBe("192.0.2.5");
    expect(clientIp({ headers: {}, socket: { remoteAddress: "192.0.2.6" } })).toBe("192.0.2.6");
    expect(clientIp({ headers: {} })).toBe("unknown");
  });

  it("ignores blank XFF segments", () => {
    expect(clientIp({ headers: { "x-forwarded-for": " , 203.0.113.9, " }, ip: "10.0.0.1" })).toBe("203.0.113.9");
  });
});
