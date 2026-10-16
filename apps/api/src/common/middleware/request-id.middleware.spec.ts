import { clientIp, setTrustProxyEnabled } from "./request-id.middleware";

/**
 * Launch Safety A10: rate-limit keys must be the edge-observed address.
 * The last X-Forwarded-For entry is trustworthy ONLY when the request
 * arrived through the configured single proxy hop (main.ts enables
 * trust alongside Express `trust proxy`); otherwise XFF is entirely
 * client-supplied and keying on ANY entry would let an attacker rotate
 * fake identities and defeat every per-IP cap — the key falls back to
 * the socket / Express peer address.
 */
describe("clientIp (A10 rate-limit keying)", () => {
  afterEach(() => setTrustProxyEnabled(false));

  describe("trusted proxy configured (hosted deployment)", () => {
    beforeEach(() => setTrustProxyEnabled(true));

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

    it("ignores blank XFF segments", () => {
      expect(clientIp({ headers: { "x-forwarded-for": " , 203.0.113.9, " }, ip: "10.0.0.1" })).toBe("203.0.113.9");
    });
  });

  describe("no trusted proxy (direct exposure)", () => {
    it("ignores a forged X-Forwarded-For header and keys on the peer address", () => {
      const req = {
        headers: { "x-forwarded-for": "1.2.3.4, 203.0.113.9, 198.51.100.7" },
        ip: "10.0.0.1",
      };
      expect(clientIp(req)).toBe("10.0.0.1");
      // Rotating the forged header must not mint a fresh limiter bucket.
      expect(clientIp({ headers: { "x-forwarded-for": "9.9.9.9" }, ip: "10.0.0.1" })).toBe("10.0.0.1");
    });
  });

  it("falls back to the socket address when no XFF header exists (direct traffic)", () => {
    expect(clientIp({ headers: {}, ip: "192.0.2.5" })).toBe("192.0.2.5");
    expect(clientIp({ headers: {}, socket: { remoteAddress: "192.0.2.6" } })).toBe("192.0.2.6");
    expect(clientIp({ headers: {} })).toBe("unknown");
  });
});
