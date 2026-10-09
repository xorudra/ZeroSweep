/** @type {import('next').NextConfig} */
// Prompt 39 RC1 hardening (§68 CSP, §180 source maps, §276 security
// headers): the web UI previously served no security headers of its
// own. The CSP is deliberately pragmatic for the Next.js App Router
// (hydration uses inline scripts/styles); frame-ancestors + DENY make
// clickjacking a non-issue, and everything else is 'self'-locked —
// with ONE deliberate exception: connect-src must allow the API origin,
// or the browser blocks every API call the UI makes (this exact bug
// broke sign-in on the first hosted deployment: the API, its CORS and
// the credentials were all correct, but the page's own CSP refused the
// connection). The origin is derived from the same public env var the
// API client uses, so the two can never drift apart.
function apiConnectOrigin() {
  const base = process.env.NEXT_PUBLIC_API_BASE_URL;
  if (base) {
    try { return new URL(base).origin; } catch { /* fall through */ }
  }
  return "http://localhost:4000"; // api-client's dev default
}
// The console also pings the AI and worker services directly (wake-up
// pings when the console opens — see Shell), so their origins belong in
// connect-src too, derived from the same public env vars with the
// reference deployment as the default.
function peerConnectOrigins() {
  const ai = process.env.NEXT_PUBLIC_AI_URL ?? "https://dsrclone-ai.onrender.com";
  const worker = process.env.NEXT_PUBLIC_WORKER_URL ?? "https://dsrclone-worker.onrender.com";
  const origins = [];
  for (const u of [ai, worker]) {
    try { origins.push(new URL(u).origin); } catch { /* ignore malformed */ }
  }
  return origins.join(" ");
}
const securityHeaders = [
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      `connect-src 'self' ${apiConnectOrigin()} ${peerConnectOrigins()}`,
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "),
  },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
];
const nextConfig = {
  reactStrictMode: true,
  productionBrowserSourceMaps: false,
  transpilePackages: ["@dsrclone/ui", "@dsrclone/types"],
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};
export default nextConfig;
