/**
 * Recorded fixture outputs for the Prompt 6 web-discovery tools, in the
 * shape of the §56 controlled test application: a predictable app on the
 * RFC 2606 example.com domain with known routes, a soft-404 behaviour, an
 * in-scope redirect, an out-of-scope redirect and an SPA fallback. No live
 * tool was run and no real target was contacted to produce these — they
 * are hand-built from each tool's documented output format.
 */

export const FFUF_JSON = JSON.stringify({
  commandline: "ffuf -w /wordlists/builtin/common-directories-small.txt -u https://example.com/FUZZ -of json",
  time: "2026-01-01T00:00:00Z",
  results: [
    { input: { FUZZ: "admin" }, url: "https://example.com/admin", status: 200, length: 1234, words: 100, lines: 40, "content-type": "text/html; charset=utf-8", redirectlocation: "", host: "example.com" },
    { input: { FUZZ: "login" }, url: "https://example.com/login", status: 200, length: 2345, words: 180, lines: 60, "content-type": "text/html", redirectlocation: "", host: "example.com" },
    { input: { FUZZ: "robots.txt" }, url: "https://example.com/robots.txt", status: 200, length: 128, words: 16, lines: 6, "content-type": "text/plain", redirectlocation: "", host: "example.com" },
    { input: { FUZZ: "api/users" }, url: "https://example.com/api/users", status: 200, length: 512, words: 40, lines: 1, "content-type": "application/json", redirectlocation: "", host: "example.com" },
    { input: { FUZZ: "assets/app.js" }, url: "https://example.com/assets/app.js", status: 200, length: 90210, words: 4000, lines: 900, "content-type": "application/javascript", redirectlocation: "", host: "example.com" },
    { input: { FUZZ: "old-home" }, url: "https://example.com/old-home", status: 301, length: 178, words: 8, lines: 6, "content-type": "text/html", redirectlocation: "https://example.com/", host: "example.com" },
    { input: { FUZZ: "promo" }, url: "https://example.com/promo", status: 302, length: 154, words: 7, lines: 5, "content-type": "text/html", redirectlocation: "https://thirdparty.example.net/promo", host: "example.com" },
    // Soft-404 twins: two different "found" paths with byte-identical
    // response shape to the app's custom not-found page (§17).
    { input: { FUZZ: "zzz-nonexistent-a" }, url: "https://example.com/zzz-nonexistent-a", status: 200, length: 640, words: 42, lines: 12, "content-type": "text/html", redirectlocation: "", host: "example.com" },
    { input: { FUZZ: "zzz-nonexistent-b" }, url: "https://example.com/zzz-nonexistent-b", status: 200, length: 640, words: 42, lines: 12, "content-type": "text/html", redirectlocation: "", host: "example.com" },
  ],
});

/** Baseline observations of certainly-nonexistent paths on the controlled
 *  app — the calibration input for Soft404Detector (§17). */
export const SOFT404_BASELINE = { statusCode: 200, contentLength: 640, wordCount: 42, lineCount: 12, contentType: "text/html" };

export const FEROX_JSONL = [
  '{"type":"response","url":"https://example.com/admin/","status":200,"content_length":1300,"line_count":44,"word_count":105,"headers":{}}',
  '{"type":"response","url":"https://example.com/api","status":200,"content_length":220,"line_count":1,"word_count":12,"headers":{}}',
  '{"type":"response","url":"https://example.com/uploads","status":403,"content_length":279,"line_count":10,"word_count":30,"headers":{}}',
  '{"type":"statistics","requests_made":120,"total_expected":500}',
  "not json at all",
].join("\n");

export const GOBUSTER_TEXT = [
  "===============================================================",
  "Gobuster v3.6",
  "===============================================================",
  "/admin (Status: 200) [Size: 1234]",
  "/images (Status: 301) [Size: 177] [--> https://example.com/images/]",
  "/server-status (Status: 403) [Size: 276]",
  "===============================================================",
].join("\n");

/** Wfuzz PARAMETER-template output: fuzzed query keys on /search. */
export const WFUZZ_JSON = JSON.stringify([
  { id: 1, url: "https://example.com/search?id=zerosweep", code: 200, lines: 30, words: 90, chars: 1500, description: "id" },
  { id: 2, url: "https://example.com/search?sort=zerosweep", code: 200, lines: 30, words: 91, chars: 1502, description: "sort" },
  { id: 3, url: "https://example.com/hidden-panel", code: 200, lines: 12, words: 40, chars: 800, description: "hidden-panel" },
]);

/** Wfuzz CONTENT-template output: fuzzed paths. */
export const WFUZZ_CONTENT_JSON = JSON.stringify([
  { id: 1, url: "https://example.com/admin", code: 200, lines: 40, words: 100, chars: 1234, description: "admin" },
  { id: 2, url: "https://example.com/backup", code: 403, lines: 9, words: 25, chars: 290, description: "backup" },
]);

export const ARJUN_JSON = JSON.stringify({
  "https://example.com/search": { params: ["q", "page", "id"] },
  "https://example.com/api/users": { params: ["limit", "offset"] },
});

export const ROBOTS_TXT = [
  "User-agent: *",
  "Disallow: /admin",
  "Disallow: /internal/",
  "Allow: /admin/public",
  "Sitemap: https://example.com/sitemap.xml",
  "# a comment",
].join("\n");

export const SITEMAP_XML = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  "<urlset>",
  "<url><loc>https://example.com/</loc></url>",
  "<url><loc>https://example.com/about</loc></url>",
  "<url><loc>https://example.com/api/users</loc></url>",
  "</urlset>",
].join("\n");

export const SITEMAP_INDEX_XML = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  "<sitemapindex>",
  "<sitemap><loc>https://example.com/sitemap-pages.xml</loc></sitemap>",
  "<sitemap><loc>https://example.com/sitemap-posts.xml</loc></sitemap>",
  "</sitemapindex>",
].join("\n");

/** The §56 controlled application's predictable behaviour, for tests that
 *  reason about what discovery SHOULD produce from it. */
export const CONTROLLED_APP = {
  baseUrl: "https://example.com/",
  routes: ["/", "/about", "/login", "/admin", "/api", "/api/users", "/search", "/assets/app.js", "/robots.txt", "/sitemap.xml"],
  soft404: "any other path returns HTTP 200 with the custom not-found page (640 bytes, 42 words, 12 lines)",
  redirect: "/old-home → https://example.com/ (in scope); /promo → https://thirdparty.example.net/promo (out of scope, record only)",
  spaFallback: "unknown /app/* paths return the identical SPA shell",
};
