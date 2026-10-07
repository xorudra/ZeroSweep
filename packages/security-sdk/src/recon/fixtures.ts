/**
 * Recorded fixture outputs for the recon parsers (Prompt 5 §36/§52).
 * These are hand-built from each tool's documented output format — no live
 * tool was run and no real target was contacted to produce them. Hosts are
 * the RFC 2606 example.com domain and its documentation IP range peers.
 */

export const SUBFINDER_JSONL = [
  '{"host":"api.example.com","input":"example.com","source":"crtsh"}',
  '{"host":"WWW.Example.com","input":"example.com","source":"hackertarget"}',
  '{"host":"dev.example.com","input":"example.com","source":"crtsh"}',
  "this line is not json",
  '{"host":"bad host!.example.com","input":"example.com","source":"broken"}',
  "",
].join("\n");

export const AMASS_JSONL = [
  '{"name":"api.example.com","domain":"example.com","addresses":[{"ip":"93.184.216.34","cidr":"93.184.216.0/24","asn":15133,"desc":"EDGECAST"}],"tag":"dns","source":"DNS"}',
  '{"name":"mail.example.com","domain":"example.com","addresses":[{"ip":"93.184.216.35"}],"tag":"dns","source":"DNS"}',
  "{broken json",
].join("\n");

export const ASSETFINDER_TEXT = ["api.example.com", "staging.example.com", "", "# comment"].join("\n");

export const FINDOMAIN_TEXT = ["api.example.com", "blog.example.com", "not a host at all"].join("\n");

export const DNSX_JSONL = [
  '{"host":"api.example.com","resolver":["1.1.1.1:53"],"a":["93.184.216.34"],"aaaa":[],"cname":["lb.example.net"],"status_code":"NOERROR"}',
  '{"host":"www.example.com","resolver":["1.1.1.1:53"],"a":["93.184.216.35"],"aaaa":["2606:2800:220:1:248:1893:25c8:1946"],"status_code":"NOERROR"}',
  '{"host":"nxprobe-deadbeef.example.com","a":["203.0.113.99"],"status_code":"NOERROR"}',
  '{"host":"fake.example.com","a":["203.0.113.99"],"status_code":"NOERROR"}',
  '{"host":"gone.example.com","status_code":"NXDOMAIN"}',
].join("\n");

export const HTTPX_JSONL = [
  '{"url":"https://api.example.com","input":"api.example.com","host":"api.example.com","port":443,"scheme":"https","status_code":200,"title":"API Root","content_type":"application/json","webserver":"nginx","tech":["nginx","HSTS"],"a":["93.184.216.34"]}',
  '{"url":"https://www.example.com","input":"www.example.com","host":"www.example.com","port":443,"scheme":"https","status_code":301,"title":"","location":"https://login.thirdparty.example.net/","a":["93.184.216.35"]}',
  '{"url":"https://dev.example.com","input":"dev.example.com","host":"dev.example.com","port":443,"scheme":"https","status_code":403,"title":"Forbidden","webserver":"Apache","tech":["Apache","PHP"],"a":["93.184.216.36"]}',
  "{malformed",
].join("\n");

export const WHATWEB_JSON = JSON.stringify([
  {
    target: "https://www.example.com/",
    http_status: 200,
    plugins: {
      nginx: { version: ["1.24.0"] },
      WordPress: { version: ["6.4.2"], certainty: 100 },
      PHP: { version: ["8.1.2"] },
      jQuery: { version: ["3.7.1"] },
    },
  },
]);

export const WHATWEB_BRIEF = "https://www.example.com/ [200 OK] nginx[1.24.0], PHP[8.1.2], WordPress[6.4.2]";

export const GAU_TEXT = [
  "https://example.com/product?id=123&lang=en",
  "https://example.com/login?next=/home&token=abc123secret",
  "https://thirdparty.example.net/tracker?ref=example",
  "not-a-url",
].join("\n");

export const WAYBACK_TEXT = [
  "http://example.com/old-page?ref=home",
  "https://example.com/product?id=123&lang=en",
].join("\n");

export const KATANA_JSONL = [
  '{"timestamp":"2026-01-01T00:00:00Z","request":{"method":"GET","endpoint":"https://example.com/"},"response":{"status_code":200}}',
  '{"timestamp":"2026-01-01T00:00:01Z","request":{"method":"GET","endpoint":"https://example.com/assets/app.js"},"response":{"status_code":200}}',
  '{"timestamp":"2026-01-01T00:00:02Z","request":{"method":"POST","endpoint":"https://example.com/search?q=shoes&page=2"},"response":{"status_code":200}}',
  '{"request":{"method":"GET"}}',
].join("\n");
