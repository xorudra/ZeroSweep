/**
 * Recorded tool output fixtures for the Prompt 10 network adapters.
 * Documentation range only (192.0.2.0/24 — RFC 5737) and example.com
 * hostnames. No fixture was produced by scanning anything; they are
 * hand-authored recordings in each tool's real output format, used by
 * the FixtureToolRunner so the whole network pipeline is verifiable
 * with zero binaries and zero network access.
 */

export const NMAP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -T3 -sV -oX - 192.0.2.10 192.0.2.11" version="7.94" xmloutputversion="1.05">
<host starttime="1700000000" endtime="1700000060">
<status state="up" reason="echo-reply" reason_ttl="64"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac"/>
<hostnames><hostname name="server.example.com" type="PTR"/></hostnames>
<ports>
<extraports state="closed" count="991"><extrareasons reason="resets" count="991"/></extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:8.9p1</cpe></service></port>
<port protocol="tcp" portid="23"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="telnet" product="Linux telnetd" method="probed" conf="10"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="http" product="Apache httpd" version="2.4.49" method="probed" conf="10"><cpe>cpe:/a:apache:http_server:2.4.49</cpe></service><script id="http-title" output="Server Dashboard"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="http" product="nginx" version="1.25.3" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:nginx:nginx:1.25.3</cpe></service></port>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="microsoft-ds" product="Samba smbd" version="4.15" method="probed" conf="10"/></port>
<port protocol="tcp" portid="3306"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="mysql" product="MySQL" version="8.0.36" method="probed" conf="10"><cpe>cpe:/a:oracle:mysql:8.0.36</cpe></service></port>
<port protocol="tcp" portid="8080"><state state="closed" reason="reset" reason_ttl="64"/><service name="http-proxy" method="table" conf="3"/></port>
</ports>
<os><osmatch name="Linux 5.15" accuracy="96" line="61234"><osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="96"><cpe>cpe:/o:linux:linux_kernel:5</cpe></osclass></osmatch></os>
<hostscript><script id="smb2-security-mode" output="&#xa;  2.02: &#xa;    Message signing enabled but not required"/></hostscript>
</host>
<host starttime="1700000000" endtime="1700000060">
<status state="up" reason="echo-reply" reason_ttl="64"/>
<address addr="192.0.2.11" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="2375"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="docker" product="Docker" version="24.0.7" method="probed" conf="10"/></port>
<port protocol="tcp" portid="3389"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="ms-wbt-server" product="Microsoft Terminal Services" method="probed" conf="10"/></port>
</ports>
</host>
<host starttime="1700000000" endtime="1700000060">
<status state="down" reason="no-responses"/>
<address addr="192.0.2.12" addrtype="ipv4"/>
</host>
<runstats><finished time="1700000060" elapsed="60" exit="success"/></runstats>
</nmaprun>`;

export const NMAP_DOCTYPE_ATTACK = `<?xml version="1.0"?>
<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/></host></nmaprun>`;

export const NAABU_JSONL = [
  { host: "192.0.2.10", ip: "192.0.2.10", port: 22, protocol: "tcp", tls: false },
  { host: "192.0.2.10", ip: "192.0.2.10", port: 23, protocol: "tcp", tls: false },
  { host: "192.0.2.10", ip: "192.0.2.10", port: 80, protocol: "tcp", tls: false },
  { host: "192.0.2.10", ip: "192.0.2.10", port: 443, protocol: "tcp", tls: true },
  { host: "192.0.2.10", ip: "192.0.2.10", port: 445, protocol: "tcp", tls: false },
  { host: "192.0.2.10", ip: "192.0.2.10", port: 3306, protocol: "tcp", tls: false },
  { host: "192.0.2.10", ip: "192.0.2.10", port: 9999, protocol: "tcp", tls: false },
  { host: "192.0.2.11", ip: "192.0.2.11", port: 2375, protocol: "tcp", tls: false },
  { host: "192.0.2.11", ip: "192.0.2.11", port: 3389, protocol: "tcp", tls: false },
].map((r) => JSON.stringify(r)).join("\n");

export const RUSTSCAN_TEXT = `Open 192.0.2.10:22
Open 192.0.2.10:80
192.0.2.10 -> [22,80,443]
192.0.2.11 -> [3389]`;

export const MASSCAN_JSON = JSON.stringify([
  {
    ip: "192.0.2.10", timestamp: "1700000000",
    ports: [{ port: 80, proto: "tcp", status: "open", reason: "syn-ack", ttl: 64, service: { name: "http", banner: "Apache/2.4.49 <script>alert(1)</script>\u001b[31m" } }],
  },
  {
    ip: "192.0.2.11", timestamp: "1700000000",
    ports: [{ port: 2375, proto: "tcp", status: "open", reason: "syn-ack", ttl: 64, service: { name: "docker" } }],
  },
]);

export const NETDISCOVER_TEXT = ` _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname
 -----------------------------------------------------------------------------
 192.0.2.1       00:11:22:33:44:01      1      60  Router Vendor
 192.0.2.10      00:11:22:33:44:55      1      60  Server Vendor
`;

export const ARP_SCAN_XML = `<?xml version="1.0"?>
<hosts>
<host><address addrtype="ipv4">192.0.2.1</address><address addrtype="mac">00:11:22:33:44:01</address><vendor>Router Vendor</vendor></host>
<host><address addrtype="ipv4">192.0.2.10</address><address addrtype="mac">00:11:22:33:44:55</address><vendor>Server Vendor</vendor></host>
</hosts>`;

export const TSHARK_JSON = JSON.stringify([
  { _source: { layers: { frame: { "frame.len": "342" }, ip: { "ip.src": "192.0.2.50", "ip.dst": "192.0.2.10" }, tcp: { "tcp.srcport": "51000", "tcp.dstport": "80", "tcp.len": "120" }, http: { "http.request.method": "GET", "http.host": "server.example.com", "http.request.uri": "/login" } } } },
  { _source: { layers: { frame: { "frame.len": "1024" }, ip: { "ip.src": "192.0.2.10", "ip.dst": "192.0.2.50" }, tcp: { "tcp.srcport": "80", "tcp.dstport": "51000", "tcp.len": "900" }, http: { "http.response.code": "200", "http.host": "server.example.com", "http.request.uri": "/" } } } },
  { _source: { layers: { frame: { "frame.len": "80" }, ip: { "ip.src": "192.0.2.50", "ip.dst": "192.0.2.1" }, udp: { "udp.srcport": "53000", "udp.dstport": "53" }, dns: { "dns.qry.name": "example.com" } } } },
]);

export const NETWORK_FIXTURES: Record<string, string> = {
  nmap: NMAP_XML,
  naabu: NAABU_JSONL,
  rustscan: RUSTSCAN_TEXT,
  masscan: MASSCAN_JSON,
  netdiscover: NETDISCOVER_TEXT,
  "arp-scan": ARP_SCAN_XML,
  tshark: TSHARK_JSON,
  tcpdump: "",
};

const FIXTURE_VERSIONS: Record<string, string> = {
  nmap: "7.94", naabu: "2.3.3", rustscan: "2.1.1", masscan: "1.3.2",
  netdiscover: "0.3.67", "arp-scan": "1.10.3", tcpdump: "4.99.4", tshark: "4.2.0",
};

/** FixtureToolRunner-shaped responses ({stdout, version}) for the raw
 *  fixture strings above. */
export function networkFixtureResponses(): Record<string, { stdout: string; version: string }> {
  return Object.fromEntries(
    Object.entries(NETWORK_FIXTURES).map(([k, v]) => [k, { stdout: v, version: FIXTURE_VERSIONS[k] ?? "0.0.0" }]),
  );
}
