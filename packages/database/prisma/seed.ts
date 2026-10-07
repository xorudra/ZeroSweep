import { PrismaClient } from "@prisma/client";
import { BUNDLED_WORDLISTS } from "@dsrclone/security-sdk";

const prisma = new PrismaClient();

/**
 * Tool catalog seed (Prompt 3 §41) — METADATA ONLY for every tool DSRclone
 * will integrate through adapters in later phases. No commands are stored,
 * no tool is executed by seeding, and catalog adapters are seeded DISABLED:
 * an adapter row here means "known to the registry", not "implemented".
 * Prompt 5 update: the ten recon adapters (subfinder, amass, assetfinder,
 * findomain, dnsx, httpx, whatweb, gau, waybackurls, katana) are now REAL
 * code adapters in @dsrclone/security-sdk; their rows are seeded ENABLED
 * below. Tool health is probed at runtime — a missing binary reports
 * UNAVAILABLE honestly; seeding never installs or executes anything.
 *
 * Multi-category tools keep ONE identity (e.g. Naabu = RECON, Trivy =
 * CONTAINER, Wireshark = NETWORK, Ghidra = BINARY, mitmproxy = API).
 * Commercial tools are ADMIN_PROVIDED: the administrator supplies the
 * installation/license/API; DSRclone never redistributes them.
 */
type Cat = "RECON" | "WEB" | "NETWORK" | "API" | "ACTIVE_DIRECTORY" | "PASSWORD_AUDIT" | "MOBILE" | "CLOUD" | "CONTAINER" | "SOURCE_CODE" | "BINARY" | "WIRELESS" | "REPORTING";
type Risk = "PASSIVE" | "LOW" | "MODERATE" | "INTRUSIVE" | "RESTRICTED";
type Lic = "OPEN_SOURCE" | "COMMERCIAL" | "EXTERNAL_API" | "ADMIN_PROVIDED";

interface CatalogTool {
  slug: string; name: string; category: Cat; riskLevel: Risk; licenseType: Lic;
  requiresApproval: boolean; description: string;
  capabilities: string[]; supportedTargets: string[]; requiresCredentials: string[];
}

const TOOLS: CatalogTool[] = [
  { slug: "burp-suite-professional", name: "Burp Suite Professional", category: "WEB", riskLevel: "MODERATE", licenseType: "ADMIN_PROVIDED", requiresApproval: true, capabilities: ["PROXY", "PASSIVE_ANALYSIS", "SITE_MAP_IMPORT", "ISSUE_IMPORT", "WEB_CRAWLING", "ACTIVE_WEB_SCANNING"], supportedTargets: ["WEB_APPLICATION", "API"], requiresCredentials: [], description: "Commercial web proxy/scanner — ADMIN_PROVIDED licensed environment (Prompt 8 §9). Passive site-map + issue import via the administrator's bridge; active scanning INTRUSIVE, approval-gated, disabled by default. Unconfigured = NOT_CONFIGURED." },
  { slug: "caido", name: "Caido", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PROXY", "TRAFFIC_ANALYSIS", "ENDPOINT_DISCOVERY", "REQUEST_COLLECTION", "ISSUE_IMPORT"], supportedTargets: ["WEB_APPLICATION", "API"], requiresCredentials: [], description: "Modern web security proxy (Prompt 8 §13): traffic analysis, endpoint/request collection and issue import where the installed version supports it; capabilities detected per deployment." },
  { slug: "owasp-zap", name: "OWASP ZAP", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PROXY", "PASSIVE_ANALYSIS", "CONTEXT_MANAGEMENT", "ENDPOINT_IMPORT", "ISSUE_IMPORT", "WEB_CRAWLING", "ENDPOINT_DISCOVERY", "VULNERABILITY_SCANNING", "ACTIVE_WEB_SCANNING"], supportedTargets: ["WEB_APPLICATION", "API"], requiresCredentials: [], description: "Open-source web proxy/scanner via its daemon API (Prompt 8 §4): passive analysis first, per-assessment contexts, endpoint + alert import. Active scanning INTRUSIVE, approval-gated, disabled by default." },
  { slug: "nuclei", name: "Nuclei", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["VULNERABILITY_SCANNING", "MISCONFIGURATION_DETECTION", "EXPOSURE_DETECTION", "TECHNOLOGY_VALIDATION"], supportedTargets: ["WEB_APPLICATION", "DOMAIN", "API"], requiresCredentials: [], description: "Template-based vulnerability scanner, restricted to the governed SAFE template policy (Prompt 7 §4)." },
  { slug: "nikto", name: "Nikto", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["VULNERABILITY_SCANNING", "WEB_SERVER_SECURITY_ASSESSMENT", "MISCONFIGURATION_DETECTION", "EXPOSURE_DETECTION"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Web server security assessment: dangerous files, outdated software, misconfigurations (Prompt 7 §9)." },
  { slug: "ffuf", name: "ffuf", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CONTENT_DISCOVERY", "DIRECTORY_DISCOVERY", "FILE_DISCOVERY", "VHOST_DISCOVERY"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Fast content discovery (directories, files, routes; vhost only when separately enabled). Implemented Prompt 6." },
  { slug: "feroxbuster", name: "Feroxbuster", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CONTENT_DISCOVERY", "DIRECTORY_DISCOVERY", "RECURSIVE_CONTENT_DISCOVERY"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Recursive content discovery with hard depth/rate limits. Implemented Prompt 6." },
  { slug: "gobuster", name: "Gobuster", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CONTENT_DISCOVERY", "DIRECTORY_DISCOVERY", "FILE_DISCOVERY"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Directory and file discovery (dir mode only in this platform). Implemented Prompt 6." },
  { slug: "wfuzz", name: "Wfuzz", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CONTENT_DISCOVERY", "PARAMETER_DISCOVERY"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Web application fuzzer." },
  { slug: "katana", name: "Katana", category: "WEB", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["WEB_CRAWLING", "URL_DISCOVERY", "ENDPOINT_DISCOVERY"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Fast web crawler for endpoint discovery." },
  { slug: "arjun", name: "Arjun", category: "WEB", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PARAMETER_DISCOVERY"], supportedTargets: ["WEB_APPLICATION", "API"], requiresCredentials: [], description: "HTTP parameter discovery suite." },
  { slug: "dalfox", name: "Dalfox", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["VULNERABILITY_SCANNING", "PARAMETER_DISCOVERY"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Focused XSS scanner and parameter analysis." },
  { slug: "xsstrike", name: "XSStrike", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Advanced XSS detection suite." },
  { slug: "sqlmap", name: "SQLmap", category: "WEB", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["WEB_APPLICATION", "API"], requiresCredentials: [], description: "Automatic SQL injection detection; intrusive features require explicit approval." },
  { slug: "commix", name: "Commix", category: "WEB", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Automated command injection testing; requires explicit approval." },
  { slug: "sstimap", name: "SSTImap", category: "WEB", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Server-side template injection detection; requires explicit approval." },
  { slug: "whatweb", name: "WhatWeb", category: "WEB", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["TECHNOLOGY_DETECTION", "HTTP_PROBING"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Web technology fingerprinting." },
  { slug: "wpscan", name: "WPScan", category: "WEB", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["VULNERABILITY_SCANNING", "TECHNOLOGY_DETECTION"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "WordPress security scanner." },
  { slug: "testssl", name: "testssl.sh", category: "WEB", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["TLS_ANALYSIS", "TLS_CONFIGURATION_ASSESSMENT"], supportedTargets: ["DOMAIN", "WEB_APPLICATION", "IP_ADDRESS"], requiresCredentials: [], description: "TLS configuration assessment: protocols, ciphers, certificates (Prompt 7 §11)." },
  { slug: "sslyze", name: "SSLyze", category: "WEB", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["TLS_ANALYSIS", "CERTIFICATE_ANALYSIS"], supportedTargets: ["DOMAIN", "WEB_APPLICATION", "IP_ADDRESS"], requiresCredentials: [], description: "Independent TLS + certificate analysis used to corroborate testssl.sh (Prompt 7 §12)." },
  { slug: "amass", name: "Amass", category: "RECON", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SUBDOMAIN_DISCOVERY", "DNS_DISCOVERY"], supportedTargets: ["DOMAIN"], requiresCredentials: [], description: "Attack surface mapping and asset discovery via OSINT." },
  { slug: "subfinder", name: "Subfinder", category: "RECON", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SUBDOMAIN_DISCOVERY"], supportedTargets: ["DOMAIN"], requiresCredentials: [], description: "Passive subdomain enumeration." },
  { slug: "assetfinder", name: "Assetfinder", category: "RECON", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SUBDOMAIN_DISCOVERY"], supportedTargets: ["DOMAIN"], requiresCredentials: [], description: "Domain asset discovery for related hosts." },
  { slug: "findomain", name: "Findomain", category: "RECON", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SUBDOMAIN_DISCOVERY"], supportedTargets: ["DOMAIN"], requiresCredentials: [], description: "Fast cross-platform subdomain enumerator." },
  { slug: "dnsx", name: "dnsx", category: "RECON", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["DNS_RESOLUTION", "DNS_DISCOVERY"], supportedTargets: ["DOMAIN"], requiresCredentials: [], description: "DNS query and resolution toolkit." },
  { slug: "shuffledns", name: "shuffledns", category: "RECON", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["DNS_RESOLUTION", "SUBDOMAIN_DISCOVERY"], supportedTargets: ["DOMAIN"], requiresCredentials: [], description: "Wildcard-aware DNS resolver wrapper." },
  { slug: "massdns", name: "MassDNS", category: "RECON", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["DNS_RESOLUTION"], supportedTargets: ["DOMAIN"], requiresCredentials: [], description: "High-performance DNS stub resolver." },
  { slug: "httpx", name: "httpx", category: "RECON", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["HTTP_PROBING", "TECHNOLOGY_DETECTION"], supportedTargets: ["DOMAIN", "WEB_APPLICATION", "IP_ADDRESS"], requiresCredentials: [], description: "Fast HTTP probing with technology detection." },
  { slug: "naabu", name: "Naabu", category: "RECON", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PORT_DISCOVERY"], supportedTargets: ["DOMAIN", "IP_ADDRESS", "CIDR"], requiresCredentials: [], description: "Fast port scanner written for pipeline use." },
  { slug: "gau", name: "gau", category: "RECON", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["URL_DISCOVERY", "HISTORICAL_URL_DISCOVERY"], supportedTargets: ["DOMAIN"], requiresCredentials: [], description: "Fetches known URLs from web archives." },
  { slug: "waybackurls", name: "waybackurls", category: "RECON", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["URL_DISCOVERY", "HISTORICAL_URL_DISCOVERY"], supportedTargets: ["DOMAIN"], requiresCredentials: [], description: "Fetches archived URLs from the Wayback Machine." },
  { slug: "hakrawler", name: "Hakrawler", category: "RECON", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["WEB_CRAWLING", "URL_DISCOVERY"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Simple web crawler for endpoints and assets." },
  { slug: "theharvester", name: "theHarvester", category: "RECON", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SUBDOMAIN_DISCOVERY"], supportedTargets: ["DOMAIN"], requiresCredentials: [], description: "OSINT gathering for emails, names and hosts." },
  { slug: "recon-ng", name: "Recon-ng", category: "RECON", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SUBDOMAIN_DISCOVERY"], supportedTargets: ["DOMAIN"], requiresCredentials: [], description: "Modular reconnaissance framework." },
  { slug: "spiderfoot", name: "SpiderFoot", category: "RECON", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SUBDOMAIN_DISCOVERY", "HTTP_PROBING"], supportedTargets: ["DOMAIN", "IP_ADDRESS"], requiresCredentials: [], description: "Automated OSINT collection and analysis." },
  { slug: "eyewitness", name: "EyeWitness", category: "RECON", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["HTTP_PROBING"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Web screenshot and fingerprint triage." },
  { slug: "gowitness", name: "gowitness", category: "RECON", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["HTTP_PROBING"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Web screenshot utility using headless Chrome." },
  { slug: "shodan-cli", name: "Shodan CLI", category: "RECON", riskLevel: "PASSIVE", licenseType: "EXTERNAL_API", requiresApproval: false, capabilities: ["SUBDOMAIN_DISCOVERY", "SERVICE_DETECTION"], supportedTargets: ["DOMAIN", "IP_ADDRESS"], requiresCredentials: ["SHODAN_API_KEY"], description: "Shodan search API client; administrator supplies the API key." },
  { slug: "censys-cli", name: "Censys CLI", category: "RECON", riskLevel: "PASSIVE", licenseType: "EXTERNAL_API", requiresApproval: false, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["DOMAIN", "IP_ADDRESS"], requiresCredentials: ["CENSYS_CREDENTIAL"], description: "Censys search API client; administrator supplies credentials." },
  { slug: "nmap", name: "Nmap", category: "NETWORK", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PORT_DISCOVERY", "SERVICE_DETECTION"], supportedTargets: ["IP_ADDRESS", "CIDR", "DOMAIN"], requiresCredentials: [], description: "Network discovery and service version detection." },
  { slug: "masscan", name: "Masscan", category: "NETWORK", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PORT_DISCOVERY"], supportedTargets: ["IP_ADDRESS", "CIDR"], requiresCredentials: [], description: "High-speed internet-scale port scanner." },
  { slug: "rustscan", name: "RustScan", category: "NETWORK", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PORT_DISCOVERY"], supportedTargets: ["IP_ADDRESS", "CIDR"], requiresCredentials: [], description: "Fast port scanner front-end." },
  { slug: "netdiscover", name: "Netdiscover", category: "NETWORK", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PORT_DISCOVERY"], supportedTargets: ["CIDR"], requiresCredentials: [], description: "ARP-based local network host discovery (lab networks)." },
  { slug: "arp-scan", name: "arp-scan", category: "NETWORK", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PORT_DISCOVERY"], supportedTargets: ["CIDR"], requiresCredentials: [], description: "ARP-based local network discovery (lab networks)." },
  { slug: "wireshark", name: "Wireshark", category: "NETWORK", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["CIDR"], requiresCredentials: [], description: "Packet capture analysis (lab/offline captures)." },
  { slug: "tcpdump", name: "tcpdump", category: "NETWORK", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["CIDR"], requiresCredentials: [], description: "Command-line packet analyzer (lab/offline captures)." },
  { slug: "tshark", name: "tshark", category: "NETWORK", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["CIDR"], requiresCredentials: [], description: "Terminal Wireshark for capture analysis." },
  { slug: "metasploit-framework", name: "Metasploit Framework", category: "NETWORK", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["IP_ADDRESS"], requiresCredentials: [], description: "Exploitation framework — restricted: controlled validation only, disabled by default, never auto-selected." },
  { slug: "searchsploit", name: "SearchSploit", category: "NETWORK", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["IP_ADDRESS"], requiresCredentials: [], description: "Local Exploit-DB search; offline reference only." },
  { slug: "greenbone-openvas", name: "Greenbone/OpenVAS", category: "NETWORK", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["IP_ADDRESS", "CIDR"], requiresCredentials: [], description: "Full vulnerability scanner appliance integration." },
  { slug: "nessus-professional", name: "Nessus Professional", category: "NETWORK", riskLevel: "MODERATE", licenseType: "ADMIN_PROVIDED", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["IP_ADDRESS", "CIDR"], requiresCredentials: ["NESSUS_API"], description: "Commercial vulnerability scanner; admin supplies license and API access." },
  { slug: "postman", name: "Postman", category: "API", riskLevel: "LOW", licenseType: "COMMERCIAL", requiresApproval: false, capabilities: ["API_DISCOVERY", "SPEC_IMPORT"], supportedTargets: ["API"], requiresCredentials: [], description: "API platform — collections import as guarded inventory (Prompt 9 §10/§11): secret-like variable values are dropped and replaced by secret references, never stored." },
  { slug: "insomnia", name: "Insomnia", category: "API", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["API_DISCOVERY", "SPEC_IMPORT"], supportedTargets: ["API"], requiresCredentials: [], description: "API client — workspace exports import as guarded inventory (Prompt 9 §12), secret environment values dropped." },
  { slug: "kiterunner", name: "Kiterunner", category: "API", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["API_DISCOVERY", "ROUTE_DISCOVERY"], supportedTargets: ["API"], requiresCredentials: [], description: "API route discovery with platform-governed route wordlists (Prompt 9 §13/§14). Discovers routes only — no authorization testing, no data modification." },
  { slug: "jwt-tool", name: "jwt_tool", category: "API", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["JWT_INSPECTION", "JWT_CONFIGURATION_ANALYSIS"], supportedTargets: ["API", "GRAPHQL"], requiresCredentials: [], description: "JWT INSPECTION only (Prompt 9 §22–§25): decode + claim inventory + algorithm/expiry/sensitive-claim policy checks. No cracking, brute force or tampering exists; raw tokens are never stored." },
  { slug: "graphqlmap", name: "GraphQLmap", category: "API", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["GRAPHQL_ANALYSIS"], supportedTargets: ["GRAPHQL"], requiresCredentials: [], description: "GraphQL endpoint discovery/fingerprint support (Prompt 9 §28). The platform records inventory facts only — exploitation payloads are never replayed." },
  { slug: "inql", name: "InQL", category: "API", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["GRAPHQL_ANALYSIS", "GRAPHQL_SCHEMA_ANALYSIS"], supportedTargets: ["GRAPHQL"], requiresCredentials: [], description: "GraphQL introspection capture and schema analysis (Prompt 9 §27). Introspection availability is inventory, never a finding by itself (§29)." },
  { slug: "schemathesis", name: "Schemathesis", category: "API", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SCHEMA_BASED_API_TESTING", "API_VALIDATION"], supportedTargets: ["API"], requiresCredentials: [], description: "Schema-based API testing from imported OpenAPI documents (Prompt 9 §15/§62), restricted to safe conformance checks and operations the API operation policy approves — state-changing operations are excluded before execution." },
  { slug: "mitmproxy", name: "mitmproxy", category: "API", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PROXY", "HTTP_TRAFFIC_CAPTURE", "API_DISCOVERY", "WEBSOCKET_DISCOVERY", "ENDPOINT_IMPORT", "REQUEST_COLLECTION"], supportedTargets: ["API", "WEB_APPLICATION"], requiresCredentials: [], description: "Open-source interactive proxy (Prompt 9 §33): API traffic capture, endpoint discovery from observed flows and WebSocket inventory via admin-registered instances. Traffic intelligence only — no findings are derived." },
  { slug: "bloodhound", name: "BloodHound", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "AD identity graph analysis from collected data (approved environments only)." },
  { slug: "sharphound", name: "SharpHound", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "BloodHound data collector for authorized AD environments." },
  { slug: "netexec", name: "NetExec", category: "ACTIVE_DIRECTORY", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION", "VULNERABILITY_SCANNING"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: ["AD_CREDENTIAL"], description: "Network service exploitation framework for approved AD engagements." },
  { slug: "impacket", name: "Impacket", category: "ACTIVE_DIRECTORY", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: ["AD_CREDENTIAL"], description: "Python classes for network protocol work in approved AD labs." },
  { slug: "certipy", name: "Certipy", category: "ACTIVE_DIRECTORY", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: ["AD_CREDENTIAL"], description: "AD Certificate Services enumeration and auditing." },
  { slug: "pingcastle", name: "PingCastle", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "Active Directory security posture assessment." },
  { slug: "enum4linux-ng", name: "enum4linux-ng", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "SMB/LDAP enumeration for approved environments." },
  { slug: "smbmap", name: "SMBMap", category: "ACTIVE_DIRECTORY", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: ["AD_CREDENTIAL"], description: "SMB share enumeration for approved environments." },
  { slug: "ldapsearch", name: "ldapsearch", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "LDAP directory queries for approved environments." },
  { slug: "kerbrute", name: "Kerbrute", category: "ACTIVE_DIRECTORY", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "Kerberos pre-auth enumeration in approved environments." },
  { slug: "responder", name: "Responder", category: "ACTIVE_DIRECTORY", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "LLMNR/NBT-NS poisoner — restricted, lab-only, disabled by default." },
  { slug: "powerview", name: "PowerView", category: "ACTIVE_DIRECTORY", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "PowerSploit AD reconnaissance for approved environments." },
  { slug: "adexplorer", name: "ADExplorer", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "Sysinternals AD object viewer for approved environments." },
  { slug: "hashcat", name: "Hashcat", category: "PASSWORD_AUDIT", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Offline password recovery — only on explicitly uploaded, authorized audit material." },
  { slug: "john-the-ripper", name: "John the Ripper", category: "PASSWORD_AUDIT", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Offline password auditing on uploaded, authorized material only." },
  { slug: "hydra", name: "Hydra", category: "PASSWORD_AUDIT", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["IP_ADDRESS"], requiresCredentials: [], description: "Online credential attacks — restricted and disabled by default." },
  { slug: "medusa", name: "Medusa", category: "PASSWORD_AUDIT", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["IP_ADDRESS"], requiresCredentials: [], description: "Online credential attacks — restricted and disabled by default." },
  { slug: "cewl", name: "CeWL", category: "PASSWORD_AUDIT", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CONTENT_DISCOVERY"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Custom wordlist generator from target content (offline auditing aid)." },
  { slug: "crunch", name: "Crunch", category: "PASSWORD_AUDIT", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CONTENT_DISCOVERY"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Wordlist generator for offline auditing." },
  { slug: "mobsf", name: "MobSF", category: "MOBILE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["MOBILE_STATIC_ANALYSIS"], supportedTargets: ["APK"], requiresCredentials: [], description: "Mobile security framework for APK static analysis." },
  { slug: "frida", name: "Frida", category: "MOBILE", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["MOBILE_STATIC_ANALYSIS"], supportedTargets: ["APK"], requiresCredentials: [], description: "Dynamic instrumentation on authorized test devices only." },
  { slug: "objection", name: "Objection", category: "MOBILE", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["MOBILE_STATIC_ANALYSIS"], supportedTargets: ["APK"], requiresCredentials: [], description: "Runtime mobile exploration on authorized test devices only." },
  { slug: "jadx", name: "JADX", category: "MOBILE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["MOBILE_STATIC_ANALYSIS"], supportedTargets: ["APK"], requiresCredentials: [], description: "Android decompiler for static analysis." },
  { slug: "apktool", name: "apktool", category: "MOBILE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["MOBILE_STATIC_ANALYSIS"], supportedTargets: ["APK"], requiresCredentials: [], description: "APK resource decoding for static analysis." },
  { slug: "adb", name: "ADB", category: "MOBILE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["MOBILE_STATIC_ANALYSIS"], supportedTargets: ["APK"], requiresCredentials: [], description: "Android Debug Bridge for authorized test devices only." },
  { slug: "prowler", name: "Prowler", category: "CLOUD", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CLOUD_CONFIGURATION_AUDIT"], supportedTargets: ["AWS", "AZURE", "GCP"], requiresCredentials: ["CLOUD_CREDENTIAL"], description: "Cloud security assessment with read-only credentials." },
  { slug: "scoutsuite", name: "ScoutSuite", category: "CLOUD", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CLOUD_CONFIGURATION_AUDIT"], supportedTargets: ["AWS", "AZURE", "GCP"], requiresCredentials: ["CLOUD_CREDENTIAL"], description: "Multi-cloud security auditing tool." },
  { slug: "cloudmapper", name: "CloudMapper", category: "CLOUD", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CLOUD_CONFIGURATION_AUDIT"], supportedTargets: ["AWS"], requiresCredentials: ["CLOUD_CREDENTIAL"], description: "Cloud environment visualization and analysis." },
  { slug: "roadtools", name: "ROADtools", category: "CLOUD", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CLOUD_CONFIGURATION_AUDIT"], supportedTargets: ["AZURE"], requiresCredentials: ["CLOUD_CREDENTIAL"], description: "Azure AD exploration framework for authorized tenants." },
  { slug: "pacu", name: "Pacu", category: "CLOUD", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CLOUD_CONFIGURATION_AUDIT"], supportedTargets: ["AWS"], requiresCredentials: ["CLOUD_CREDENTIAL"], description: "AWS exploitation framework — approved cloud engagements only." },
  { slug: "steampipe", name: "Steampipe", category: "CLOUD", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CLOUD_CONFIGURATION_AUDIT"], supportedTargets: ["AWS", "AZURE", "GCP"], requiresCredentials: ["CLOUD_CREDENTIAL"], description: "SQL queries over cloud APIs for posture checks." },
  { slug: "checkov", name: "Checkov", category: "CLOUD", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CLOUD_CONFIGURATION_AUDIT", "SAST"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Infrastructure-as-code static analysis." },
  { slug: "trivy", name: "Trivy", category: "CONTAINER", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CONTAINER_SCANNING", "SCA", "SECRET_SCANNING"], supportedTargets: ["CONTAINER_IMAGE", "SOURCE_REPOSITORY"], requiresCredentials: [], description: "Container, IaC and repository vulnerability scanner." },
  { slug: "grype", name: "Grype", category: "CONTAINER", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CONTAINER_SCANNING", "SCA"], supportedTargets: ["CONTAINER_IMAGE", "SOURCE_REPOSITORY"], requiresCredentials: [], description: "Vulnerability scanner for container images and filesystems." },
  { slug: "syft", name: "Syft", category: "CONTAINER", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SCA"], supportedTargets: ["CONTAINER_IMAGE", "SOURCE_REPOSITORY"], requiresCredentials: [], description: "SBOM generation for images and filesystems." },
  { slug: "docker-bench-for-security", name: "Docker Bench for Security", category: "CONTAINER", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CONTAINER_SCANNING"], supportedTargets: ["DOCKER"], requiresCredentials: [], description: "Docker host configuration checks (CIS benchmark)." },
  { slug: "kube-bench", name: "kube-bench", category: "CONTAINER", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CONTAINER_SCANNING"], supportedTargets: ["KUBERNETES"], requiresCredentials: [], description: "Kubernetes CIS benchmark checks." },
  { slug: "kube-hunter", name: "kube-hunter", category: "CONTAINER", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CONTAINER_SCANNING"], supportedTargets: ["KUBERNETES"], requiresCredentials: [], description: "Kubernetes penetration-testing discovery tool." },
  { slug: "kubescape", name: "Kubescape", category: "CONTAINER", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CONTAINER_SCANNING"], supportedTargets: ["KUBERNETES"], requiresCredentials: [], description: "Kubernetes security posture framework." },
  { slug: "falco", name: "Falco", category: "CONTAINER", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CONTAINER_SCANNING"], supportedTargets: ["KUBERNETES", "DOCKER"], requiresCredentials: [], description: "Runtime security monitoring for containers." },
  { slug: "semgrep", name: "Semgrep", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SAST"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Static analysis with community and custom rules." },
  { slug: "sonarqube", name: "SonarQube", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SAST", "SCA"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: ["SONAR_TOKEN"], description: "Code quality and security platform (self-hosted or admin-provided)." },
  { slug: "codeql", name: "CodeQL", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SAST"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Semantic code analysis engine." },
  { slug: "bandit", name: "Bandit", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SAST"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Python source security linter." },
  { slug: "brakeman", name: "Brakeman", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SAST"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Rails application security scanner." },
  { slug: "spotbugs", name: "SpotBugs", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SAST"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Java bytecode bug and security analysis." },
  { slug: "gitleaks", name: "Gitleaks", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SECRET_SCANNING"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Secret scanning for git repositories." },
  { slug: "trufflehog", name: "TruffleHog", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SECRET_SCANNING"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "High-entropy secret scanning for repositories." },
  { slug: "owasp-dependency-check", name: "OWASP Dependency-Check", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SCA"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Dependency vulnerability analysis (CVE matching)." },
  { slug: "ghidra", name: "Ghidra", category: "BINARY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["BINARY_ANALYSIS"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Software reverse engineering suite for uploaded binaries." },
  { slug: "cutter", name: "Cutter", category: "BINARY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["BINARY_ANALYSIS"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "radare2-powered reverse engineering GUI backend." },
  { slug: "radare2", name: "radare2", category: "BINARY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["BINARY_ANALYSIS"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Reverse engineering framework for uploaded artifacts." },
  { slug: "gdb", name: "GDB", category: "BINARY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["BINARY_ANALYSIS"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Debugger for authorized lab artifacts only." },
  { slug: "pwndbg", name: "pwndbg", category: "BINARY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["BINARY_ANALYSIS"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "GDB enhancement for lab binary analysis." },
  { slug: "binary-ninja", name: "Binary Ninja", category: "BINARY", riskLevel: "LOW", licenseType: "ADMIN_PROVIDED", requiresApproval: true, capabilities: ["BINARY_ANALYSIS"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Commercial reverse engineering platform; admin supplies license." },
  { slug: "ida", name: "IDA", category: "BINARY", riskLevel: "LOW", licenseType: "ADMIN_PROVIDED", requiresApproval: true, capabilities: ["BINARY_ANALYSIS"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Commercial disassembler; admin supplies license and installation." },
  { slug: "checksec", name: "checksec", category: "BINARY", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["BINARY_ANALYSIS"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Binary hardening property checker." },
  { slug: "aircrack-ng", name: "Aircrack-ng", category: "WIRELESS", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["WIRELESS_LAB"], requiresCredentials: [], description: "Wireless lab assessment suite — lab module only, never an internet target." },
  { slug: "kismet", name: "Kismet", category: "WIRELESS", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["WIRELESS_LAB"], requiresCredentials: [], description: "Wireless network detector for lab use." },
  { slug: "wifite", name: "Wifite", category: "WIRELESS", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["WIRELESS_LAB"], requiresCredentials: [], description: "Automated wireless auditing — isolated lab only, requires approval." },
  { slug: "hcxdumptool", name: "hcxdumptool", category: "WIRELESS", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["WIRELESS_LAB"], requiresCredentials: [], description: "WLAN packet capture for lab assessments." },
  { slug: "hcxtools", name: "hcxtools", category: "WIRELESS", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SERVICE_DETECTION"], supportedTargets: ["WIRELESS_LAB"], requiresCredentials: [], description: "WLAN capture conversion tools for lab assessments." },
  { slug: "defectdojo", name: "DefectDojo", category: "REPORTING", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["REPORT_EXPORT"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: ["DEFECTDOJO_API_KEY"], description: "Vulnerability management platform export target." },
  { slug: "faraday", name: "Faraday", category: "REPORTING", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["REPORT_EXPORT"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Collaborative vulnerability management workspace export." },
  { slug: "dradis", name: "Dradis", category: "REPORTING", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["REPORT_EXPORT"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Reporting and collaboration framework export." },
  { slug: "plextrac", name: "PlexTrac", category: "REPORTING", riskLevel: "PASSIVE", licenseType: "ADMIN_PROVIDED", requiresApproval: true, capabilities: ["REPORT_EXPORT"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: ["PLEXTRAC_API"], description: "Commercial reporting platform; admin supplies access." },
  { slug: "serpico", name: "Serpico", category: "REPORTING", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["REPORT_EXPORT"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Report generation collaboration tool export." },
];

const MODE: Record<string, "CONTAINER" | "EXTERNAL_API" | "ADMIN_PROVIDED"> = {
  "shodan-cli": "EXTERNAL_API", "censys-cli": "EXTERNAL_API",
  "owasp-zap": "EXTERNAL_API", "caido": "EXTERNAL_API",
  "burp-suite-professional": "ADMIN_PROVIDED", "nessus-professional": "ADMIN_PROVIDED",
  "binary-ninja": "ADMIN_PROVIDED", "ida": "ADMIN_PROVIDED", "plextrac": "ADMIN_PROVIDED",
};

async function main(): Promise<void> {
  for (const t of TOOLS) {
    const tool = await prisma.tool.upsert({
      where: { slug: t.slug },
      update: { name: t.name, category: t.category, description: t.description, riskLevel: t.riskLevel, licenseType: t.licenseType, requiresApproval: t.requiresApproval },
      create: { slug: t.slug, name: t.name, category: t.category, description: t.description, riskLevel: t.riskLevel, licenseType: t.licenseType, requiresApproval: t.requiresApproval },
    });
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { capabilities: t.capabilities, supportedTargets: t.supportedTargets },
      create: {
        toolId: tool.id, adapterVersion: "1.0.0",
        executionMode: MODE[t.slug] ?? "CONTAINER",
        supportedTargets: t.supportedTargets, capabilities: t.capabilities,
        inputSchema: { note: "Catalog metadata only — adapter not yet implemented", requiresCredentials: t.requiresCredentials },
        outputFormat: "JSON", parser: "json", defaultTimeout: 600,
        networkPolicy: "SCOPE_ONLY", enabled: false, // catalog entry, NOT an implemented adapter
      },
    });
  }
  // Prompt 5: adapters implemented in code are seeded ENABLED so the
  // registry/planner can select them. Health stays UNKNOWN in the catalog —
  // the real state is probed live (API plan-time + worker execution-time).
  const IMPLEMENTED_RECON: Array<{ slug: string; outputFormat: string; parser: string; defaultTimeout: number; networkPolicy: string }> = [
    { slug: "subfinder", outputFormat: "JSONL", parser: "subfinder-jsonl", defaultTimeout: 300, networkPolicy: "INTERNET_READ_ONLY" },
    { slug: "amass", outputFormat: "JSONL", parser: "amass-jsonl", defaultTimeout: 600, networkPolicy: "INTERNET_READ_ONLY" },
    { slug: "assetfinder", outputFormat: "TEXT", parser: "assetfinder-text", defaultTimeout: 300, networkPolicy: "INTERNET_READ_ONLY" },
    { slug: "findomain", outputFormat: "TEXT", parser: "findomain-text", defaultTimeout: 300, networkPolicy: "INTERNET_READ_ONLY" },
    { slug: "dnsx", outputFormat: "JSONL", parser: "dnsx-jsonl", defaultTimeout: 300, networkPolicy: "SCOPE_ONLY" },
    { slug: "httpx", outputFormat: "JSONL", parser: "httpx-jsonl", defaultTimeout: 600, networkPolicy: "SCOPE_ONLY" },
    { slug: "whatweb", outputFormat: "JSON", parser: "whatweb-json", defaultTimeout: 300, networkPolicy: "SCOPE_ONLY" },
    { slug: "gau", outputFormat: "TEXT", parser: "gau-text", defaultTimeout: 300, networkPolicy: "INTERNET_READ_ONLY" },
    { slug: "waybackurls", outputFormat: "TEXT", parser: "waybackurls-text", defaultTimeout: 300, networkPolicy: "INTERNET_READ_ONLY" },
    { slug: "katana", outputFormat: "JSONL", parser: "katana-jsonl", defaultTimeout: 900, networkPolicy: "SCOPE_ONLY" },
  ];
  for (const impl of IMPLEMENTED_RECON) {
    const tool = await prisma.tool.findUnique({ where: { slug: impl.slug } });
    const catalog = TOOLS.find((x) => x.slug === impl.slug);
    if (!tool || !catalog) continue;
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { enabled: true, executionMode: "CONTAINER", outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, inputSchema: { note: "Implemented adapter (Prompt 5) — validated input schema enforced in code by the security-sdk adapter", implementedPhase: 5 } },
      create: { toolId: tool.id, adapterVersion: "1.0.0", enabled: true, executionMode: "CONTAINER", outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, supportedTargets: catalog.supportedTargets, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 5)", implementedPhase: 5 } },
    });
  }
  // Prompt 6: the web content / route / parameter discovery adapters.
  // Content discovery is intrusive-adjacent, so these run SCOPE_ONLY with
  // the adapters' conservative default rates and governed wordlists.
  const IMPLEMENTED_WEB_DISCOVERY: Array<{ slug: string; outputFormat: string; parser: string; defaultTimeout: number; networkPolicy: string }> = [
    { slug: "ffuf", outputFormat: "JSON", parser: "ffuf-json", defaultTimeout: 600, networkPolicy: "SCOPE_ONLY" },
    { slug: "feroxbuster", outputFormat: "JSON", parser: "feroxbuster-json", defaultTimeout: 900, networkPolicy: "SCOPE_ONLY" },
    { slug: "gobuster", outputFormat: "TEXT", parser: "gobuster-text", defaultTimeout: 600, networkPolicy: "SCOPE_ONLY" },
    { slug: "wfuzz", outputFormat: "JSON", parser: "wfuzz-json", defaultTimeout: 600, networkPolicy: "SCOPE_ONLY" },
    { slug: "arjun", outputFormat: "JSON", parser: "arjun-json", defaultTimeout: 300, networkPolicy: "SCOPE_ONLY" },
  ];
  for (const impl of IMPLEMENTED_WEB_DISCOVERY) {
    const tool = await prisma.tool.findUnique({ where: { slug: impl.slug } });
    const catalog = TOOLS.find((x) => x.slug === impl.slug);
    if (!tool || !catalog) continue;
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { enabled: true, executionMode: "CONTAINER", outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, inputSchema: { note: "Implemented adapter (Prompt 6) — validated input schema enforced in code by the security-sdk adapter; wordlists referenced by registered id only", implementedPhase: 6 } },
      create: { toolId: tool.id, adapterVersion: "1.0.0", enabled: true, executionMode: "CONTAINER", outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, supportedTargets: catalog.supportedTargets, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 6)", implementedPhase: 6 } },
    });
  }
  // Implemented adapters (Prompt 7): vulnerability detection + TLS. These
  // run SCOPE_ONLY like the other active stages; Nuclei additionally runs
  // under the governed SAFE template policy enforced in code (§4) — the
  // seed only marks the adapter implemented + enabled.
  const IMPLEMENTED_VULN: Array<{ slug: string; outputFormat: string; parser: string; defaultTimeout: number; networkPolicy: string }> = [
    { slug: "nuclei", outputFormat: "JSONL", parser: "nuclei-jsonl", defaultTimeout: 1200, networkPolicy: "SCOPE_ONLY" },
    { slug: "nikto", outputFormat: "JSON", parser: "nikto-json", defaultTimeout: 1800, networkPolicy: "SCOPE_ONLY" },
    { slug: "testssl", outputFormat: "JSON", parser: "testssl-json", defaultTimeout: 900, networkPolicy: "SCOPE_ONLY" },
    { slug: "sslyze", outputFormat: "JSON", parser: "sslyze-json", defaultTimeout: 900, networkPolicy: "SCOPE_ONLY" },
  ];
  for (const impl of IMPLEMENTED_VULN) {
    const tool = await prisma.tool.findUnique({ where: { slug: impl.slug } });
    const catalog = TOOLS.find((x) => x.slug === impl.slug);
    if (!tool || !catalog) continue;
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { enabled: true, executionMode: "CONTAINER", outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, inputSchema: { note: "Implemented adapter (Prompt 7) — Nuclei templates selected by the governed template policy in code; templates are never user-supplied paths", implementedPhase: 7 } },
      create: { toolId: tool.id, adapterVersion: "1.0.0", enabled: true, executionMode: "CONTAINER", outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, supportedTargets: catalog.supportedTargets, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 7)", implementedPhase: 7 } },
    });
  }
  // Implemented connectors (Prompt 8): interactive proxy scanners. These
  // are NOT containers — they execute through admin-registered scanner
  // instances (ScannerInstance rows) resolved from server configuration.
  // With no instance registered, health is honestly NOT_CONFIGURED (§66);
  // the seed only marks the connector implemented + enabled.
  const IMPLEMENTED_PROXY: Array<{ slug: string; executionMode: "EXTERNAL_API" | "ADMIN_PROVIDED"; outputFormat: string; parser: string; defaultTimeout: number; networkPolicy: string }> = [
    { slug: "owasp-zap", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "zap-json", defaultTimeout: 1200, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "burp-suite-professional", executionMode: "ADMIN_PROVIDED", outputFormat: "JSON", parser: "burp-xml", defaultTimeout: 1200, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "caido", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "caido-json", defaultTimeout: 1200, networkPolicy: "CUSTOM_ALLOWLIST" },
    // Prompt 9 §33: mitmproxy joins the connector family (traffic
    // intelligence; registered-instance based like the others).
    { slug: "mitmproxy", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "mitmproxy-flows", defaultTimeout: 1200, networkPolicy: "CUSTOM_ALLOWLIST" },
  ];
  for (const impl of IMPLEMENTED_PROXY) {
    const tool = await prisma.tool.findUnique({ where: { slug: impl.slug } });
    const catalog = TOOLS.find((x) => x.slug === impl.slug);
    if (!tool || !catalog) continue;
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, inputSchema: { note: "Interactive scanner connector (Prompt 8) — executes only against admin-registered scanner instances; endpoints are opaque references resolved from server configuration, credentials are secret references only", implementedPhase: 8 } },
      create: { toolId: tool.id, adapterVersion: "1.0.0", enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, supportedTargets: catalog.supportedTargets, capabilities: catalog.capabilities, inputSchema: { note: "Interactive scanner connector (Prompt 8)", implementedPhase: 8 } },
    });
  }
  // Implemented API adapters + importers (Prompt 9): route discovery,
  // safe schema testing, GraphQL analysis and JWT inspection run
  // SCOPE_ONLY under the API operation policy enforced in code (§16/§17);
  // Postman/Insomnia are platform importers (no subprocess) whose health
  // is the importer's own availability.
  const IMPLEMENTED_API: Array<{ slug: string; executionMode: "CONTAINER" | "EXTERNAL_API"; outputFormat: string; parser: string; defaultTimeout: number; networkPolicy: string }> = [
    { slug: "kiterunner", executionMode: "CONTAINER", outputFormat: "JSONL", parser: "kiterunner-jsonl", defaultTimeout: 600, networkPolicy: "SCOPE_ONLY" },
    { slug: "schemathesis", executionMode: "CONTAINER", outputFormat: "XML", parser: "schemathesis-junit", defaultTimeout: 900, networkPolicy: "SCOPE_ONLY" },
    { slug: "inql", executionMode: "CONTAINER", outputFormat: "JSON", parser: "inql-json", defaultTimeout: 300, networkPolicy: "SCOPE_ONLY" },
    { slug: "graphqlmap", executionMode: "CONTAINER", outputFormat: "TEXT", parser: "graphqlmap-text", defaultTimeout: 300, networkPolicy: "SCOPE_ONLY" },
    { slug: "jwt-tool", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "jwt-inspection", defaultTimeout: 60, networkPolicy: "NONE" },
    { slug: "postman", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "postman-collection", defaultTimeout: 60, networkPolicy: "NONE" },
    { slug: "insomnia", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "insomnia-export", defaultTimeout: 60, networkPolicy: "NONE" },
  ];
  for (const impl of IMPLEMENTED_API) {
    const tool = await prisma.tool.findUnique({ where: { slug: impl.slug } });
    const catalog = TOOLS.find((x) => x.slug === impl.slug);
    if (!tool || !catalog) continue;
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, inputSchema: { note: "Implemented (Prompt 9) — API operation policy + import guards enforced in code by the security-sdk; JWT inspection never persists raw tokens", implementedPhase: 9 } },
      create: { toolId: tool.id, adapterVersion: "1.0.0", enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, supportedTargets: catalog.supportedTargets, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter/importer (Prompt 9)", implementedPhase: 9 } },
    });
  }
  // Prompt 6 §10: wordlists are governed platform data, seeded from the
  // security-sdk's bundled registry so DB metadata and code can never
  // drift. Entries themselves live in controlled storage (bundled lists
  // ship with the worker image); only metadata is persisted here.
  for (const w of BUNDLED_WORDLISTS) {
    const data = {
      description: w.description, category: w.category, storageLocation: w.storageLocation,
      checksum: w.checksum, entryCount: w.entryCount, sizeBytes: w.sizeBytes, enabled: w.enabled,
      profiles: [...w.profiles], technologies: w.technology ? [w.technology] : [],
    };
    await prisma.wordlist.upsert({ where: { name: w.name }, update: data, create: { name: w.name, ...data } });
  }
  // The safe mock (simulation) and local echo (diagnostics).
  const mock = await prisma.tool.upsert({
    where: { slug: "mock" },
    update: {},
    create: {
      slug: "mock", name: "Mock Security Adapter (TEST ONLY)", category: "REPORTING",
      description: "Exercises the pipeline end-to-end. Performs no network activity and produces no findings.",
      riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", installed: true, healthStatus: "HEALTHY",
    },
  });
  await prisma.toolAdapter.upsert({
    where: { toolId_adapterVersion: { toolId: mock.id, adapterVersion: "1.0.0" } },
    update: {},
    create: {
      toolId: mock.id, adapterVersion: "1.0.0", executionMode: "MOCK",
      supportedTargets: ["DOMAIN", "WEB_APPLICATION"], capabilities: [], outputFormat: "JSON",
      parser: "json", defaultTimeout: 5, networkPolicy: "NO_NETWORK", enabled: true,
    },
  });
  const echo = await prisma.tool.upsert({
    where: { slug: "local-echo" },
    update: {},
    create: {
      slug: "local-echo", name: "Local Echo Adapter (TEST ONLY)", category: "REPORTING",
      description: "Echoes validated plan arguments in-process. No network, no subprocess, no findings.",
      riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", installed: true, healthStatus: "HEALTHY",
    },
  });
  await prisma.toolAdapter.upsert({
    where: { toolId_adapterVersion: { toolId: echo.id, adapterVersion: "1.0.0" } },
    update: {},
    create: {
      toolId: echo.id, adapterVersion: "1.0.0", executionMode: "MOCK",
      supportedTargets: ["DOMAIN", "WEB_APPLICATION"], capabilities: [], outputFormat: "JSON",
      parser: "json", defaultTimeout: 5, networkPolicy: "NO_NETWORK", enabled: true,
    },
  });
  console.log(`Seeded ${TOOLS.length + 2} tool catalog entries (10 recon + 5 web-discovery adapters enabled — Prompts 5–6; ${BUNDLED_WORDLISTS.length} governed wordlists; other catalog adapters disabled)`);
}

main().catch((e) => { console.error(e); process.exit(1); }).finally(() => prisma.$disconnect());
