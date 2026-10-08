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
  { slug: "nmap", name: "Nmap", category: "NETWORK", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["HOST_DISCOVERY", "PORT_DISCOVERY", "SERVICE_DETECTION", "VERSION_DETECTION", "OS_HINTING", "SAFE_NETWORK_CHECKS"], supportedTargets: ["IP_ADDRESS", "CIDR", "DOMAIN"], requiresCredentials: [], description: "Host discovery, port scanning, service/version fingerprinting, OS hinting and governed SAFE NSE checks (Prompt 10). Commands are built only from validated typed configuration." },
  { slug: "masscan", name: "Masscan", category: "NETWORK", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["HIGH_SPEED_PORT_DISCOVERY"], supportedTargets: ["IP_ADDRESS", "CIDR"], requiresCredentials: [], description: "High-speed port discovery (Prompt 10 §19): elevated policy — explicit profile + administrator approval + hard rate/target clamps; never auto-selected." },
  { slug: "rustscan", name: "RustScan", category: "NETWORK", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PORT_DISCOVERY"], supportedTargets: ["IP_ADDRESS", "CIDR"], requiresCredentials: [], description: "Fast port scanner front-end (Prompt 10 §18 — no downstream command passthrough)." },
  { slug: "netdiscover", name: "Netdiscover", category: "NETWORK", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["LOCAL_NETWORK_DISCOVERY"], supportedTargets: ["CIDR"], requiresCredentials: [], description: "ARP-based local network host discovery (Prompt 10 §21) — approved internal workers with layer-2 access only." },
  { slug: "arp-scan", name: "arp-scan", category: "NETWORK", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["LOCAL_NETWORK_DISCOVERY"], supportedTargets: ["CIDR"], requiresCredentials: [], description: "ARP-based local network discovery (Prompt 10 §22) — approved internal workers with layer-2 access only." },
  { slug: "wireshark", name: "Wireshark", category: "NETWORK", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PACKET_ANALYSIS"], supportedTargets: ["CIDR", "IP_ADDRESS"], requiresCredentials: [], description: "Manual analyst/desktop tool (Prompt 10 §46): NOT a worker adapter — authorized capture exports are analyzed offline by tshark; raw access is VIEW_RAW_PCAP-gated and audited." },
  { slug: "tcpdump", name: "tcpdump", category: "NETWORK", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PACKET_CAPTURE"], supportedTargets: ["CIDR", "IP_ADDRESS"], requiresCredentials: [], description: "Bounded packet capture for approved controlled test environments only (Prompt 10 §44): explicit interface, bounded duration/size." },
  { slug: "tshark", name: "tshark", category: "NETWORK", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PACKET_ANALYSIS"], supportedTargets: ["CIDR", "IP_ADDRESS"], requiresCredentials: [], description: "Offline capture analysis (Prompt 10 §45): protocol hierarchy + HTTP transaction inventory from authorized capture artifacts." },
  { slug: "metasploit-framework", name: "Metasploit Framework", category: "NETWORK", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["IP_ADDRESS"], requiresCredentials: [], description: "Exploitation framework — restricted: controlled validation only, disabled by default, never auto-selected." },
  { slug: "searchsploit", name: "SearchSploit", category: "NETWORK", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["VULNERABILITY_REFERENCE_LOOKUP"], supportedTargets: ["IP_ADDRESS"], requiresCredentials: [], description: "Exploit-DB REFERENCE LOOKUP ONLY (Prompt 11 §17): associates known public exploit references with already-identified CVEs/products. It never executes, downloads, compiles or launches exploit code — reference existence is a risk signal, never confirmation of exploitability (§20/§21)." },
  { slug: "greenbone-openvas", name: "Greenbone/OpenVAS", category: "NETWORK", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING", "NETWORK_VULNERABILITY_ASSESSMENT", "SCAN_RESULT_IMPORT", "VULNERABILITY_DETECTION"], supportedTargets: ["IP_ADDRESS", "CIDR"], requiresCredentials: [], description: "Administrator-managed network vulnerability scanner (Prompt 11 §3): governed scan tasks over scope-derived targets with administrator-approved logical profiles (BASELINE/STANDARD/COMPREHENSIVE); results import through the correlation pipeline." },
  { slug: "nessus-professional", name: "Nessus Professional", category: "NETWORK", riskLevel: "MODERATE", licenseType: "ADMIN_PROVIDED", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING", "NETWORK_VULNERABILITY_ASSESSMENT", "SCAN_RESULT_IMPORT", "VULNERABILITY_DETECTION"], supportedTargets: ["IP_ADDRESS", "CIDR"], requiresCredentials: ["NESSUS_API"], description: "Commercial vulnerability scanner (Prompt 11 §10) — COMMERCIAL / ADMIN_PROVIDED / LICENSE_REQUIRED: used only against an administrator-provided licensed environment, never redistributed. Unconfigured it reports NOT_CONFIGURED (§85)." },
  { slug: "postman", name: "Postman", category: "API", riskLevel: "LOW", licenseType: "COMMERCIAL", requiresApproval: false, capabilities: ["API_DISCOVERY", "SPEC_IMPORT"], supportedTargets: ["API"], requiresCredentials: [], description: "API platform — collections import as guarded inventory (Prompt 9 §10/§11): secret-like variable values are dropped and replaced by secret references, never stored." },
  { slug: "insomnia", name: "Insomnia", category: "API", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["API_DISCOVERY", "SPEC_IMPORT"], supportedTargets: ["API"], requiresCredentials: [], description: "API client — workspace exports import as guarded inventory (Prompt 9 §12), secret environment values dropped." },
  { slug: "kiterunner", name: "Kiterunner", category: "API", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["API_DISCOVERY", "ROUTE_DISCOVERY"], supportedTargets: ["API"], requiresCredentials: [], description: "API route discovery with platform-governed route wordlists (Prompt 9 §13/§14). Discovers routes only — no authorization testing, no data modification." },
  { slug: "jwt-tool", name: "jwt_tool", category: "API", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["JWT_INSPECTION", "JWT_CONFIGURATION_ANALYSIS"], supportedTargets: ["API", "GRAPHQL"], requiresCredentials: [], description: "JWT INSPECTION only (Prompt 9 §22–§25): decode + claim inventory + algorithm/expiry/sensitive-claim policy checks. No cracking, brute force or tampering exists; raw tokens are never stored." },
  { slug: "graphqlmap", name: "GraphQLmap", category: "API", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["GRAPHQL_ANALYSIS"], supportedTargets: ["GRAPHQL"], requiresCredentials: [], description: "GraphQL endpoint discovery/fingerprint support (Prompt 9 §28). The platform records inventory facts only — exploitation payloads are never replayed." },
  { slug: "inql", name: "InQL", category: "API", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["GRAPHQL_ANALYSIS", "GRAPHQL_SCHEMA_ANALYSIS"], supportedTargets: ["GRAPHQL"], requiresCredentials: [], description: "GraphQL introspection capture and schema analysis (Prompt 9 §27). Introspection availability is inventory, never a finding by itself (§29)." },
  { slug: "schemathesis", name: "Schemathesis", category: "API", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SCHEMA_BASED_API_TESTING", "API_VALIDATION"], supportedTargets: ["API"], requiresCredentials: [], description: "Schema-based API testing from imported OpenAPI documents (Prompt 9 §15/§62), restricted to safe conformance checks and operations the API operation policy approves — state-changing operations are excluded before execution." },
  { slug: "mitmproxy", name: "mitmproxy", category: "API", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PROXY", "HTTP_TRAFFIC_CAPTURE", "API_DISCOVERY", "WEBSOCKET_DISCOVERY", "ENDPOINT_IMPORT", "REQUEST_COLLECTION"], supportedTargets: ["API", "WEB_APPLICATION"], requiresCredentials: [], description: "Open-source interactive proxy (Prompt 9 §33): API traffic capture, endpoint discovery from observed flows and WebSocket inventory via admin-registered instances. Traffic intelligence only — no findings are derived." },
  { slug: "ldap-directory-connector", name: "LDAP Directory Connector", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["DIRECTORY_INVENTORY", "LDAP_SECURITY_ANALYSIS", "IDENTITY_RELATIONSHIP_DISCOVERY", "MANUAL_DIRECTORY_ANALYSIS"], supportedTargets: ["ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST", "DOMAIN_CONTROLLER", "LDAP_DIRECTORY", "ACTIVE_DIRECTORY"], requiresCredentials: ["credentialReference"], description: "Platform read-only directory connector (Prompt 15 §15): LDAPS-preferred typed queries against APPROVED domain controllers only, plus governed import of directory exports. Unconfigured it reports NOT_CONFIGURED — data is never fabricated." },
  { slug: "bloodhound-connector", name: "BloodHound Import Connector", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["DIRECTORY_RELATIONSHIP_COLLECTION", "IDENTITY_GRAPH", "SNAPSHOT_IMPORT"], supportedTargets: ["ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST", "DOMAIN_CONTROLLER", "LDAP_DIRECTORY", "ACTIVE_DIRECTORY"], requiresCredentials: ["credentialReference"], description: "BloodHound/SharpHound dataset IMPORT connector (Prompt 15 §27–§31): parses recorded collector exports into the evidence-backed identity graph. Credential material in exports is stripped before persistence (§113); session/local-admin edges follow the collection policy (§29)." },
  { slug: "bloodhound", name: "BloodHound", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["IDENTITY_GRAPH", "PRIVILEGE_RELATIONSHIP_ANALYSIS", "DEFENSIVE_ATTACK_PATH_ANALYSIS"], supportedTargets: ["ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST", "DOMAIN_CONTROLLER", "LDAP_DIRECTORY", "ACTIVE_DIRECTORY"], requiresCredentials: [], description: "AD identity graph analysis from collected data (Prompt 15 §28/§32). Import + graph analysis only — attack paths are defensive models over collected data, never executed (§35)." },
  { slug: "sharphound", name: "SharpHound", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["DIRECTORY_RELATIONSHIP_COLLECTION", "IDENTITY_RELATIONSHIP_DISCOVERY"], supportedTargets: ["ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST", "DOMAIN_CONTROLLER", "LDAP_DIRECTORY", "ACTIVE_DIRECTORY"], requiresCredentials: ["credentialReference"], description: "BloodHound data collector for authorized AD environments (Prompt 15 §27). Collection methods are policy-classified: SAFE methods run by default; session/local-group methods need recorded approval; everything else is refused (§29)." },
  { slug: "netexec", name: "NetExec", category: "ACTIVE_DIRECTORY", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["OFFENSIVE_AD_OPERATIONS"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "DISABLED by policy (Prompt 15 §51): NetExec performs offensive remote operations and credential attacks. DSRclone performs defensive read-only assessment only — no adapter exists, it is never enabled and no stage can select it." },
  { slug: "impacket", name: "Impacket", category: "ACTIVE_DIRECTORY", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["OFFENSIVE_AD_OPERATIONS"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "DISABLED by policy (Prompt 15 §52): Impacket's offensive tooling (secretsdump, pass-the-hash, ticket forgery, DCSync-class operations) is permanently excluded. Defensive protocol parsing exists in libraries, never as executable tooling — no adapter exists." },
  { slug: "certipy", name: "Certipy", category: "ACTIVE_DIRECTORY", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["ADCS_OFFENSIVE_VALIDATION"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "DISABLED by policy (Prompt 15 §47): Certipy's offensive actions (req/auth/forge/relay/shadow/account/ca) are permanently excluded. AD CS assessment uses the governed FIND-only certipy-posture adapter (§48–§50) — no adapter exists for this row." },
  { slug: "certipy-posture", name: "Certipy (posture, find-only)", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["ADCS_INVENTORY", "ADCS_POSTURE_ANALYSIS"], supportedTargets: ["ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST", "DOMAIN_CONTROLLER", "LDAP_DIRECTORY", "ACTIVE_DIRECTORY"], requiresCredentials: ["credentialReference"], description: "Governed Certipy FIND-only posture adapter (Prompt 15 §48–§50): inventories CAs and templates and classifies ESC1–ESC8-style configuration risk. Every other Certipy action is refused at plan time (§112)." },
  { slug: "pingcastle", name: "PingCastle", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "ADMIN_PROVIDED", requiresApproval: true, capabilities: ["AD_SECURITY_POSTURE", "AD_RISK_ASSESSMENT", "DOMAIN_CONFIGURATION_REVIEW"], supportedTargets: ["ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST", "DOMAIN_CONTROLLER", "LDAP_DIRECTORY", "ACTIVE_DIRECTORY"], requiresCredentials: ["credentialReference"], description: "Active Directory security posture assessment (Prompt 15 §38–§40): healthcheck mode only. The PingCastle score is preserved as a separate metric and mapped findings deduplicate against native checks (§39/§61)." },
  { slug: "enum4linux-ng", name: "enum4linux-ng", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SMB_DIRECTORY_ENUMERATION", "WINDOWS_SERVICE_DISCOVERY", "SAFE_SERVICE_ENUMERATION"], supportedTargets: ["ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST", "DOMAIN_CONTROLLER", "LDAP_DIRECTORY", "ACTIVE_DIRECTORY"], requiresCredentials: [], description: "Governed SMB/LDAP inventory adapter (Prompt 15 §42/§43): users/groups/shares/policy enumeration with bounded flags — the all-in-one mode and RID cycling are refused at plan time." },
  { slug: "smbmap", name: "SmbMap", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SMB_SHARE_INVENTORY", "SMB_PERMISSION_REVIEW"], supportedTargets: ["ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST", "DOMAIN_CONTROLLER", "LDAP_DIRECTORY", "ACTIVE_DIRECTORY"], requiresCredentials: ["credentialReference"], description: "SMB share INVENTORY adapter (Prompt 15 §44): share names + permission metadata only. Content listing, download, upload, deletion and recursive drive operations are refused at plan time — share contents are never browsed." },
  { slug: "ldapsearch", name: "ldapsearch", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["DIRECTORY_INVENTORY", "LDAP_SECURITY_ANALYSIS"], supportedTargets: ["ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST", "DOMAIN_CONTROLLER", "LDAP_DIRECTORY", "ACTIVE_DIRECTORY"], requiresCredentials: ["credentialReference"], description: "Governed LDAP query adapter (Prompt 15 §14/§41): platform-generated typed queries only (fixed filters + attribute sets), LDAPS preferred, paged and size-bounded. Raw filters, arbitrary base DNs and credential values in configuration are refused." },
  { slug: "kerbrute", name: "Kerbrute", category: "ACTIVE_DIRECTORY", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["ACCOUNT_AUTHENTICATION_TESTING", "CREDENTIAL_ATTACKS"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "DISABLED by policy (Prompt 15 §53/§120): Kerbrute performs username enumeration, password spraying and AS-REP/TGS requests for offline cracking. Credential attacks are permanently excluded — no adapter exists." },
  { slug: "responder", name: "Responder", category: "ACTIVE_DIRECTORY", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["NETWORK_POISONING", "CREDENTIAL_CAPTURE"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "DISABLED by policy (Prompt 15 §54/§120): Responder poisons LLMNR/NBT-NS/mDNS and captures credentials. Poisoning and credential capture are permanently excluded — no adapter exists." },
  { slug: "powerview", name: "PowerView", category: "ACTIVE_DIRECTORY", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["DIRECTORY_ENUMERATION", "OFFENSIVE_AD_OPERATIONS"], supportedTargets: ["ACTIVE_DIRECTORY"], requiresCredentials: [], description: "DISABLED by policy (Prompt 15 §55): PowerView is offensive AD reconnaissance/enumeration tooling (including hash-dumping helpers). Collection uses the governed platform connectors instead — no adapter exists." },
  { slug: "adexplorer", name: "ADExplorer", category: "ACTIVE_DIRECTORY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["MANUAL_DIRECTORY_ANALYSIS"], supportedTargets: ["ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST", "DOMAIN_CONTROLLER", "LDAP_DIRECTORY", "ACTIVE_DIRECTORY"], requiresCredentials: [], description: "Sysinternals AD object viewer (Prompt 15 §56): MANUAL analysis aid — its exports import through the guarded directory import path; the tool itself is never executed by the platform." },
  { slug: "hashcat", name: "Hashcat", category: "PASSWORD_AUDIT", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Offline password recovery — only on explicitly uploaded, authorized audit material." },
  { slug: "john-the-ripper", name: "John the Ripper", category: "PASSWORD_AUDIT", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Offline password auditing on uploaded, authorized material only." },
  { slug: "hydra", name: "Hydra", category: "PASSWORD_AUDIT", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["IP_ADDRESS"], requiresCredentials: [], description: "Online credential attacks — restricted and disabled by default." },
  { slug: "medusa", name: "Medusa", category: "PASSWORD_AUDIT", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["VULNERABILITY_SCANNING"], supportedTargets: ["IP_ADDRESS"], requiresCredentials: [], description: "Online credential attacks — restricted and disabled by default." },
  { slug: "cewl", name: "CeWL", category: "PASSWORD_AUDIT", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CONTENT_DISCOVERY"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Custom wordlist generator from target content (offline auditing aid)." },
  { slug: "crunch", name: "Crunch", category: "PASSWORD_AUDIT", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CONTENT_DISCOVERY"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Wordlist generator for offline auditing." },
  { slug: "mobsf", name: "MobSF", category: "MOBILE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["MOBILE_STATIC_ANALYSIS", "MANIFEST_ANALYSIS", "CODE_ANALYSIS", "BINARY_ANALYSIS", "CERTIFICATE_ANALYSIS", "NETWORK_SECURITY_CONFIG_ANALYSIS"], supportedTargets: ["MOBILE_APP"], requiresCredentials: [], description: "MobSF static-analysis connector (Prompt 17 §13–§17): submits ONLY authorized artifacts to the administrator-registered trusted ScannerInstance; credentials are secret references on the instance (§14). Unconfigured = NOT_CONFIGURED." },
  { slug: "frida", name: "Frida", category: "MOBILE", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["DYNAMIC_INSTRUMENTATION"], supportedTargets: ["MOBILE_APP"], requiresCredentials: [], description: "DISABLED registration (Prompt 17 §69–§71): Frida instrumentation exists in DSRclone only as administrator-reviewed, versioned modules under the MobileInstrumentationPolicy — default DISABLED for static profiles. No adapter exists, arbitrary user-supplied JavaScript is never accepted (§72/§75), and no stage can select it." },
  { slug: "objection", name: "Objection", category: "MOBILE", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["DYNAMIC_INSTRUMENTATION"], supportedTargets: ["MOBILE_APP"], requiresCredentials: [], description: "APPROVAL_REQUIRED registration (Prompt 17 §73/§74): Objection is never an interactive shell into an application. Governed, administrator-approved modules only, inside an approved lab session — no adapter exists by default and arbitrary commands are prohibited (§75)." },
  { slug: "jadx", name: "JADX", category: "MOBILE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["ANDROID_DECOMPILATION", "STATIC_CODE_EXTRACTION"], supportedTargets: ["MOBILE_APP"], requiresCredentials: [], description: "JADX Android decompilation (Prompt 17 §19): runs in the static sandbox on MOBILE_STATIC_ANALYSIS workers; output is an analysis artifact — decompiled code is NEVER executed and its access is RBAC-gated (§24)." },
  { slug: "apktool", name: "apktool", category: "MOBILE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["APK_RESOURCE_ANALYSIS", "MANIFEST_EXTRACTION", "RESOURCE_EXTRACTION"], supportedTargets: ["MOBILE_APP"], requiresCredentials: [], description: "apktool resource + manifest analysis (Prompt 17 §18): decodes resources/AndroidManifest.xml in the safe extraction workspace; archive attacks are refused at intake (§107)." },
  { slug: "adb", name: "ADB (lab devices)", category: "MOBILE", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["DEVICE_MANAGEMENT", "APP_INSTALLATION", "LOG_COLLECTION", "CONTROLLED_APP_INTERACTION"], supportedTargets: ["MOBILE_APP"], requiresCredentials: [], description: "ADB lab adapter (Prompt 17 §59): governed operations on APPROVED DSRclone-managed lab devices only — device inventory, install of the authorized build (hash verified, §60), launch, logs, reset. There is NO generic adb shell endpoint anywhere (§59/§75); personal devices are never targeted (§55)." },
  { slug: "burp-suite", name: "Burp Suite (mobile proxy)", category: "MOBILE", riskLevel: "MODERATE", licenseType: "ADMIN_PROVIDED", requiresApproval: true, capabilities: ["MOBILE_PROXY_ANALYSIS"], supportedTargets: ["MOBILE_APP"], requiresCredentials: [], description: "Burp Suite connector for mobile proxy analysis (Prompt 17 §65): reuses the Prompt 8 governed connector + MOBILE_PROXY_ANALYSIS — sanitized flow metadata for authorized lab traffic only; no unrestricted Burp control exists." },
  { slug: "prowler", name: "Prowler", category: "CLOUD", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CSPM", "CLOUD_POSTURE", "COMPLIANCE_QUERY"], supportedTargets: ["AWS", "AZURE", "GCP"], requiresCredentials: ["credentialReference"], description: "Prowler CSPM (Prompt 14 §23): multi-cloud CIS/posture checks over read-only credential references. FAIL results become findings on canonical cloud rules; PASS is posture evidence only." },
  { slug: "scoutsuite", name: "ScoutSuite", category: "CLOUD", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CSPM", "CLOUD_POSTURE"], supportedTargets: ["AWS", "AZURE", "GCP"], requiresCredentials: ["credentialReference"], description: "ScoutSuite multi-cloud auditing (Prompt 14 §26): rule results land on the canonical cloud rules and merge with Prowler/native observations of the same issue." },
  { slug: "cloudmapper", name: "CloudMapper", category: "CLOUD", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["AWS_NETWORK_ANALYSIS", "AWS_ACCOUNT_VISUALIZATION", "PUBLIC_EXPOSURE_ANALYSIS"], supportedTargets: ["AWS"], requiresCredentials: ["credentialReference"], description: "CloudMapper (AWS) account-graph import (Prompt 14 §27): public nodes and network structure from recorded exports become exposure evidence in the asset graph." },
  { slug: "roadtools", name: "ROADtools", category: "CLOUD", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["DIRECTORY_ANALYSIS", "IDENTITY_INVENTORY"], supportedTargets: ["AZURE"], requiresCredentials: ["credentialReference"], description: "ROADtools (Entra ID) DEFENSIVE analysis (Prompt 14 §29): role assignments and application permissions from recorded exports. Offensive directory operations are never invoked." },
  { slug: "pacu", name: "Pacu", category: "CLOUD", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CLOUD_OFFENSIVE_TESTING"], supportedTargets: ["AWS"], requiresCredentials: ["credentialReference"], description: "DISABLED by policy (Prompt 14 §34): Pacu is offensive cloud exploitation tooling. DSRclone performs read-only assessment only — no adapter exists, it is never enabled and no stage can select it." },
  { slug: "steampipe", name: "Steampipe", category: "CLOUD", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CLOUD_QUERY", "CSPM"], supportedTargets: ["AWS", "AZURE", "GCP"], requiresCredentials: ["credentialReference"], description: "Steampipe governed query packs (Prompt 14 §32): approved CIS/exposure packs only — arbitrary SQL from users or repositories is refused." },
  { slug: "aws-inventory", name: "AWS Inventory Connector", category: "CLOUD", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CLOUD_INVENTORY", "CLOUD_POSTURE", "IDENTITY_INVENTORY", "RELATIONSHIP_ANALYSIS"], supportedTargets: ["AWS"], requiresCredentials: ["credentialReference"], description: "Read-only AWS inventory (Prompt 14 §16): account structure, IAM, network, storage, encryption and logging metadata. No data-plane access, no mutations (§7/§13)." },
  { slug: "azure-inventory", name: "Azure Inventory Connector", category: "CLOUD", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CLOUD_INVENTORY", "CLOUD_POSTURE", "IDENTITY_INVENTORY", "RELATIONSHIP_ANALYSIS"], supportedTargets: ["AZURE"], requiresCredentials: ["credentialReference"], description: "Read-only Azure inventory (Prompt 14 §17): subscriptions, resource groups, NSGs, storage, RBAC metadata. No data-plane access, no mutations (§7/§13)." },
  { slug: "gcp-inventory", name: "GCP Inventory Connector", category: "CLOUD", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CLOUD_INVENTORY", "CLOUD_POSTURE", "IDENTITY_INVENTORY", "RELATIONSHIP_ANALYSIS"], supportedTargets: ["GCP"], requiresCredentials: ["credentialReference"], description: "Read-only GCP inventory (Prompt 14 §18): organization/folder/project structure, firewall, storage, IAM metadata. No data-plane access, no mutations (§7/§13)." },
  { slug: "checkov", name: "Checkov", category: "CLOUD", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["IAC_SECURITY", "KUBERNETES_MANIFEST_SECURITY", "DOCKERFILE_SECURITY", "HELM_SECURITY"], supportedTargets: ["SOURCE_REPOSITORY", "CONTAINER_IMAGE", "KUBERNETES_MANIFEST", "HELM_CHART", "KUBERNETES_CLUSTER"], requiresCredentials: [], description: "Infrastructure-as-code, Kubernetes manifest, Helm and Dockerfile static analysis (Prompt 13 §46) — IaC is never executed." },
  { slug: "trivy", name: "Trivy", category: "CONTAINER", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["IMAGE_VULNERABILITY_SCANNING", "MISCONFIGURATION_SCANNING", "SECRET_SCANNING", "IMAGE_ANALYSIS"], supportedTargets: ["CONTAINER_IMAGE", "CONTAINER_REGISTRY", "SOURCE_REPOSITORY"], requiresCredentials: [], description: "Static container image analysis: vulnerabilities, misconfigurations and secret metadata (Prompt 13 §15–§18). Images are never executed." },
  { slug: "grype", name: "Grype", category: "CONTAINER", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CONTAINER_SCANNING", "SCA", "PACKAGE_VULNERABILITY_ANALYSIS", "SBOM_ANALYSIS", "IMAGE_VULNERABILITY_SCANNING"], supportedTargets: ["CONTAINER_IMAGE", "SOURCE_REPOSITORY"], requiresCredentials: [], description: "Vulnerability scanner for container images, filesystems and source snapshots (Prompt 12 §51 for source use; Prompt 13 §19 for image use — one adapter, two input kinds)." },
  { slug: "syft", name: "Syft", category: "CONTAINER", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SBOM_GENERATION", "IMAGE_ANALYSIS"], supportedTargets: ["CONTAINER_IMAGE", "SOURCE_REPOSITORY"], requiresCredentials: [], description: "SBOM generation for container images and filesystems (Prompt 13 §12)." },
  { slug: "docker-bench-for-security", name: "Docker Bench for Security", category: "CONTAINER", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["DOCKER_CIS_ASSESSMENT", "DOCKER_HOST_CONFIGURATION", "COMPLIANCE_ASSESSMENT"], supportedTargets: ["DOCKER_HOST"], requiresCredentials: [], description: "CIS Docker Benchmark host checks — INTERNAL_PRIVILEGED: approved host + dedicated privileged worker only (Prompt 13 §28)." },
  { slug: "kube-bench", name: "kube-bench", category: "CONTAINER", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["KUBERNETES_CIS_ASSESSMENT", "COMPLIANCE_ASSESSMENT"], supportedTargets: ["KUBERNETES_CLUSTER"], requiresCredentials: [], description: "CIS Kubernetes Benchmark checks — INTERNAL_PRIVILEGED: approved cluster + dedicated privileged worker only (Prompt 13 §39)." },
  { slug: "kube-hunter", name: "kube-hunter", category: "CONTAINER", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["KUBERNETES_SECURITY_DISCOVERY", "KUBERNETES_POSTURE_TESTING"], supportedTargets: ["KUBERNETES_CLUSTER"], requiresCredentials: [], description: "Kubernetes discovery — automated runs are passive-only by policy; intrusive checks are classified and never executed (Prompt 13 §42/§43)." },
  { slug: "kubescape", name: "Kubescape", category: "CONTAINER", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["KUBERNETES_POSTURE", "MANIFEST_ANALYSIS", "COMPLIANCE_ASSESSMENT"], supportedTargets: ["KUBERNETES_CLUSTER", "KUBERNETES_MANIFEST", "CONTAINER_IMAGE"], requiresCredentials: [], description: "Kubernetes posture and manifest analysis with compliance framework mapping (Prompt 13 §44)." },
  { slug: "falco", name: "Falco", category: "CONTAINER", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["RUNTIME_SECURITY_EVENTS"], supportedTargets: ["KUBERNETES_CLUSTER", "DOCKER_HOST"], requiresCredentials: [], description: "Runtime security sensor — events arrive through the trusted ingestion path; DSRclone never deploys the sensor (Prompt 13 §57–§63)." },
  { slug: "kubernetes-connector", name: "Kubernetes Connector", category: "CONTAINER", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["CLUSTER_INVENTORY", "RESOURCE_INVENTORY", "POSTURE_ASSESSMENT"], supportedTargets: ["KUBERNETES_CLUSTER"], requiresCredentials: ["credentialReference"], description: "Read-only cluster inventory + posture over registered cluster connections; secret values are never retrieved (Prompt 13 §32–§38)." },
  { slug: "semgrep", name: "Semgrep", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SAST", "CODE_PATTERN_ANALYSIS", "SECURITY_RULE_ANALYSIS", "DATAFLOW_ANALYSIS"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Static analysis with the governed, pinned rule-pack catalog (Prompt 12 §22) — users never supply arbitrary rules." },
  { slug: "sonarqube", name: "SonarQube", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["SAST", "CODE_PATTERN_ANALYSIS", "SCAN_RESULT_IMPORT"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: ["SONAR_TOKEN"], description: "Code quality and security platform (self-hosted or admin-provided)." },
  { slug: "codeql", name: "CodeQL", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SAST", "SECURITY_QUERY_ANALYSIS", "DATAFLOW_ANALYSIS"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Semantic code analysis engine with governed query suites + SARIF import (Prompt 12 §28–§31). Build-needing languages degrade as BUILD_REQUIRED — target code is never built." },
  { slug: "bandit", name: "Bandit", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SAST", "PYTHON_SECURITY_ANALYSIS"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Python source security linter (Prompt 12 §25)." },
  { slug: "brakeman", name: "Brakeman", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SAST", "FRAMEWORK_SECURITY_ANALYSIS"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Rails application security scanner (Prompt 12 §26)." },
  { slug: "spotbugs", name: "SpotBugs", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SAST"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Java bytecode analysis (Prompt 12 §29): SECURITY/FindSecBugs findings only — correctness bugs are not vulnerabilities." },
  { slug: "gitleaks", name: "Gitleaks", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SECRET_SCANNING", "SECRET_DETECTION"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Secret scanning for git repositories (Prompt 12 §34). Values are fingerprinted at parse time — never stored or displayed." },
  { slug: "trufflehog", name: "TruffleHog", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SECRET_SCANNING", "SECRET_DETECTION", "SECRET_VERIFICATION"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "High-entropy secret scanning for repositories (Prompt 12 §37). External verification is DISABLED by platform policy (§44)." },
  { slug: "owasp-dependency-check", name: "OWASP Dependency-Check", category: "SOURCE_CODE", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["SCA", "DEPENDENCY_VULNERABILITY_ANALYSIS"], supportedTargets: ["SOURCE_REPOSITORY"], requiresCredentials: [], description: "Dependency vulnerability analysis (Prompt 12 §49) against the worker-provisioned database — no installs, no network audits (§57)." },
  { slug: "ghidra", name: "Ghidra", category: "BINARY", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["BINARY_ANALYSIS", "BINARY_STATIC_ANALYSIS", "NATIVE_LIBRARY_ANALYSIS", "DISASSEMBLY", "DECOMPILATION", "FUNCTION_ANALYSIS", "IMPORT_EXPORT_ANALYSIS", "STRING_REFERENCE_ANALYSIS"], supportedTargets: ["BINARY", "MOBILE_APP"], requiresCredentials: [], description: "Ghidra headless static analysis (Prompt 17 §34–§36, EXTENDED by Prompt 18 §18–§21): native-library hardening inventory PLUS the binary function/import/export/string inventory, from administrator-approved scripts only. Binaries are never executed; no arbitrary Ghidra script is expressible." },
  { slug: "cutter", name: "Cutter", category: "BINARY", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["BINARY_ANALYSIS", "STATIC_BINARY_ANALYSIS"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "ANALYST_TOOL registration (Prompt 18 §35): Cutter is an analyst-workstation GUI for radare2 — it is registered for inventory/health only and NEVER executes in the DSRclone pipeline." },
  { slug: "radare2", name: "radare2", category: "BINARY", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["BINARY_ANALYSIS", "STATIC_BINARY_ANALYSIS", "DISASSEMBLY", "FUNCTION_INVENTORY", "IMPORT_EXPORT_ANALYSIS", "STRING_ANALYSIS"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Radare2 static binary analysis (Prompt 18 §33/§34): typed analysis profiles ONLY — the command line is composed by the adapter from the approved operation set; unrestricted r2 commands via the API are rejected and never planned." },
  { slug: "gdb", name: "GDB", category: "BINARY", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["BINARY_ANALYSIS", "DYNAMIC_DEBUGGING"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "DISABLED outside LAB registration (Prompt 18 §65/§66): GDB exists in DSRclone only as a governed debug-session descriptor — typed approved operations inside an approved, isolated, kill-switched LAB session. No executing adapter exists in this build; unrestricted GDB/Python is never accepted (§68/§93)." },
  { slug: "pwndbg", name: "pwndbg", category: "BINARY", riskLevel: "RESTRICTED", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["BINARY_ANALYSIS", "DYNAMIC_DEBUGGING"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "APPROVAL_REQUIRED registration (Prompt 18 §65/§66): pwndbg is a governed debug-session descriptor under the same BinaryDebugPolicy as GDB — LAB + authorization + separate approval + isolation + kill switch. No executing adapter exists in this build." },
  { slug: "binary-ninja", name: "Binary Ninja", category: "BINARY", riskLevel: "RESTRICTED", licenseType: "ADMIN_PROVIDED", requiresApproval: true, capabilities: ["BINARY_ANALYSIS", "BINARY_STATIC_ANALYSIS", "DISASSEMBLY", "DECOMPILATION"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Optional commercial connector (Prompt 18 §38/§96): license-aware health (NOT_INSTALLED / INSTALLED / LICENSE_UNAVAILABLE / READY); never bundled, license never bypassed; the baseline open-source pipeline works fully without it." },
  { slug: "ida", name: "IDA", category: "BINARY", riskLevel: "RESTRICTED", licenseType: "ADMIN_PROVIDED", requiresApproval: true, capabilities: ["BINARY_ANALYSIS", "BINARY_STATIC_ANALYSIS", "DISASSEMBLY", "DECOMPILATION"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "Optional commercial connector (Prompt 18 §37/§96): license-aware health (NOT_INSTALLED / INSTALLED / LICENSE_UNAVAILABLE / READY); never bundled, license never bypassed; the baseline open-source pipeline works fully without it. IDAPython from users is never accepted (§93)." },
  { slug: "checksec", name: "checksec", category: "BINARY", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["BINARY_ANALYSIS", "BINARY_HARDENING_ANALYSIS"], supportedTargets: ["BINARY"], requiresCredentials: [], description: "checksec hardening analysis (Prompt 18 §15): NX/PIE/RELRO/canary/FORTIFY properties of a registered binary artifact, parsed from headers — the artifact is input data, never executed." },
  { slug: "aircrack-ng", name: "Aircrack-ng (metadata only)", category: "WIRELESS", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["CAPTURE_METADATA_ANALYSIS", "WIRELESS_CONFIGURATION_ANALYSIS", "OFFLINE_CAPTURE_INSPECTION"], supportedTargets: ["WIRELESS_LAB"], requiresCredentials: [], description: "Aircrack-ng restricted by AircrackPolicy (Prompt 19 §19/§20): capture inspection + metadata extraction ONLY — cracking, key recovery and deauthentication modes are not expressible in any plan." },
  { slug: "kismet", name: "Kismet", category: "WIRELESS", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["PASSIVE_WIFI_DISCOVERY", "ACCESS_POINT_INVENTORY", "STATION_OBSERVATION", "CHANNEL_OBSERVATION", "WIRELESS_SECURITY_METADATA"], supportedTargets: ["WIRELESS_LAB"], requiresCredentials: [], description: "Kismet passive wireless discovery (Prompt 19 §16/§18): listens only — never transmits, associates or probes. Runs on dedicated WIRELESS_PASSIVE_ANALYSIS sensor workers against approved sensors." },
  { slug: "tshark-wireless", name: "tshark (wireless)", category: "WIRELESS", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PCAP_ANALYSIS", "FRAME_ANALYSIS_80211", "WIRELESS_PROTOCOL_METADATA"], supportedTargets: ["WIRELESS_LAB"], requiresCredentials: [], description: "tshark offline 802.11 frame analysis (Prompt 19 §24): a FIXED platform field set over approved captures — arbitrary display filters are not expressible (§78)." },
  { slug: "wifite", name: "Wifite", category: "WIRELESS", riskLevel: "INTRUSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["ACTIVE_WIRELESS_TESTING"], supportedTargets: ["WIRELESS_LAB"], requiresCredentials: [], description: "DISABLED descriptor (Prompt 19 §21/§64): active wireless auditing — no executing adapter exists and baseline profiles can never select it; governed lab architecture only (§65)." },
  { slug: "hcxdumptool", name: "hcxdumptool", category: "WIRELESS", riskLevel: "MODERATE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["ACTIVE_WIRELESS_CAPTURE"], supportedTargets: ["WIRELESS_LAB"], requiresCredentials: [], description: "DISABLED descriptor (Prompt 19 §22/§64): active capture tooling — no executing adapter exists outside explicitly controlled lab workflows; never used against surrounding networks." },
  { slug: "hcxtools", name: "hcxtools (hcxpcapngtool)", category: "WIRELESS", riskLevel: "LOW", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["OFFLINE_CAPTURE_PROCESSING", "CAPTURE_METADATA_EXTRACTION"], supportedTargets: ["WIRELESS_LAB"], requiresCredentials: [], description: "hcxpcapngtool offline capture processing (Prompt 19 §23): approved capture artifacts only; hash-export modes are not expressible and authentication material is counted, never extracted (§67)." },
  { slug: "wireshark", name: "Wireshark", category: "WIRELESS", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: false, capabilities: ["PCAP_ANALYSIS", "FRAME_ANALYSIS_80211"], supportedTargets: ["WIRELESS_LAB"], requiresCredentials: [], description: "ANALYST_TOOL registration (Prompt 19 §25): Wireshark is analyst-workstation GUI tooling — registered for inventory/health only; backend automation uses tshark and Wireshark NEVER executes in the pipeline." },
  { slug: "defectdojo", name: "DefectDojo", category: "REPORTING", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["REPORT_EXPORT"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: ["DEFECTDOJO_API_KEY"], description: "Vulnerability management platform export target." },
  { slug: "faraday", name: "Faraday", category: "REPORTING", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["REPORT_EXPORT"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Collaborative vulnerability management workspace export." },
  { slug: "dradis", name: "Dradis", category: "REPORTING", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["REPORT_EXPORT"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Reporting and collaboration framework export." },
  { slug: "plextrac", name: "PlexTrac", category: "REPORTING", riskLevel: "PASSIVE", licenseType: "ADMIN_PROVIDED", requiresApproval: true, capabilities: ["REPORT_EXPORT"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: ["PLEXTRAC_API"], description: "Commercial reporting platform; admin supplies access." },
  { slug: "serpico", name: "Serpico", category: "REPORTING", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", requiresApproval: true, capabilities: ["REPORT_EXPORT"], supportedTargets: ["WEB_APPLICATION"], requiresCredentials: [], description: "Report generation collaboration tool export." },
];

const MODE: Record<string, "CONTAINER" | "EXTERNAL_API" | "ADMIN_PROVIDED"> = {
  "shodan-cli": "EXTERNAL_API", "censys-cli": "EXTERNAL_API",
  "owasp-zap": "EXTERNAL_API", "caido": "EXTERNAL_API", "sonarqube": "EXTERNAL_API",
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
  // Prompt 16 §30/§31: the OFFENSIVE tool registry. These tools are
  // registered SEPARATELY as metadata only — classification
  // OFFENSIVE_SECURITY_TOOL, default execution DISABLED, manual-only.
  // The registry may track name/version/capabilities/risk/required
  // authorization/required environment, but ordinary scan orchestration
  // must never invoke them: no adapter is implemented for any of them,
  // and both the Tool and its catalog adapter stay disabled.
  const OFFENSIVE_REGISTRY: Array<{ slug: string; requiredAuthorization: string; requiredEnvironment: string }> = [
    { slug: "netexec", requiredAuthorization: "separate external engagement process (§22)", requiredEnvironment: "LAB" },
    { slug: "impacket", requiredAuthorization: "separate external engagement process (§22)", requiredEnvironment: "LAB" },
    { slug: "certipy", requiredAuthorization: "separate external engagement process (§22)", requiredEnvironment: "LAB" },
    { slug: "kerbrute", requiredAuthorization: "separate external engagement process (§22)", requiredEnvironment: "LAB" },
    { slug: "responder", requiredAuthorization: "separate external engagement process (§22)", requiredEnvironment: "LAB" },
    { slug: "powerview", requiredAuthorization: "separate external engagement process (§22)", requiredEnvironment: "LAB" },
    { slug: "metasploit-framework", requiredAuthorization: "separate external engagement process (§22)", requiredEnvironment: "LAB" },
    { slug: "pacu", requiredAuthorization: "separate external engagement process (§22)", requiredEnvironment: "LAB" },
  ];
  for (const offensive of OFFENSIVE_REGISTRY) {
    const tool = await prisma.tool.findUnique({ where: { slug: offensive.slug } });
    if (!tool) continue;
    await prisma.tool.update({ where: { id: tool.id }, data: { enabled: false } });
    await prisma.toolAdapter.updateMany({
      where: { toolId: tool.id },
      data: {
        enabled: false,
        inputSchema: {
          classification: "OFFENSIVE_SECURITY_TOOL",
          execution: "DISABLED",
          manualOnly: true,
          requiredAuthorization: offensive.requiredAuthorization,
          requiredEnvironment: offensive.requiredEnvironment,
          note: "Registry metadata only (Prompt 16 §30/§31) — no adapter exists and scan orchestration must never invoke this tool. Metasploit-class frameworks are never executors in DSRclone.",
        },
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
  // Prompt 10: the network VAPT adapters. All run SCOPE_ONLY; the
  // executor additionally gates masscan (recorded approval), the local
  // discovery pair (LOCAL_LAYER2_ACCESS worker capability) and tcpdump
  // (packet-analysis workers) — enablement here never bypasses a gate.
  const IMPLEMENTED_NETWORK: Array<{ slug: string; outputFormat: string; parser: string; defaultTimeout: number; networkPolicy: string }> = [
    { slug: "nmap", outputFormat: "XML", parser: "nmap-xml", defaultTimeout: 1200, networkPolicy: "SCOPE_ONLY" },
    { slug: "naabu", outputFormat: "JSONL", parser: "naabu-jsonl", defaultTimeout: 600, networkPolicy: "SCOPE_ONLY" },
    { slug: "rustscan", outputFormat: "TEXT", parser: "rustscan-text", defaultTimeout: 600, networkPolicy: "SCOPE_ONLY" },
    { slug: "masscan", outputFormat: "JSON", parser: "masscan-json", defaultTimeout: 600, networkPolicy: "SCOPE_ONLY" },
    { slug: "netdiscover", outputFormat: "TEXT", parser: "netdiscover-text", defaultTimeout: 300, networkPolicy: "SCOPE_ONLY" },
    { slug: "arp-scan", outputFormat: "XML", parser: "arp-scan-xml", defaultTimeout: 300, networkPolicy: "SCOPE_ONLY" },
    { slug: "tcpdump", outputFormat: "TEXT", parser: "tcpdump-capture", defaultTimeout: 300, networkPolicy: "SCOPE_ONLY" },
    { slug: "tshark", outputFormat: "JSON", parser: "tshark-json", defaultTimeout: 600, networkPolicy: "NONE" },
  ];
  for (const impl of IMPLEMENTED_NETWORK) {
    const tool = await prisma.tool.findUnique({ where: { slug: impl.slug } });
    const catalog = TOOLS.find((x) => x.slug === impl.slug);
    if (!tool || !catalog) continue;
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { enabled: true, executionMode: "CONTAINER", outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, inputSchema: { note: "Implemented adapter (Prompt 10) — typed config only, governed NSE/port-profile/budget policy enforced in code by the security-sdk", implementedPhase: 10 } },
      create: { toolId: tool.id, adapterVersion: "1.0.0", enabled: true, executionMode: "CONTAINER", outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, supportedTargets: catalog.supportedTargets, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 10)", implementedPhase: 10 } },
    });
  }
  // Prompt 12: the source code security adapters. All source tools run
  // NO_NETWORK against the isolated snapshot (rule packs and vuln DBs are
  // provisioned on the worker out of band, §13/§50); SonarQube is an
  // EXTERNAL_API connector — unregistered it reports NOT_CONFIGURED.
  const IMPLEMENTED_CODE: Array<{ slug: string; executionMode: "CONTAINER" | "EXTERNAL_API"; outputFormat: string; parser: string; defaultTimeout: number; networkPolicy: string }> = [
    { slug: "semgrep", executionMode: "CONTAINER", outputFormat: "JSON", parser: "semgrep-json", defaultTimeout: 1800, networkPolicy: "NO_NETWORK" },
    { slug: "codeql", executionMode: "CONTAINER", outputFormat: "SARIF", parser: "sarif", defaultTimeout: 3600, networkPolicy: "NO_NETWORK" },
    { slug: "bandit", executionMode: "CONTAINER", outputFormat: "JSON", parser: "bandit-json", defaultTimeout: 900, networkPolicy: "NO_NETWORK" },
    { slug: "brakeman", executionMode: "CONTAINER", outputFormat: "JSON", parser: "brakeman-json", defaultTimeout: 900, networkPolicy: "NO_NETWORK" },
    { slug: "spotbugs", executionMode: "CONTAINER", outputFormat: "XML", parser: "spotbugs-xml", defaultTimeout: 1800, networkPolicy: "NO_NETWORK" },
    { slug: "gitleaks", executionMode: "CONTAINER", outputFormat: "JSON", parser: "gitleaks-json", defaultTimeout: 900, networkPolicy: "NO_NETWORK" },
    { slug: "trufflehog", executionMode: "CONTAINER", outputFormat: "JSONL", parser: "trufflehog-jsonl", defaultTimeout: 900, networkPolicy: "NO_NETWORK" },
    { slug: "owasp-dependency-check", executionMode: "CONTAINER", outputFormat: "JSON", parser: "dependency-check-json", defaultTimeout: 1800, networkPolicy: "NO_NETWORK" },
    { slug: "grype", executionMode: "CONTAINER", outputFormat: "JSON", parser: "grype-json", defaultTimeout: 900, networkPolicy: "NO_NETWORK" },
    { slug: "sonarqube", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "sonarqube-issues", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
  ];
  for (const impl of IMPLEMENTED_CODE) {
    const tool = await prisma.tool.findUnique({ where: { slug: impl.slug } });
    const catalog = TOOLS.find((x) => x.slug === impl.slug);
    if (!tool || !catalog) continue;
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 12) — snapshot path + worker-derived config only; governed rule/query policies enforced in code; source is never executed", implementedPhase: 12 } },
      create: { toolId: tool.id, adapterVersion: "1.0.0", enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, supportedTargets: catalog.supportedTargets, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 12)", implementedPhase: 12 } },
    });
  }
  // Prompt 13: the cloud-native adapters. Image/manifest tools run
  // NO_NETWORK on the isolated CONTAINER_ANALYSIS worker (vuln DBs and
  // rule packs provisioned out of band, §10); Docker Bench / kube-bench
  // are INTERNAL_PRIVILEGED (executor-gated on the PRIVILEGED_HOST
  // worker capability); the Kubernetes connector and Falco are
  // connector-style — unconfigured they report NOT_CONFIGURED (§34/§59).
  const IMPLEMENTED_CLOUD: Array<{ slug: string; executionMode: "CONTAINER" | "EXTERNAL_API"; outputFormat: string; parser: string; defaultTimeout: number; networkPolicy: string }> = [
    { slug: "trivy", executionMode: "CONTAINER", outputFormat: "JSON", parser: "trivy-json", defaultTimeout: 1800, networkPolicy: "NO_NETWORK" },
    { slug: "syft", executionMode: "CONTAINER", outputFormat: "JSON", parser: "syft-json", defaultTimeout: 900, networkPolicy: "NO_NETWORK" },
    { slug: "checkov", executionMode: "CONTAINER", outputFormat: "JSON", parser: "checkov-json", defaultTimeout: 1800, networkPolicy: "NO_NETWORK" },
    { slug: "kubescape", executionMode: "CONTAINER", outputFormat: "JSON", parser: "kubescape-json", defaultTimeout: 1800, networkPolicy: "NO_NETWORK" },
    { slug: "kube-hunter", executionMode: "CONTAINER", outputFormat: "JSON", parser: "kube-hunter-json", defaultTimeout: 900, networkPolicy: "NO_NETWORK" },
    { slug: "docker-bench-for-security", executionMode: "CONTAINER", outputFormat: "JSON", parser: "docker-bench-json", defaultTimeout: 900, networkPolicy: "NO_NETWORK" },
    { slug: "kube-bench", executionMode: "CONTAINER", outputFormat: "JSON", parser: "kube-bench-json", defaultTimeout: 900, networkPolicy: "NO_NETWORK" },
    { slug: "kubernetes-connector", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "kubernetes-inventory", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "falco", executionMode: "EXTERNAL_API", outputFormat: "JSONL", parser: "falco-events", defaultTimeout: 300, networkPolicy: "CUSTOM_ALLOWLIST" },
  ];
  for (const impl of IMPLEMENTED_CLOUD) {
    const tool = await prisma.tool.findUnique({ where: { slug: impl.slug } });
    const catalog = TOOLS.find((x) => x.slug === impl.slug);
    if (!tool || !catalog) continue;
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 13) — static analysis only; images are never executed; credentials are secret references only", implementedPhase: 13 } },
      create: { toolId: tool.id, adapterVersion: "1.0.0", enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, supportedTargets: catalog.supportedTargets, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 13)", implementedPhase: 13 } },
    });
  }
  // Prompt 14: the multi-cloud security adapters. Provider inventory
  // connectors + import connectors are EXTERNAL_API (per-account
  // configuration; unconfigured they report NOT_CONFIGURED, §9); the
  // CSPM CLIs run on the isolated CLOUD_ANALYSIS worker with egress
  // limited to provider APIs (CUSTOM_ALLOWLIST). Pacu is deliberately
  // ABSENT: it stays a disabled catalog row with no adapter (§34).
  const IMPLEMENTED_CLOUD_SEC: Array<{ slug: string; executionMode: "CONTAINER" | "EXTERNAL_API"; outputFormat: string; parser: string; defaultTimeout: number; networkPolicy: string }> = [
    { slug: "aws-inventory", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "aws-inventory", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "azure-inventory", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "azure-inventory", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "gcp-inventory", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "gcp-inventory", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "prowler", executionMode: "CONTAINER", outputFormat: "JSON", parser: "prowler-json", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "scoutsuite", executionMode: "CONTAINER", outputFormat: "JSON", parser: "scoutsuite-json", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "steampipe", executionMode: "CONTAINER", outputFormat: "JSON", parser: "steampipe-json", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "cloudmapper", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "cloudmapper-import", defaultTimeout: 900, networkPolicy: "NO_NETWORK" },
    { slug: "roadtools", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "roadtools-import", defaultTimeout: 900, networkPolicy: "NO_NETWORK" },
  ];
  for (const impl of IMPLEMENTED_CLOUD_SEC) {
    const tool = await prisma.tool.findUnique({ where: { slug: impl.slug } });
    const catalog = TOOLS.find((x) => x.slug === impl.slug);
    if (!tool || !catalog) continue;
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 14) — read-only assessment only; credentials are secret references resolved inside the CLOUD_ANALYSIS worker; no remediation actions exist", implementedPhase: 14 } },
      create: { toolId: tool.id, adapterVersion: "1.0.0", enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, supportedTargets: catalog.supportedTargets, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 14)", implementedPhase: 14 } },
    });
  }
  // Prompt 15: the Active Directory adapters. Connectors are
  // EXTERNAL_API (per-domain configuration on the DIRECTORY_ANALYSIS
  // worker; unconfigured they report NOT_CONFIGURED, §15); the
  // governed CLI adapters run against APPROVED domain controllers
  // only (CUSTOM_ALLOWLIST). The offensive registrations (netexec,
  // impacket, kerbrute, responder, powerview, certipy-offensive) are
  // deliberately ABSENT: they stay disabled catalog rows with no
  // adapter (§51–§56/§120), exactly like Pacu in Prompt 14.
  const IMPLEMENTED_DIRECTORY: Array<{ slug: string; executionMode: "CONTAINER" | "EXTERNAL_API"; outputFormat: string; parser: string; defaultTimeout: number; networkPolicy: string }> = [
    { slug: "ldap-directory-connector", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "directory-inventory", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "bloodhound-connector", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "bloodhound-import", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "ldapsearch", executionMode: "CONTAINER", outputFormat: "LDIF", parser: "ldapsearch-ldif", defaultTimeout: 900, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "sharphound", executionMode: "CONTAINER", outputFormat: "JSON", parser: "bloodhound-import", defaultTimeout: 3600, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "pingcastle", executionMode: "CONTAINER", outputFormat: "XML", parser: "pingcastle-xml", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "enum4linux-ng", executionMode: "CONTAINER", outputFormat: "JSON", parser: "enum4linux-ng-json", defaultTimeout: 900, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "smbmap", executionMode: "CONTAINER", outputFormat: "JSON", parser: "smbmap", defaultTimeout: 900, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "certipy-posture", executionMode: "CONTAINER", outputFormat: "JSON", parser: "certipy-find", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
  ];
  for (const impl of IMPLEMENTED_DIRECTORY) {
    const tool = await prisma.tool.findUnique({ where: { slug: impl.slug } });
    const catalog = TOOLS.find((x) => x.slug === impl.slug);
    if (!tool || !catalog) continue;
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 15) — defensive read-only assessment only; credentials are secret references resolved inside the DIRECTORY_ANALYSIS worker; offensive actions are refused at plan time", implementedPhase: 15 } },
      create: { toolId: tool.id, adapterVersion: "1.0.0", enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, supportedTargets: catalog.supportedTargets, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 15)", implementedPhase: 15 } },
    });
  }
  // Prompt 17: the mobile security adapters. JADX / apktool / Ghidra
  // are CONTAINER adapters on MOBILE_STATIC_ANALYSIS workers with
  // NO_NETWORK (app artifacts are hostile content — static sandbox,
  // never executed, §8); the MobSF connector and the lab adapters
  // (ADB / mitmproxy mobile sessions) are EXTERNAL_API — the MobSF
  // instance resolves per workspace (§14) and lab sessions per
  // approved dynamic session (§58); unconfigured they report
  // NOT_CONFIGURED. Frida / Objection are deliberately ABSENT: they
  // stay DISABLED / APPROVAL_REQUIRED catalog registrations with no
  // adapter (§69–§74), exactly like Pacu in Prompt 14.
  const IMPLEMENTED_MOBILE: Array<{ slug: string; executionMode: "CONTAINER" | "EXTERNAL_API"; outputFormat: string; parser: string; defaultTimeout: number; networkPolicy: string }> = [
    { slug: "mobsf", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "mobsf-report", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "jadx", executionMode: "CONTAINER", outputFormat: "JSON", parser: "jadx-output", defaultTimeout: 1800, networkPolicy: "NO_NETWORK" },
    { slug: "apktool", executionMode: "CONTAINER", outputFormat: "JSON", parser: "apktool-output", defaultTimeout: 1200, networkPolicy: "NO_NETWORK" },
    { slug: "ghidra", executionMode: "CONTAINER", outputFormat: "JSON", parser: "ghidra-report", defaultTimeout: 1800, networkPolicy: "NO_NETWORK" },
    { slug: "adb", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "adb-lab-session", defaultTimeout: 1800, networkPolicy: "CUSTOM_ALLOWLIST" },
    { slug: "mitmproxy", executionMode: "EXTERNAL_API", outputFormat: "JSON", parser: "mitmproxy-flows", defaultTimeout: 1200, networkPolicy: "CUSTOM_ALLOWLIST" },
  ];
  for (const impl of IMPLEMENTED_MOBILE) {
    const tool = await prisma.tool.findUnique({ where: { slug: impl.slug } });
    const catalog = TOOLS.find((x) => x.slug === impl.slug);
    if (!tool || !catalog) continue;
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 17) — static analysis in the sandbox; app code is never executed; dynamic adapters run only in the controlled device lab with an approved session; credentials are secret references only", implementedPhase: 17 } },
      create: { toolId: tool.id, adapterVersion: "1.0.0", enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, supportedTargets: catalog.supportedTargets, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 17)", implementedPhase: 17 } },
    });
  }
  // Prompt 18: the implemented binary adapters (§10/§95). checksec
  // and radare2 are CONTAINER static analyzers over registered
  // artifacts (parsed, NEVER executed, NO_NETWORK); ghidra's config
  // was registered with the mobile family above (parser
  // "ghidra-report" serves both modes). Cutter (ANALYST_TOOL), GDB
  // (DISABLED outside LAB), pwndbg (APPROVAL_REQUIRED) and the
  // commercial IDA / Binary Ninja connectors are deliberately
  // ABSENT: they stay governed catalog registrations with no
  // executing adapter (§35–§39/§65/§66/§96), exactly like Frida.
  const IMPLEMENTED_BINARY: Array<{ slug: string; executionMode: "CONTAINER" | "EXTERNAL_API"; outputFormat: string; parser: string; defaultTimeout: number; networkPolicy: string }> = [
    { slug: "checksec", executionMode: "CONTAINER", outputFormat: "JSON", parser: "checksec-report", defaultTimeout: 600, networkPolicy: "NO_NETWORK" },
    { slug: "radare2", executionMode: "CONTAINER", outputFormat: "JSON", parser: "radare2-report", defaultTimeout: 1200, networkPolicy: "NO_NETWORK" },
  ];
  for (const impl of IMPLEMENTED_BINARY) {
    const tool = await prisma.tool.findUnique({ where: { slug: impl.slug } });
    const catalog = TOOLS.find((x) => x.slug === impl.slug);
    if (!tool || !catalog) continue;
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 18) — static analysis of registered artifacts in the sandbox; artifacts are never executed; radare2 runs typed approved profiles only", implementedPhase: 18 } },
      create: { toolId: tool.id, adapterVersion: "1.0.0", enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, supportedTargets: catalog.supportedTargets, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 18)", implementedPhase: 18 } },
    });
  }
  // Prompt 19: the implemented wireless adapters (§15/§80). Kismet
  // is a PASSIVE sensor-side collector (dedicated
  // WIRELESS_PASSIVE_ANALYSIS workers, approved sensors only); the
  // other three are OFFLINE capture analyzers over APPROVED capture
  // artifacts (NO_NETWORK). Wifite and hcxdumptool are deliberately
  // ABSENT: they stay DISABLED catalog descriptors with no executing
  // adapter (§21/§22/§64), and Wireshark is an ANALYST_TOOL (§25) —
  // exactly like Frida/Cutter above.
  const IMPLEMENTED_WIRELESS: Array<{ slug: string; executionMode: "CONTAINER" | "EXTERNAL_API"; outputFormat: string; parser: string; defaultTimeout: number; networkPolicy: string }> = [
    { slug: "kismet", executionMode: "CONTAINER", outputFormat: "JSON", parser: "kismet-devices", defaultTimeout: 900, networkPolicy: "NO_NETWORK" },
    { slug: "tshark-wireless", executionMode: "CONTAINER", outputFormat: "TEXT", parser: "tshark-wireless-fields", defaultTimeout: 900, networkPolicy: "NO_NETWORK" },
    { slug: "hcxtools", executionMode: "CONTAINER", outputFormat: "TEXT", parser: "hcxpcapngtool-summary", defaultTimeout: 600, networkPolicy: "NO_NETWORK" },
    { slug: "aircrack-ng", executionMode: "CONTAINER", outputFormat: "TEXT", parser: "aircrack-capture-info", defaultTimeout: 600, networkPolicy: "NO_NETWORK" },
  ];
  for (const impl of IMPLEMENTED_WIRELESS) {
    const tool = await prisma.tool.findUnique({ where: { slug: impl.slug } });
    const catalog = TOOLS.find((x) => x.slug === impl.slug);
    if (!tool || !catalog) continue;
    await prisma.toolAdapter.upsert({
      where: { toolId_adapterVersion: { toolId: tool.id, adapterVersion: "1.0.0" } },
      update: { enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 19) — passive collection on approved sensors / offline analysis of approved captures only; nothing transmits; no cracking, deauth or active modes are expressible", implementedPhase: 19 } },
      create: { toolId: tool.id, adapterVersion: "1.0.0", enabled: true, executionMode: impl.executionMode, outputFormat: impl.outputFormat, parser: impl.parser, defaultTimeout: impl.defaultTimeout, networkPolicy: impl.networkPolicy, supportedTargets: catalog.supportedTargets, capabilities: catalog.capabilities, inputSchema: { note: "Implemented adapter (Prompt 19)", implementedPhase: 19 } },
    });
  }
  // Prompt 13 §55: the compliance framework catalog. Control titles are
  // the governed checks' own descriptions (posture engine + benchmark
  // tools) — posture evidence catalog, NEVER a certification (§88).
  const COMPLIANCE_CATALOG: Array<{ key: string; name: string; version: string; controls: Array<{ controlId: string; title: string; severityDefault: string }> }> = [
    {
      key: "CIS_DOCKER", name: "CIS Docker Benchmark", version: "1.6",
      controls: [
        { controlId: "1.1.1", title: "Host configuration check 1.1.1 (Docker Bench)", severityDefault: "MEDIUM" },
        { controlId: "2.8", title: "Container configuration check 2.8 (Docker Bench)", severityDefault: "LOW" },
        { controlId: "4.1", title: "Image user should not be root (Docker Bench 4.1)", severityDefault: "HIGH" },
      ],
    },
    {
      key: "CIS_KUBERNETES", name: "CIS Kubernetes Benchmark", version: "1.8",
      controls: [
        { controlId: "1.1.1", title: "Control plane configuration check 1.1.1 (kube-bench)", severityDefault: "MEDIUM" },
        { controlId: "1.1.12", title: "Control plane configuration check 1.1.12 (kube-bench)", severityDefault: "HIGH" },
        { controlId: "CIS-5.1.1", title: "Cluster-admin / wildcard RBAC binding", severityDefault: "CRITICAL" },
        { controlId: "CIS-5.2.2", title: "Host network namespace shared", severityDefault: "HIGH" },
        { controlId: "CIS-5.2.3", title: "Host PID namespace shared", severityDefault: "HIGH" },
        { controlId: "CIS-5.2.5", title: "Dangerous Linux capabilities added", severityDefault: "HIGH" },
        { controlId: "CIS-5.2.6", title: "Container may run as root", severityDefault: "HIGH" },
        { controlId: "CIS-5.2.9", title: "Host filesystem (hostPath) volume mounted", severityDefault: "HIGH" },
        { controlId: "CIS-5.3.2", title: "NetworkPolicy coverage for exposed workloads", severityDefault: "MEDIUM" },
        { controlId: "CIS-5.4.1", title: "Resource limits not declared", severityDefault: "LOW" },
        { controlId: "CIS-5.4.5", title: "Default service account in use", severityDefault: "MEDIUM" },
        { controlId: "CIS-5.7.3", title: "Service account token automount not disabled", severityDefault: "MEDIUM" },
      ],
    },
    {
      key: "NSA_CISA_KUBERNETES", name: "NSA/CISA Kubernetes Hardening Guidance", version: "1.2",
      controls: [
        { controlId: "KSV-0012", title: "Writable root filesystem", severityDefault: "MEDIUM" },
        { controlId: "KSV-0013", title: "Image pull policy allows mutable tags (Always / latest)", severityDefault: "MEDIUM" },
        { controlId: "KSV-0014", title: "Privileged container", severityDefault: "CRITICAL" },
        { controlId: "KSV-0015", title: "Image not pinned by digest", severityDefault: "MEDIUM" },
        { controlId: "C-0057", title: "Privileged container (Kubescape control)", severityDefault: "CRITICAL" },
      ],
    },
    // Prompt 14 §68/§69: CIS cloud foundations — control ids are exactly
    // the analyzer's governed rule→control mapping; framework mappings
    // to NIST/PCI DSS/SOC 2/ISO 27001 are mapping-only, never a
    // certification claim (§84).
    {
      key: "CIS_AWS", name: "CIS Amazon Web Services Foundations Benchmark", version: "1.5.0",
      controls: [
        { controlId: "1.10", title: "MFA enabled for IAM users (mfa-not-enabled)", severityDefault: "MEDIUM" },
        { controlId: "1.16", title: "No admin-equivalent IAM policies attached (iam-admin-equivalent)", severityDefault: "CRITICAL" },
        { controlId: "2.1.1", title: "S3 bucket encryption with SSE (storage-encryption)", severityDefault: "MEDIUM" },
        { controlId: "2.1.2", title: "S3 Block Public Access enabled (storage-public-access)", severityDefault: "HIGH" },
        { controlId: "2.1.3", title: "S3 bucket access logging enabled (storage-logging)", severityDefault: "LOW" },
        { controlId: "2.2.1", title: "RDS instance encryption enabled (database-encryption)", severityDefault: "HIGH" },
        { controlId: "2.2.2", title: "RDS instance not publicly accessible (database-public-access)", severityDefault: "HIGH" },
        { controlId: "3.1", title: "CloudTrail enabled in all regions (audit-logging-disabled)", severityDefault: "HIGH" },
        { controlId: "3.8", title: "KMS key rotation enabled (kms-rotation-disabled)", severityDefault: "MEDIUM" },
        { controlId: "5.2", title: "No security group allows ingress from 0.0.0.0/0 to remote server administration ports (firewall-sensitive-port-world)", severityDefault: "HIGH" },
      ],
    },
    {
      key: "CIS_AZURE", name: "CIS Microsoft Azure Foundations Benchmark", version: "2.1.0",
      controls: [
        { controlId: "1.1", title: "MFA enabled for Entra ID users (mfa-not-enabled)", severityDefault: "MEDIUM" },
        { controlId: "1.23", title: "No subscription owner-equivalent role assignments beyond need (iam-admin-equivalent)", severityDefault: "CRITICAL" },
        { controlId: "3.1", title: "Storage account encryption with customer-managed keys where required (storage-encryption)", severityDefault: "MEDIUM" },
        { controlId: "3.6", title: "Public network access to storage accounts restricted (storage-public-access)", severityDefault: "HIGH" },
        { controlId: "4.1", title: "Azure SQL transparent data encryption enabled (database-encryption)", severityDefault: "HIGH" },
        { controlId: "5.1.2", title: "Activity log export / diagnostic settings configured (audit-logging-disabled)", severityDefault: "HIGH" },
        { controlId: "6.1", title: "No NSG allows ingress from the internet to remote administration ports (firewall-sensitive-port-world)", severityDefault: "HIGH" },
      ],
    },
    {
      key: "MS_AD_BASELINE", name: "Microsoft Active Directory Security Baseline (DSRclone governed checks)", version: "1.0.0",
      controls: [
        { controlId: "MS-AD-1.1", title: "Privileged group effective membership stays within the governed threshold (AD_PRIVILEGED_GROUP_EXCESS)", severityDefault: "HIGH" },
        { controlId: "MS-AD-1.2", title: "No unexpected nested groups inside privileged groups (AD_NESTED_PRIVILEGED_GROUP)", severityDefault: "MEDIUM" },
        { controlId: "MS-AD-1.3", title: "No dangerous ACL grants (GenericAll/WriteDacl/WriteOwner) for non-administrative principals (AD_DANGEROUS_ACL)", severityDefault: "CRITICAL" },
        { controlId: "MS-AD-2.1", title: "No unconstrained delegation outside domain controllers (AD_UNCONSTRAINED_DELEGATION)", severityDefault: "HIGH" },
        { controlId: "MS-AD-2.2", title: "Constrained delegation targets reviewed (AD_CONSTRAINED_DELEGATION_REVIEW)", severityDefault: "MEDIUM" },
        { controlId: "MS-AD-3.1", title: "Kerberos pre-authentication required for all accounts (AD_PREAUTH_NOT_REQUIRED)", severityDefault: "HIGH" },
        { controlId: "MS-AD-3.2", title: "Passwords expire for privileged and service accounts (AD_PASSWORD_NEVER_EXPIRES)", severityDefault: "MEDIUM" },
        { controlId: "MS-AD-3.3", title: "No account is flagged password-not-required (AD_PASSWORD_NOT_REQUIRED)", severityDefault: "HIGH" },
        { controlId: "MS-AD-3.4", title: "Enabled accounts authenticate within the organizational staleness policy (AD_STALE_ENABLED_ACCOUNT)", severityDefault: "MEDIUM" },
        { controlId: "MS-AD-3.5", title: "Disabled accounts hold no effective privilege (AD_DISABLED_PRIVILEGED_ACCOUNT)", severityDefault: "MEDIUM" },
        { controlId: "MS-AD-3.6", title: "Domain password policy meets baseline length and lockout (AD_PASSWORD_POLICY_WEAK)", severityDefault: "MEDIUM" },
        { controlId: "MS-AD-3.7", title: "KRBTGT password rotated within the governed period (AD_KRBTGT_OLD)", severityDefault: "HIGH" },
        { controlId: "MS-AD-3.8", title: "Service accounts with SPNs carry no compounding risk factors (AD_SPN_SERVICE_ACCOUNT)", severityDefault: "MEDIUM" },
        { controlId: "MS-AD-4.1", title: "LDAP signing required on domain controllers (AD_LDAP_SIGNING_NOT_REQUIRED)", severityDefault: "HIGH" },
        { controlId: "MS-AD-4.2", title: "LDAP channel binding enforced or required-when-supported (AD_LDAP_CHANNEL_BINDING_WEAK)", severityDefault: "MEDIUM" },
        { controlId: "MS-AD-4.3", title: "SMB1 disabled on domain controllers (AD_SMB1_ENABLED)", severityDefault: "HIGH" },
        { controlId: "MS-AD-4.4", title: "SMB signing required (AD_SMB_SIGNING_NOT_REQUIRED)", severityDefault: "MEDIUM" },
        { controlId: "MS-AD-4.5", title: "No anonymously accessible SMB shares (AD_SMB_ANONYMOUS_SHARE)", severityDefault: "HIGH" },
        { controlId: "MS-AD-4.6", title: "Writable SMB shares reviewed (AD_SMB_WRITABLE_SHARE)", severityDefault: "MEDIUM" },
        { controlId: "MS-AD-5.1", title: "External/forest trusts reviewed — SID filtering and selective authentication (AD_TRUST_REVIEW)", severityDefault: "MEDIUM" },
        { controlId: "MS-AD-5.2", title: "Domain controller exposed services reviewed (AD_DC_SERVICE_EXPOSURE)", severityDefault: "LOW" },
        { controlId: "MS-AD-6.1", title: "No certificate template carries an ESC-class risk configuration (ADCS_TEMPLATE_RISK)", severityDefault: "CRITICAL" },
        { controlId: "MS-AD-6.2", title: "Certificate authority configuration hardened (ADCS_CA_CONFIGURATION)", severityDefault: "HIGH" },
      ],
    },
    {
      key: "CIS_GCP", name: "CIS Google Cloud Platform Foundation Benchmark", version: "1.6.0",
      controls: [
        { controlId: "1.1", title: "MFA enabled for user accounts (mfa-not-enabled)", severityDefault: "MEDIUM" },
        { controlId: "1.5", title: "No owner-equivalent IAM roles beyond need (iam-admin-equivalent)", severityDefault: "CRITICAL" },
        { controlId: "1.9", title: "KMS key rotation within the governed period (kms-rotation-disabled)", severityDefault: "MEDIUM" },
        { controlId: "2.1", title: "Cloud Audit Logs enabled (audit-logging-disabled)", severityDefault: "HIGH" },
        { controlId: "3.6", title: "No firewall rule allows ingress from 0.0.0.0/0 to administration ports (firewall-sensitive-port-world)", severityDefault: "HIGH" },
        { controlId: "4.1", title: "Cloud Storage buckets not publicly accessible (storage-public-access)", severityDefault: "HIGH" },
        { controlId: "4.2", title: "Cloud Storage bucket access logging enabled (storage-logging)", severityDefault: "LOW" },
        { controlId: "4.3", title: "Cloud Storage encryption with customer-managed keys where required (storage-encryption)", severityDefault: "MEDIUM" },
      ],
    },
    {
      key: "OWASP_MASVS", name: "OWASP MASVS (Mobile Application Security Verification Standard)", version: "2.1",
      controls: [
        { controlId: "MASVS-STORAGE-1", title: "Sensitive data storage reviewed (MOBILE_WORLD_READABLE_STORAGE)", severityDefault: "HIGH" },
        { controlId: "MASVS-STORAGE-2", title: "Sensitive data leakage via logs/backups reviewed (MOBILE_SENSITIVE_DATA_LOGGING / MOBILE_BACKUP_ALLOWED)", severityDefault: "MEDIUM" },
        { controlId: "MASVS-CRYPTO-1", title: "Weak cryptography usage reviewed (MOBILE_WEAK_CRYPTOGRAPHY)", severityDefault: "HIGH" },
        { controlId: "MASVS-CRYPTO-2", title: "Insecure randomness reviewed (MOBILE_INSECURE_RANDOM)", severityDefault: "MEDIUM" },
        { controlId: "MASVS-NETWORK-1", title: "Cleartext traffic configuration reviewed (MOBILE_CLEARTEXT_ENABLED / MOBILE_ATS_ARBITRARY_LOADS)", severityDefault: "HIGH" },
        { controlId: "MASVS-NETWORK-2", title: "Certificate pinning evidence reviewed — presence is an observation, never a bypass target (MOBILE_PINNING_ABSENT_OBSERVED_CLEARTEXT)", severityDefault: "MEDIUM" },
        { controlId: "MASVS-PLATFORM-1", title: "WebView bridge/file-access surface reviewed (MOBILE_WEBVIEW_JS_BRIDGE / MOBILE_WEBVIEW_FILE_ACCESS)", severityDefault: "MEDIUM" },
        { controlId: "MASVS-PLATFORM-2", title: "Exported component protection reviewed (MOBILE_EXPORTED_COMPONENT_UNPROTECTED)", severityDefault: "HIGH" },
        { controlId: "MASVS-CODE-1", title: "Debuggable production build reviewed (MOBILE_DEBUGGABLE_BUILD)", severityDefault: "HIGH" },
        { controlId: "MASVS-CODE-2", title: "Hardcoded secrets reviewed — metadata/fingerprint only (MOBILE_HARDCODED_SECRET)", severityDefault: "HIGH" },
        { controlId: "MASVS-RESILIENCE-1", title: "Native binary hardening — PIE (MOBILE_BINARY_NO_PIE)", severityDefault: "MEDIUM" },
        { controlId: "MASVS-RESILIENCE-2", title: "Native binary hardening — NX/canary/RELRO (MOBILE_BINARY_NO_NX / MOBILE_BINARY_NO_CANARY / MOBILE_BINARY_NO_RELRO)", severityDefault: "MEDIUM" },
        { controlId: "MASVS-RESILIENCE-3", title: "Debug symbols in release binaries reviewed (MOBILE_BINARY_DEBUG_SYMBOLS)", severityDefault: "LOW" },
      ],
    },
  ];
  for (const fw of COMPLIANCE_CATALOG) {
    // The catalog rows carry severityDefault as seed-local metadata;
    // the schema stores it in the control's description (no dedicated
    // column) and requires a framework description.
    const frameworkDescription = `${fw.name} ${fw.version} — governed posture-evidence catalog; assessments are evidence, never a certification.`;
    const framework = await prisma.complianceFramework.upsert({
      where: { key: fw.key },
      update: { name: fw.name, version: fw.version, description: frameworkDescription },
      create: { key: fw.key, name: fw.name, version: fw.version, description: frameworkDescription },
    });
    for (const c of fw.controls) {
      await prisma.complianceControl.upsert({
        where: { frameworkId_controlId: { frameworkId: framework.id, controlId: c.controlId } },
        update: { title: c.title, description: `Default severity: ${c.severityDefault}` },
        create: { frameworkId: framework.id, controlId: c.controlId, title: c.title, description: `Default severity: ${c.severityDefault}` },
      });
    }
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
