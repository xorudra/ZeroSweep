import type { ControlMappingData, MappingConfidence, SecurityControlData } from "./types";

/**
 * Internal normalized control library (Prompt 26 §7). A ZeroSweep
 * control states what the PLATFORM can evidence. Technical controls
 * carry the signal keys they are evaluated from; administrative
 * controls have no automated test (§18 — automation NONE) and can
 * only be supported by manual evidence and human review (§38).
 */
export const CONTROL_LIBRARY: SecurityControlData[] = [
  { code: "MFA-ENFORCEMENT", title: "Multi-factor authentication enforced for user accounts", description: "All interactive user accounts are required to complete a second authentication factor.", controlType: "PREVENTIVE", implementationType: "TECHNICAL", signals: ["identity.mfa_enforced"], evidenceSources: ["MFA_CONFIGURATION", "IDENTITY_POSTURE"], testName: "MFA enforcement configuration check", testMethod: "AUTOMATED", automationLevel: "FULL", testFrequency: "CONTINUOUS", expectedResult: "Identity configuration reports MFA required for all users" },
  { code: "MFA-PHISHING-RESISTANT-ADMIN", title: "Phishing-resistant MFA for privileged accounts", description: "Administrators authenticate with WebAuthn/passkey-class factors.", controlType: "PREVENTIVE", implementationType: "TECHNICAL", signals: ["identity.admin_phishing_resistant_mfa"], evidenceSources: ["MFA_CONFIGURATION", "IDENTITY_POSTURE"], testName: "Privileged-account factor review", testMethod: "AUTOMATED", automationLevel: "PARTIAL", testFrequency: "CONTINUOUS", expectedResult: "Every privileged account has a phishing-resistant factor enrolled" },
  { code: "SSO-CONFIGURATION", title: "Centralized SSO configured and enforced", description: "Authentication is federated through the organization IdP where SSO is configured.", controlType: "PREVENTIVE", implementationType: "TECHNICAL", signals: ["identity.sso_configured"], evidenceSources: ["SSO_CONFIGURATION"], testName: "SSO configuration check", testMethod: "AUTOMATED", automationLevel: "FULL", testFrequency: "CONTINUOUS", expectedResult: "SSO provider configured and login enforcement enabled" },
  { code: "ACCESS-REVIEW", title: "Periodic access reviews performed", description: "Workspace membership and privileged access are reviewed on a defined cadence; revocations execute.", controlType: "DETECTIVE", implementationType: "HYBRID", signals: ["identity.access_review_current"], evidenceSources: ["ACCESS_REVIEW", "AUDIT_EVENT"], testName: "Access review currency check", testMethod: "HYBRID", automationLevel: "PARTIAL", testFrequency: "QUARTERLY", expectedResult: "Most recent access review completed within the review period" },
  { code: "PRIVILEGED-ACCESS-MGMT", title: "Privileged access is restricted and managed", description: "Privileged roles are limited, dedicated and monitored; dormant privileged accounts are disabled.", controlType: "PREVENTIVE", implementationType: "HYBRID", signals: ["identity.privileged_accounts_managed"], evidenceSources: ["IDENTITY_POSTURE", "ACCESS_REVIEW"], testName: "Privileged account posture check", testMethod: "HYBRID", automationLevel: "PARTIAL", testFrequency: "CONTINUOUS", expectedResult: "No unmanaged or dormant privileged accounts detected" },
  { code: "PASSWORD-POLICY", title: "Password policy enforced", description: "Local password policy meets the organization baseline (length, breach screening, lockout).", controlType: "PREVENTIVE", implementationType: "TECHNICAL", signals: ["identity.password_policy_compliant"], evidenceSources: ["IDENTITY_POSTURE"], testName: "Password policy check", testMethod: "AUTOMATED", automationLevel: "FULL", testFrequency: "CONTINUOUS", expectedResult: "Configured password policy satisfies the organization baseline" },
  { code: "VULN-SCAN-COVERAGE", title: "Vulnerability scanning covers in-scope assets", description: "Verified in-scope assets are scanned on the defined cadence across web, network, API, cloud and code surfaces.", controlType: "DETECTIVE", implementationType: "TECHNICAL", signals: ["vuln.scan_coverage"], evidenceSources: ["CONTINUOUS_SNAPSHOT", "ASSET_INVENTORY"], testName: "Scan coverage evaluation", testMethod: "AUTOMATED", automationLevel: "FULL", testFrequency: "CONTINUOUS", expectedResult: "Posture snapshot reports scan coverage for all in-scope asset classes" },
  { code: "VULN-REMEDIATION-SLA", title: "Vulnerabilities remediated within SLA", description: "Findings are triaged and remediated within severity-based SLA windows; breaches are visible.", controlType: "CORRECTIVE", implementationType: "HYBRID", signals: ["vuln.sla_compliance"], evidenceSources: ["CONTINUOUS_SNAPSHOT", "AUDIT_EVENT"], testName: "SLA compliance evaluation", testMethod: "AUTOMATED", automationLevel: "PARTIAL", testFrequency: "CONTINUOUS", expectedResult: "No unexcepted SLA breach on confirmed findings" },
  { code: "PATCH-MANAGEMENT", title: "Security patches applied within policy windows", description: "Known exploited and critical vulnerabilities in components are patched within defined windows.", controlType: "CORRECTIVE", implementationType: "HYBRID", signals: ["vuln.kev_open"], evidenceSources: ["SCA", "WEB_FINDING", "NETWORK_FINDING"], testName: "Known-exploited vulnerability check", testMethod: "AUTOMATED", automationLevel: "PARTIAL", testFrequency: "CONTINUOUS", expectedResult: "No open finding matches a known-exploited vulnerability past its window" },
  { code: "ENCRYPTION-AT-REST", title: "Sensitive data encrypted at rest", description: "Storage resources holding sensitive data have encryption at rest enabled.", controlType: "PREVENTIVE", implementationType: "TECHNICAL", signals: ["cloud.encryption_at_rest"], evidenceSources: ["CLOUD_FINDING"], testName: "Cloud encryption-at-rest posture check", testMethod: "AUTOMATED", automationLevel: "FULL", testFrequency: "CONTINUOUS", expectedResult: "No cloud finding reports unencrypted sensitive storage" },
  { code: "ENCRYPTION-IN-TRANSIT", title: "Data encrypted in transit (TLS)", description: "Services enforce modern TLS; cleartext services and weak TLS configurations are findings.", controlType: "PREVENTIVE", implementationType: "TECHNICAL", signals: ["crypto.tls_findings"], evidenceSources: ["WEB_FINDING", "NETWORK_FINDING"], testName: "TLS posture check", testMethod: "AUTOMATED", automationLevel: "FULL", testFrequency: "CONTINUOUS", expectedResult: "No open finding reports cleartext transport or broken TLS" },
  { code: "PUBLIC-EXPOSURE-PREVENTION", title: "Public exposure of sensitive resources prevented", description: "Storage, databases and management interfaces are not publicly exposed without approval.", controlType: "PREVENTIVE", implementationType: "TECHNICAL", signals: ["cloud.public_exposure"], evidenceSources: ["CLOUD_FINDING", "NETWORK_FINDING"], testName: "Public exposure posture check", testMethod: "AUTOMATED", automationLevel: "FULL", testFrequency: "CONTINUOUS", expectedResult: "No open finding reports public exposure of a sensitive resource" },
  { code: "LOGGING-MONITORING", title: "Security logging and monitoring active", description: "Audit logging is enabled, retained and reviewed; monitoring detects anomalous activity.", controlType: "DETECTIVE", implementationType: "TECHNICAL", signals: ["platform.audit_logging_active", "cloud.logging_enabled"], evidenceSources: ["AUDIT_EVENT", "CLOUD_FINDING", "CONTINUOUS_SNAPSHOT"], testName: "Logging posture check", testMethod: "AUTOMATED", automationLevel: "PARTIAL", testFrequency: "CONTINUOUS", expectedResult: "Audit events are being recorded and no mapped resource reports logging disabled" },
  { code: "BACKUP-VERIFICATION", title: "Backups taken and restore-verified", description: "Backups run on schedule and restore verification succeeds within the freshness window.", controlType: "DETECTIVE", implementationType: "TECHNICAL", signals: ["platform.backup_verified"], evidenceSources: ["BACKUP_VERIFICATION"], testName: "Backup verification check", testMethod: "AUTOMATED", automationLevel: "FULL", testFrequency: "DAILY", expectedResult: "Latest backup verification record is successful and current" },
  { code: "DR-TESTING", title: "Disaster recovery tested", description: "DR failover/restore tests are executed and recorded on the defined cadence.", controlType: "CORRECTIVE", implementationType: "HYBRID", signals: ["platform.dr_test_current"], evidenceSources: ["DR_TEST"], testName: "DR test currency check", testMethod: "HYBRID", automationLevel: "PARTIAL", testFrequency: "ANNUAL", expectedResult: "A DR test record exists within the test period" },
  { code: "SECURE-SDLC-GATES", title: "Secure development lifecycle gates enforced in CI", description: "SAST, SCA and secret-scanning gates run on changes; failing gates block per policy.", controlType: "PREVENTIVE", implementationType: "TECHNICAL", signals: ["devsecops.gates_enforced"], evidenceSources: ["DEVSECOPS_GATE", "SAST", "SCA"], testName: "DevSecOps gate posture check", testMethod: "AUTOMATED", automationLevel: "PARTIAL", testFrequency: "CONTINUOUS", expectedResult: "Repository policies require security gates and recent evaluations are recorded" },
  { code: "SECRET-SCANNING", title: "Secrets in code are detected and remediated", description: "Committed secrets are detected via governed scanning; confirmed secrets are treated as incidents.", controlType: "DETECTIVE", implementationType: "TECHNICAL", signals: ["code.secrets_open"], evidenceSources: ["SECRETS"], testName: "Open secret findings check", testMethod: "AUTOMATED", automationLevel: "FULL", testFrequency: "CONTINUOUS", expectedResult: "No open confirmed secret findings in scanned repositories" },
  { code: "DEPENDENCY-MANAGEMENT", title: "Third-party components inventoried and vulnerability-managed", description: "SBOMs are produced for builds; components with known vulnerabilities are tracked and updated.", controlType: "PREVENTIVE", implementationType: "TECHNICAL", signals: ["code.sbom_current", "code.vulnerable_components_open"], evidenceSources: ["SBOM", "SCA"], testName: "Dependency posture check", testMethod: "AUTOMATED", automationLevel: "PARTIAL", testFrequency: "CONTINUOUS", expectedResult: "Current SBOM exists and no unexcepted critical vulnerable component is open" },
  { code: "CONTAINER-IMAGE-SCANNING", title: "Container images scanned before deployment", description: "Images are scanned for vulnerabilities and configuration issues; critical findings gate deployment.", controlType: "DETECTIVE", implementationType: "TECHNICAL", signals: ["container.critical_findings_open"], evidenceSources: ["CONTAINER_FINDING"], testName: "Container finding check", testMethod: "AUTOMATED", automationLevel: "FULL", testFrequency: "CONTINUOUS", expectedResult: "No open critical container image finding" },
  { code: "K8S-RBAC-HARDENING", title: "Kubernetes RBAC and workload hardening applied", description: "Cluster RBAC, admission and workload settings follow the CIS Kubernetes Benchmark posture checks.", controlType: "PREVENTIVE", implementationType: "TECHNICAL", signals: ["k8s.posture_failures_open"], evidenceSources: ["KUBERNETES_FINDING"], testName: "Kubernetes posture check", testMethod: "AUTOMATED", automationLevel: "FULL", testFrequency: "CONTINUOUS", expectedResult: "No open FAIL control assessment in the Kubernetes posture catalogs" },
  { code: "CLOUD-IAM-LEAST-PRIVILEGE", title: "Cloud IAM follows least privilege", description: "Cloud identities hold only required permissions; unused and over-broad access is remediated.", controlType: "PREVENTIVE", implementationType: "TECHNICAL", signals: ["cloud.iam_findings_open"], evidenceSources: ["CLOUD_FINDING"], testName: "Cloud IAM posture check", testMethod: "AUTOMATED", automationLevel: "PARTIAL", testFrequency: "CONTINUOUS", expectedResult: "No open cloud IAM finding of high severity or above" },
  { code: "API-SECURITY-TESTING", title: "APIs inventoried and security-tested", description: "API surfaces are imported through guarded importers and tested under the API operation policy.", controlType: "DETECTIVE", implementationType: "TECHNICAL", signals: ["api.critical_findings_open"], evidenceSources: ["API_FINDING"], testName: "API finding check", testMethod: "AUTOMATED", automationLevel: "FULL", testFrequency: "CONTINUOUS", expectedResult: "No open critical API finding" },
  { code: "NETWORK-SEGMENTATION", title: "Network segmentation enforced", description: "Internal and sensitive segments are reachable only through governed paths; exposure is inventoried.", controlType: "PREVENTIVE", implementationType: "TECHNICAL", signals: ["network.exposure_findings_open"], evidenceSources: ["NETWORK_FINDING"], testName: "Network exposure check", testMethod: "AUTOMATED", automationLevel: "PARTIAL", testFrequency: "CONTINUOUS", expectedResult: "No open finding reports an unapproved exposed sensitive service" },
  { code: "MALWARE-PROTECTION", title: "Malware protection deployed", description: "Anti-malware controls are deployed on in-scope endpoints and servers.", controlType: "PREVENTIVE", implementationType: "HYBRID", signals: [], evidenceSources: ["MANUAL_UPLOAD"], testName: "Malware protection attestation review", testMethod: "HYBRID", automationLevel: "NONE", testFrequency: "QUARTERLY", expectedResult: "Reviewed evidence shows malware protection deployed across in-scope systems" },
  { code: "CHANGE-MANAGEMENT", title: "Changes follow formal change management", description: "Changes to production systems are authorized, tested and recorded.", controlType: "GOVERNANCE", implementationType: "HYBRID", signals: ["devsecops.gates_enforced"], evidenceSources: ["DEVSECOPS_GATE", "MANUAL_UPLOAD"], testName: "Change process review", testMethod: "HYBRID", automationLevel: "PARTIAL", testFrequency: "QUARTERLY", expectedResult: "Sampled changes carry approvals and gate results" },
  { code: "INCIDENT-RESPONSE-PLAN", title: "Incident response plan exists and is exercised", description: "A documented incident response plan with defined roles is maintained and tabletop-exercised.", controlType: "GOVERNANCE", implementationType: "ADMINISTRATIVE", signals: [], evidenceSources: ["MANUAL_UPLOAD"], testName: "IR plan review", testMethod: "MANUAL", automationLevel: "NONE", testFrequency: "ANNUAL", expectedResult: "Approved IR plan and exercise record on file" },
  { code: "SECURITY-POLICY-GOVERNANCE", title: "Security policies are approved and reviewed", description: "Information security policies are approved by management and reviewed at planned intervals.", controlType: "GOVERNANCE", implementationType: "ADMINISTRATIVE", signals: [], evidenceSources: ["MANUAL_UPLOAD"], testName: "Policy governance review", testMethod: "MANUAL", automationLevel: "NONE", testFrequency: "ANNUAL", expectedResult: "Active approved policies exist in the policy library with current review dates" },
  { code: "RISK-ASSESSMENT-PROCESS", title: "Risk assessment process is defined and operating", description: "Risks are identified, assessed in the register, treated and reviewed on cadence.", controlType: "GOVERNANCE", implementationType: "ADMINISTRATIVE", signals: [], evidenceSources: ["MANUAL_UPLOAD"], testName: "Risk process review", testMethod: "MANUAL", automationLevel: "NONE", testFrequency: "ANNUAL", expectedResult: "Risk register shows assessed risks with current review dates" },
  { code: "VENDOR-MANAGEMENT", title: "Supplier security is assessed and managed", description: "Suppliers with access to organizational data are risk-assessed before engagement and periodically.", controlType: "GOVERNANCE", implementationType: "ADMINISTRATIVE", signals: [], evidenceSources: ["MANUAL_UPLOAD"], testName: "Vendor assessment review", testMethod: "MANUAL", automationLevel: "NONE", testFrequency: "ANNUAL", expectedResult: "Critical vendors hold current risk assessments" },
  { code: "SECURITY-AWARENESS-TRAINING", title: "Security awareness training is delivered", description: "Personnel complete role-appropriate security awareness training.", controlType: "GOVERNANCE", implementationType: "ADMINISTRATIVE", signals: [], evidenceSources: ["MANUAL_UPLOAD"], testName: "Training record review", testMethod: "MANUAL", automationLevel: "NONE", testFrequency: "ANNUAL", expectedResult: "Training completion records are current" },
];

/**
 * Cross-framework mappings (§10–§12). Coverage is deliberately
 * conservative: a technical control rarely covers an entire
 * requirement, so DIRECT mappings carry coverage < 1 unless the
 * control IS the requirement's technical substance, and nothing here
 * upgrades a partial mapping into a compliance claim (§11).
 */
const M = (controlCode: string, frameworkKey: ControlMappingData["frameworkKey"], frameworkVersion: string,
  requirementId: string, mappingType: ControlMappingData["mappingType"], coverage: number, notes: string): ControlMappingData =>
  ({ controlCode, frameworkKey, frameworkVersion, requirementId, mappingType, coverage, notes, source: "ZeroSweep control library v1" });

export const CONTROL_MAPPINGS: ControlMappingData[] = [
  M("MFA-ENFORCEMENT", "ISO_27001", "2022", "A.8.5", "DIRECT", 0.8, "Secure authentication technology; policy and lifecycle aspects remain organizational."),
  M("MFA-ENFORCEMENT", "ISO_27001", "2022", "A.5.17", "SUPPORTING", 0.3, "Supports controlled management of authentication information."),
  M("MFA-ENFORCEMENT", "PCI_DSS", "4.0", "8.4", "DIRECT", 0.9, "MFA for access into the CDE; scope determination remains organizational."),
  M("MFA-ENFORCEMENT", "PCI_DSS", "4.0", "8.3", "PARTIAL", 0.5, "Strong authentication includes factors beyond MFA."),
  M("MFA-ENFORCEMENT", "NIST_800_53", "Rev. 5", "IA-2", "PARTIAL", 0.5, "IA-2 includes identification and authentication beyond MFA enforcement."),
  M("MFA-ENFORCEMENT", "NIST_CSF", "2.0", "PR.AA", "PARTIAL", 0.4, "PR.AA spans the full identity and access lifecycle."),
  M("MFA-ENFORCEMENT", "SOC_2", "2017", "CC6.1", "PARTIAL", 0.4, "CC6.1 covers logical access architecture broadly."),
  M("MFA-ENFORCEMENT", "CIS_CONTROLS", "8.0", "6.3", "DIRECT", 0.9, "MFA for externally-exposed applications."),
  M("MFA-ENFORCEMENT", "CIS_CONTROLS", "8.0", "6.4", "DIRECT", 0.9, "MFA for remote network access."),
  M("MFA-ENFORCEMENT", "OWASP_ASVS", "4.0.3", "V2.8", "PARTIAL", 0.5, "ASVS V2.8 covers verifier implementation details beyond enforcement."),
  M("MFA-PHISHING-RESISTANT-ADMIN", "PCI_DSS", "4.0", "8.4", "SUPPORTING", 0.3, "Strengthens MFA assurance for administrative access."),
  M("MFA-PHISHING-RESISTANT-ADMIN", "CIS_CONTROLS", "8.0", "6.5", "DIRECT", 0.85, "MFA for administrative access; phishing resistance exceeds the safeguard minimum."),
  M("MFA-PHISHING-RESISTANT-ADMIN", "NIST_800_53", "Rev. 5", "IA-2", "PARTIAL", 0.4, "Supports IA-2 MFA enhancements for privileged access."),
  M("SSO-CONFIGURATION", "ISO_27001", "2022", "A.8.5", "SUPPORTING", 0.3, "Federation supports secure authentication."),
  M("SSO-CONFIGURATION", "NIST_CSF", "2.0", "PR.AA", "PARTIAL", 0.3, "Centralized identity lifecycle support."),
  M("SSO-CONFIGURATION", "SOC_2", "2017", "CC6.1", "PARTIAL", 0.3, "Logical access architecture component."),
  M("ACCESS-REVIEW", "ISO_27001", "2022", "A.5.15", "PARTIAL", 0.5, "Reviews evidence the operation of access control rules."),
  M("ACCESS-REVIEW", "NIST_800_53", "Rev. 5", "AC-2", "PARTIAL", 0.5, "Account management includes periodic review."),
  M("ACCESS-REVIEW", "SOC_2", "2017", "CC6.1", "SUPPORTING", 0.25, "Supports logical access governance."),
  M("ACCESS-REVIEW", "CIS_CONTROLS", "8.0", "5.3", "SUPPORTING", 0.3, "Reviews surface dormant accounts for disablement."),
  M("PRIVILEGED-ACCESS-MGMT", "ISO_27001", "2022", "A.8.2", "DIRECT", 0.8, "Privileged access rights restricted and managed."),
  M("PRIVILEGED-ACCESS-MGMT", "PCI_DSS", "4.0", "7.2", "PARTIAL", 0.5, "Least-privilege assignment is broader than privileged-account hygiene."),
  M("PRIVILEGED-ACCESS-MGMT", "NIST_800_53", "Rev. 5", "AC-6", "PARTIAL", 0.5, "Least privilege principle support."),
  M("PRIVILEGED-ACCESS-MGMT", "CIS_CONTROLS", "8.0", "5.4", "DIRECT", 0.85, "Dedicated administrator accounts."),
  M("PASSWORD-POLICY", "ISO_27001", "2022", "A.5.17", "PARTIAL", 0.5, "Authentication information management."),
  M("PASSWORD-POLICY", "OWASP_ASVS", "4.0.3", "V2.1", "PARTIAL", 0.6, "Password security requirements."),
  M("PASSWORD-POLICY", "NIST_800_53", "Rev. 5", "IA-5", "PARTIAL", 0.5, "Authenticator management."),
  M("VULN-SCAN-COVERAGE", "ISO_27001", "2022", "A.8.8", "PARTIAL", 0.6, "Obtaining vulnerability information and evaluating exposure."),
  M("VULN-SCAN-COVERAGE", "PCI_DSS", "4.0", "11.3", "PARTIAL", 0.6, "Regular vulnerability identification; ASV/attestation aspects are external."),
  M("VULN-SCAN-COVERAGE", "NIST_800_53", "Rev. 5", "RA-5", "DIRECT", 0.8, "Vulnerability monitoring and scanning."),
  M("VULN-SCAN-COVERAGE", "NIST_CSF", "2.0", "ID.RA", "PARTIAL", 0.4, "Risk assessment input."),
  M("VULN-SCAN-COVERAGE", "CIS_CONTROLS", "8.0", "7", "PARTIAL", 0.6, "Continuous vulnerability management."),
  M("VULN-SCAN-COVERAGE", "SOC_2", "2017", "CC7.1", "PARTIAL", 0.5, "Detection of changes and vulnerabilities."),
  M("VULN-REMEDIATION-SLA", "ISO_27001", "2022", "A.8.8", "PARTIAL", 0.4, "Appropriate measures taken on vulnerabilities."),
  M("VULN-REMEDIATION-SLA", "NIST_800_53", "Rev. 5", "SI-2", "PARTIAL", 0.5, "Flaw remediation timeliness."),
  M("VULN-REMEDIATION-SLA", "PCI_DSS", "4.0", "6.3", "SUPPORTING", 0.3, "Supports vulnerability management for bespoke software."),
  M("PATCH-MANAGEMENT", "NIST_800_53", "Rev. 5", "SI-2", "PARTIAL", 0.6, "Flaw remediation."),
  M("PATCH-MANAGEMENT", "PCI_DSS", "4.0", "6.3", "PARTIAL", 0.5, "Security patches within defined windows."),
  M("PATCH-MANAGEMENT", "CIS_CONTROLS", "8.0", "7", "PARTIAL", 0.4, "Continuous vulnerability management."),
  M("ENCRYPTION-AT-REST", "ISO_27001", "2022", "A.8.24", "PARTIAL", 0.5, "Cryptography use for stored information."),
  M("ENCRYPTION-AT-REST", "NIST_800_53", "Rev. 5", "SC-28", "DIRECT", 0.85, "Protection of information at rest."),
  M("ENCRYPTION-AT-REST", "PCI_DSS", "4.0", "3", "PARTIAL", 0.4, "Stored account data protection includes rendering PAN unreadable by several methods."),
  M("ENCRYPTION-AT-REST", "CIS_CONTROLS", "8.0", "3", "PARTIAL", 0.3, "Data protection program element."),
  M("ENCRYPTION-IN-TRANSIT", "ISO_27001", "2022", "A.8.24", "PARTIAL", 0.5, "Cryptography use for transmitted information."),
  M("ENCRYPTION-IN-TRANSIT", "NIST_800_53", "Rev. 5", "SC-8", "DIRECT", 0.85, "Transmission confidentiality and integrity."),
  M("ENCRYPTION-IN-TRANSIT", "PCI_DSS", "4.0", "4", "PARTIAL", 0.6, "Strong cryptography during transmission."),
  M("ENCRYPTION-IN-TRANSIT", "OWASP_TOP_10", "2021", "A02", "PARTIAL", 0.5, "Cryptographic failures category."),
  M("PUBLIC-EXPOSURE-PREVENTION", "SOC_2", "2017", "CC6.6", "PARTIAL", 0.5, "Protection against threats from outside system boundaries."),
  M("PUBLIC-EXPOSURE-PREVENTION", "NIST_CSF", "2.0", "PR.DS", "PARTIAL", 0.3, "Data security support."),
  M("PUBLIC-EXPOSURE-PREVENTION", "OWASP_TOP_10", "2021", "A05", "PARTIAL", 0.4, "Security misconfiguration category."),
  M("PUBLIC-EXPOSURE-PREVENTION", "CIS_CONTROLS", "8.0", "3.3", "PARTIAL", 0.5, "Data access control lists."),
  M("LOGGING-MONITORING", "ISO_27001", "2022", "A.8.15", "PARTIAL", 0.6, "Logging production, protection and analysis."),
  M("LOGGING-MONITORING", "ISO_27001", "2022", "A.8.16", "PARTIAL", 0.5, "Monitoring activities."),
  M("LOGGING-MONITORING", "PCI_DSS", "4.0", "10.2", "PARTIAL", 0.6, "Audit log implementation."),
  M("LOGGING-MONITORING", "NIST_800_53", "Rev. 5", "AU-6", "PARTIAL", 0.5, "Audit review and analysis."),
  M("LOGGING-MONITORING", "NIST_800_53", "Rev. 5", "SI-4", "PARTIAL", 0.5, "System monitoring."),
  M("LOGGING-MONITORING", "CIS_CONTROLS", "8.0", "8.2", "PARTIAL", 0.6, "Collect audit logs."),
  M("LOGGING-MONITORING", "CIS_CONTROLS", "8.0", "8.11", "PARTIAL", 0.5, "Conduct audit log reviews."),
  M("LOGGING-MONITORING", "NIST_CSF", "2.0", "DE.CM", "PARTIAL", 0.5, "Continuous monitoring."),
  M("LOGGING-MONITORING", "OWASP_TOP_10", "2021", "A09", "PARTIAL", 0.5, "Logging and monitoring failures category."),
  M("LOGGING-MONITORING", "OWASP_ASVS", "4.0.3", "V7.1", "PARTIAL", 0.5, "Log content requirements."),
  M("BACKUP-VERIFICATION", "ISO_27001", "2022", "A.8.13", "DIRECT", 0.85, "Backups maintained and regularly tested."),
  M("BACKUP-VERIFICATION", "NIST_800_53", "Rev. 5", "CP-9", "PARTIAL", 0.6, "System backup."),
  M("BACKUP-VERIFICATION", "SOC_2", "2017", "A1.2", "PARTIAL", 0.4, "Recovery capability support."),
  M("BACKUP-VERIFICATION", "CIS_CONTROLS", "8.0", "11", "PARTIAL", 0.5, "Data recovery practices."),
  M("BACKUP-VERIFICATION", "CIS_CONTROLS", "8.0", "11.3", "SUPPORTING", 0.3, "Recovery data protection is related but distinct."),
  M("DR-TESTING", "NIST_800_53", "Rev. 5", "CP-4", "DIRECT", 0.85, "Contingency plan testing."),
  M("DR-TESTING", "SOC_2", "2017", "A1.2", "PARTIAL", 0.5, "Recovery execution support."),
  M("DR-TESTING", "NIST_CSF", "2.0", "RC.RP", "PARTIAL", 0.5, "Recovery plan execution."),
  M("SECURE-SDLC-GATES", "PCI_DSS", "4.0", "6.5", "PARTIAL", 0.5, "Change management for system components."),
  M("SECURE-SDLC-GATES", "NIST_800_53", "Rev. 5", "SA-11", "PARTIAL", 0.5, "Developer testing and evaluation."),
  M("SECURE-SDLC-GATES", "SOC_2", "2017", "CC8.1", "PARTIAL", 0.5, "Change management."),
  M("SECURE-SDLC-GATES", "CIS_CONTROLS", "8.0", "16", "PARTIAL", 0.5, "Application software security lifecycle."),
  M("SECURE-SDLC-GATES", "OWASP_TOP_10", "2021", "A08", "PARTIAL", 0.4, "Software and data integrity failures."),
  M("SECRET-SCANNING", "CIS_CONTROLS", "8.0", "16", "SUPPORTING", 0.25, "Application security lifecycle element."),
  M("SECRET-SCANNING", "OWASP_TOP_10", "2021", "A07", "SUPPORTING", 0.2, "Authentication failure prevention support."),
  M("DEPENDENCY-MANAGEMENT", "OWASP_ASVS", "4.0.3", "V14.2", "PARTIAL", 0.6, "Dependency requirements."),
  M("DEPENDENCY-MANAGEMENT", "OWASP_TOP_10", "2021", "A06", "DIRECT", 0.8, "Vulnerable and outdated components category."),
  M("DEPENDENCY-MANAGEMENT", "NIST_CSF", "2.0", "GV.SC", "SUPPORTING", 0.25, "Supply chain risk management input."),
  M("DEPENDENCY-MANAGEMENT", "PCI_DSS", "4.0", "6.3", "PARTIAL", 0.4, "Vulnerability identification for bespoke software dependencies."),
  M("CONTAINER-IMAGE-SCANNING", "CIS_CONTROLS", "8.0", "16", "SUPPORTING", 0.25, "Application software security support."),
  M("CONTAINER-IMAGE-SCANNING", "NIST_800_53", "Rev. 5", "RA-5", "SUPPORTING", 0.3, "Vulnerability scanning scope includes hosted applications."),
  M("K8S-RBAC-HARDENING", "CIS_CONTROLS", "8.0", "4", "SUPPORTING", 0.3, "Secure configuration of enterprise assets."),
  M("K8S-RBAC-HARDENING", "NIST_800_53", "Rev. 5", "CM-6", "PARTIAL", 0.5, "Configuration settings."),
  M("CLOUD-IAM-LEAST-PRIVILEGE", "ISO_27001", "2022", "A.8.3", "PARTIAL", 0.5, "Information access restriction."),
  M("CLOUD-IAM-LEAST-PRIVILEGE", "NIST_800_53", "Rev. 5", "AC-6", "PARTIAL", 0.5, "Least privilege."),
  M("CLOUD-IAM-LEAST-PRIVILEGE", "PCI_DSS", "4.0", "7.2", "PARTIAL", 0.5, "Access definition and assignment."),
  M("API-SECURITY-TESTING", "OWASP_ASVS", "4.0.3", "V13", "PARTIAL", 0.5, "API and web service verification."),
  M("API-SECURITY-TESTING", "OWASP_TOP_10", "2021", "A01", "SUPPORTING", 0.3, "Broken access control detection support."),
  M("NETWORK-SEGMENTATION", "NIST_800_53", "Rev. 5", "SC-8", "SUPPORTING", 0.2, "Boundary protection is broader than this signal set."),
  M("NETWORK-SEGMENTATION", "CIS_CONTROLS", "8.0", "13", "PARTIAL", 0.4, "Network monitoring and defense."),
  M("MALWARE-PROTECTION", "ISO_27001", "2022", "A.8.7", "PARTIAL", 0.6, "Protection against malware; evidence here is attestation-based."),
  M("MALWARE-PROTECTION", "PCI_DSS", "4.0", "5", "PARTIAL", 0.5, "Malicious software protection."),
  M("MALWARE-PROTECTION", "NIST_800_53", "Rev. 5", "SI-3", "PARTIAL", 0.5, "Malicious code protection."),
  M("CHANGE-MANAGEMENT", "SOC_2", "2017", "CC8.1", "PARTIAL", 0.6, "Change management; platform evidences the technical gate portion."),
  M("CHANGE-MANAGEMENT", "ISO_27001", "2022", "A.8.9", "SUPPORTING", 0.3, "Configuration management support."),
  M("INCIDENT-RESPONSE-PLAN", "ISO_27001", "2022", "A.5.24", "PARTIAL", 0.6, "Incident management planning; manual evidence only."),
  M("INCIDENT-RESPONSE-PLAN", "NIST_800_53", "Rev. 5", "IR-4", "SUPPORTING", 0.3, "Incident handling capability is operational, not platform-evidenced."),
  M("INCIDENT-RESPONSE-PLAN", "NIST_CSF", "2.0", "RS.MA", "PARTIAL", 0.5, "Incident management; manual evidence only."),
  M("SECURITY-POLICY-GOVERNANCE", "ISO_27001", "2022", "A.5.1", "PARTIAL", 0.7, "Policy definition and review; the policy library evidences lifecycle, not content quality."),
  M("SECURITY-POLICY-GOVERNANCE", "NIST_CSF", "2.0", "GV.OC", "SUPPORTING", 0.25, "Organizational context support."),
  M("SECURITY-POLICY-GOVERNANCE", "PCI_DSS", "4.0", "12.5", "PARTIAL", 0.5, "Security program documentation."),
  M("RISK-ASSESSMENT-PROCESS", "ISO_27001", "2022", "A.5.35", "SUPPORTING", 0.2, "Independent review remains external."),
  M("RISK-ASSESSMENT-PROCESS", "NIST_CSF", "2.0", "ID.RA", "PARTIAL", 0.5, "Risk assessment; register evidences operation of the process."),
  M("RISK-ASSESSMENT-PROCESS", "NIST_CSF", "2.0", "GV.RM", "PARTIAL", 0.5, "Risk management strategy operation."),
  M("VENDOR-MANAGEMENT", "ISO_27001", "2022", "A.5.19", "PARTIAL", 0.6, "Supplier relationship security; register evidences assessments."),
  M("VENDOR-MANAGEMENT", "SOC_2", "2017", "CC9.2", "PARTIAL", 0.6, "Vendor risk management."),
  M("VENDOR-MANAGEMENT", "CIS_CONTROLS", "8.0", "15", "PARTIAL", 0.6, "Service provider management."),
  M("SECURITY-AWARENESS-TRAINING", "ISO_27001", "2022", "A.6.3", "PARTIAL", 0.6, "Awareness and training; manual evidence only."),
  M("SECURITY-AWARENESS-TRAINING", "NIST_CSF", "2.0", "PR.AT", "PARTIAL", 0.5, "Awareness and training."),
  M("SECURITY-AWARENESS-TRAINING", "CIS_CONTROLS", "8.0", "14", "PARTIAL", 0.6, "Security awareness program."),
];

/** Default evidence freshness windows per control (§25) — per-control,
 *  never one global duration. staleAfterDays → STALE, expireAfterDays
 *  → EXPIRED. Configurable per workspace in the database. */
export const DEFAULT_FRESHNESS_POLICIES: Record<string, { staleAfterDays: number; expireAfterDays: number }> = {
  "MFA-ENFORCEMENT": { staleAfterDays: 30, expireAfterDays: 90 },
  "MFA-PHISHING-RESISTANT-ADMIN": { staleAfterDays: 30, expireAfterDays: 90 },
  "SSO-CONFIGURATION": { staleAfterDays: 30, expireAfterDays: 90 },
  "ACCESS-REVIEW": { staleAfterDays: 100, expireAfterDays: 190 },
  "PRIVILEGED-ACCESS-MGMT": { staleAfterDays: 30, expireAfterDays: 90 },
  "PASSWORD-POLICY": { staleAfterDays: 30, expireAfterDays: 90 },
  "VULN-SCAN-COVERAGE": { staleAfterDays: 14, expireAfterDays: 45 },
  "VULN-REMEDIATION-SLA": { staleAfterDays: 14, expireAfterDays: 45 },
  "PATCH-MANAGEMENT": { staleAfterDays: 14, expireAfterDays: 45 },
  "ENCRYPTION-AT-REST": { staleAfterDays: 30, expireAfterDays: 90 },
  "ENCRYPTION-IN-TRANSIT": { staleAfterDays: 30, expireAfterDays: 90 },
  "PUBLIC-EXPOSURE-PREVENTION": { staleAfterDays: 14, expireAfterDays: 45 },
  "LOGGING-MONITORING": { staleAfterDays: 14, expireAfterDays: 45 },
  "BACKUP-VERIFICATION": { staleAfterDays: 3, expireAfterDays: 14 },
  "DR-TESTING": { staleAfterDays: 370, expireAfterDays: 550 },
  "SECURE-SDLC-GATES": { staleAfterDays: 30, expireAfterDays: 90 },
  "SECRET-SCANNING": { staleAfterDays: 14, expireAfterDays: 45 },
  "DEPENDENCY-MANAGEMENT": { staleAfterDays: 30, expireAfterDays: 90 },
  "CONTAINER-IMAGE-SCANNING": { staleAfterDays: 14, expireAfterDays: 45 },
  "K8S-RBAC-HARDENING": { staleAfterDays: 30, expireAfterDays: 90 },
  "CLOUD-IAM-LEAST-PRIVILEGE": { staleAfterDays: 30, expireAfterDays: 90 },
  "API-SECURITY-TESTING": { staleAfterDays: 30, expireAfterDays: 90 },
  "NETWORK-SEGMENTATION": { staleAfterDays: 30, expireAfterDays: 90 },
};
export const MANUAL_EVIDENCE_FRESHNESS = { staleAfterDays: 335, expireAfterDays: 400 };

export interface FindingControlRule {
  id: string;
  /** Match when the finding carries any of these CWE ids (e.g. "CWE-319"). */
  cwes?: string[];
  /** Match when the finding category contains any of these substrings (upper-case compare). */
  categoryIncludes?: string[];
  /** Match when the finding's security domain equals one of these. */
  domains?: string[];
  controlCode: string;
  confidence: MappingConfidence;
  rationale: string;
}

/**
 * Deterministic finding → control mapping rules (§85). First matching
 * rule wins; analysts may override (override is recorded, §87). These
 * rules never create compliance claims — they link a technical finding
 * to the control whose signal it degrades.
 */
export const FINDING_CONTROL_RULES: FindingControlRule[] = [
  { id: "secrets", cwes: ["CWE-798", "CWE-259", "CWE-321"], categoryIncludes: ["SECRET", "CREDENTIAL"], controlCode: "SECRET-SCANNING", confidence: "HIGH", rationale: "Credential material detected in scanned content" },
  { id: "tls", cwes: ["CWE-319", "CWE-295", "CWE-327"], categoryIncludes: ["TLS", "SSL", "CLEARTEXT"], controlCode: "ENCRYPTION-IN-TRANSIT", confidence: "HIGH", rationale: "Transport encryption weakness" },
  { id: "public-exposure", categoryIncludes: ["PUBLIC_EXPOSURE", "PUBLIC_STORAGE", "OPEN_STORAGE"], domains: ["CLOUD"], controlCode: "PUBLIC-EXPOSURE-PREVENTION", confidence: "HIGH", rationale: "Sensitive resource publicly exposed" },
  { id: "cloud-encryption", categoryIncludes: ["ENCRYPTION"], domains: ["CLOUD"], controlCode: "ENCRYPTION-AT-REST", confidence: "HIGH", rationale: "Cloud storage encryption posture" },
  { id: "cloud-iam", categoryIncludes: ["IAM", "LEAST_PRIVILEGE", "OVER_PRIVILEGED"], domains: ["CLOUD"], controlCode: "CLOUD-IAM-LEAST-PRIVILEGE", confidence: "HIGH", rationale: "Cloud identity privilege posture" },
  { id: "cloud-logging", categoryIncludes: ["LOGGING", "AUDIT_TRAIL"], domains: ["CLOUD"], controlCode: "LOGGING-MONITORING", confidence: "HIGH", rationale: "Logging disabled or incomplete on a cloud resource" },
  { id: "vulnerable-component", cwes: ["CWE-1035", "CWE-1104"], categoryIncludes: ["VULNERABLE_COMPONENT", "OUTDATED_COMPONENT", "SCA"], controlCode: "DEPENDENCY-MANAGEMENT", confidence: "HIGH", rationale: "Known-vulnerable third-party component" },
  { id: "kev-patch", categoryIncludes: ["KEV", "KNOWN_EXPLOITED"], controlCode: "PATCH-MANAGEMENT", confidence: "HIGH", rationale: "Known-exploited vulnerability open past its window" },
  { id: "container", domains: ["CONTAINER"], controlCode: "CONTAINER-IMAGE-SCANNING", confidence: "MEDIUM", rationale: "Container image finding" },
  { id: "kubernetes", domains: ["KUBERNETES"], controlCode: "K8S-RBAC-HARDENING", confidence: "MEDIUM", rationale: "Kubernetes posture finding" },
  { id: "api", domains: ["API"], controlCode: "API-SECURITY-TESTING", confidence: "MEDIUM", rationale: "API security finding" },
  { id: "injection", cwes: ["CWE-89", "CWE-79", "CWE-78", "CWE-94"], controlCode: "SECURE-SDLC-GATES", confidence: "MEDIUM", rationale: "Injection-class defect indicates SDLC gate gap" },
  { id: "auth", cwes: ["CWE-287", "CWE-862", "CWE-863"], categoryIncludes: ["AUTHENTICATION", "AUTHORIZATION", "ACCESS_CONTROL"], controlCode: "PRIVILEGED-ACCESS-MGMT", confidence: "LOW", rationale: "Authentication/authorization weakness; control link is indicative only" },
  { id: "network-exposure", domains: ["NETWORK"], controlCode: "NETWORK-SEGMENTATION", confidence: "LOW", rationale: "Network exposure finding" },
];
