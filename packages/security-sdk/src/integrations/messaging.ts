import { scrubSecretPatterns, sanitizeUntrustedText } from "./sanitize";
import type { SanitizedFindingView } from "./types";

/**
 * Slack / Microsoft Teams message builders (Prompt 24 §55–§59).
 * Messages are built ONLY from sanitized finding views and pass
 * through the secret scrubber as a second line of defence (§56,
 * §127): a raw credential, private key or unredacted evidence snippet
 * can never appear in a chat message.
 */

function clean(text: string, max = 500): string {
  return scrubSecretPatterns(sanitizeUntrustedText(text, max)).text;
}

export function buildSlackFindingAlert(finding: SanitizedFindingView): { text: string; blocks: unknown[] } {
  const location = finding.filePath
    ? `${finding.filePath}${finding.startLine ? `:${finding.startLine}` : ""}`
    : (finding.assetReference ?? "asset");
  const headline = clean(`[${finding.severity}] ${finding.title}`, 300);
  const text = `${headline} — ${clean(location, 200)} (${finding.dsrcloneReference})`;
  return {
    text,
    blocks: [
      { type: "header", text: { type: "plain_text", text: headline } },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Severity:* ${finding.severity}` },
          { type: "mrkdwn", text: `*Status:* ${finding.lifecycleStatus}` },
          { type: "mrkdwn", text: `*Location:* ${clean(location, 200)}` },
          { type: "mrkdwn", text: `*Reference:* ${finding.dsrcloneReference}` },
        ],
      },
      ...(finding.remediation
        ? [{ type: "section", text: { type: "mrkdwn", text: `*Remediation:* ${clean(finding.remediation, 400)}` } }]
        : []),
    ],
  };
}

export function buildSlackReportReady(input: { title: string; reference: string }): { text: string } {
  return { text: `Security report ready: ${clean(input.title, 200)} (${input.reference})` };
}

export function buildTeamsFindingAlert(finding: SanitizedFindingView): Record<string, unknown> {
  const location = finding.filePath
    ? `${finding.filePath}${finding.startLine ? `:${finding.startLine}` : ""}`
    : (finding.assetReference ?? "asset");
  return {
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    summary: clean(`[${finding.severity}] ${finding.title}`, 300),
    themeColor: finding.severity === "CRITICAL" ? "A30202" : finding.severity === "HIGH" ? "D24726" : "0076D7",
    sections: [{
      activityTitle: clean(`[${finding.severity}] ${finding.title}`, 300),
      facts: [
        { name: "Severity", value: finding.severity },
        { name: "Status", value: finding.lifecycleStatus },
        { name: "Location", value: clean(location, 200) },
        { name: "Reference", value: finding.dsrcloneReference },
      ],
      text: finding.remediation ? clean(finding.remediation, 400) : undefined,
    }],
  };
}
