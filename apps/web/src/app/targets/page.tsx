"use client";

import { useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge, Card } from "@dsrclone/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

/**
 * Targets — step 1 of the road. The Add Target form posts to the real
 * POST /targets API (the page previously only listed targets, so there
 * was no way to add one from the UI at all — owner report 2026-10-20).
 * A fresh target starts unverified: verification is the next step and
 * nothing can scan it before that.
 */
const TYPES: { value: string; label: string; hint: string; placeholder: string }[] = [
  { value: "DOMAIN", label: "Domain", hint: "Just the domain, no https:// in front.", placeholder: "example.com" },
  { value: "WEB_APPLICATION", label: "Website / web app", hint: "The full web address of the site or app.", placeholder: "https://example.com" },
  { value: "IP_ADDRESS", label: "IP address", hint: "A single IPv4 address.", placeholder: "203.0.113.10" },
  { value: "CIDR", label: "Network range (CIDR)", hint: "A range of addresses in CIDR form.", placeholder: "192.168.1.0/24" },
  { value: "API", label: "API", hint: "The base address of the API.", placeholder: "https://api.example.com" },
  { value: "GRAPHQL", label: "GraphQL API", hint: "The GraphQL endpoint address.", placeholder: "https://example.com/graphql" },
  { value: "SOURCE_REPOSITORY", label: "Code repository", hint: "The repository address.", placeholder: "https://github.com/you/project" },
  { value: "APK", label: "Android app (APK)", hint: "The app package or artifact reference.", placeholder: "com.example.app" },
  { value: "CONTAINER_IMAGE", label: "Container image", hint: "The image name and tag.", placeholder: "registry.example.com/app:latest" },
  { value: "KUBERNETES_CLUSTER", label: "Kubernetes cluster", hint: "The cluster name or reference.", placeholder: "production-cluster" },
  { value: "AWS", label: "AWS account", hint: "The AWS account reference.", placeholder: "123456789012" },
  { value: "AZURE", label: "Azure", hint: "The Azure subscription or resource reference.", placeholder: "subscription-id" },
  { value: "GCP", label: "Google Cloud", hint: "The Google Cloud project reference.", placeholder: "my-project-id" },
  { value: "ACTIVE_DIRECTORY", label: "Active Directory", hint: "The AD domain name.", placeholder: "corp.example.com" },
  { value: "BINARY", label: "Binary / file", hint: "The file or artifact reference.", placeholder: "firmware.bin" },
  { value: "WIRELESS_LAB", label: "Wireless lab", hint: "The lab network reference.", placeholder: "lab-ssid" },
];

const inputCls = "w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 outline-none focus:border-slate-500";
const labelCls = "block text-xs font-medium uppercase tracking-wider text-slate-400";

export default function Page() {
  const [name, setName] = useState("");
  const [type, setType] = useState(TYPES[0].value);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [added, setAdded] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);

  const selected = TYPES.find((t) => t.value === type) ?? TYPES[0];

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(""); setAdded("");
    try {
      // NOTE: no Content-Type header here — apiFetch already sets
      // application/json; passing it again (different casing) makes the
      // browser send "application/json, application/json", which the
      // API's JSON parser does not recognize, so the body arrives empty.
      await apiFetch("/targets", {
        method: "POST",
        body: JSON.stringify({ name: name.trim(), type, value: value.trim() }),
      });
      setAdded(`"${name.trim()}" added below. It starts as Pending — a target must be verified as yours before anything can scan it.`);
      setName(""); setValue("");
      setRefreshKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not add the target. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader eyebrow="Targets — step 1" title="Targets" body="Add the website, app or system you want checked — only ones you own or have permission to test. Then open a target from the list to verify it's yours (step 2) — a target must be verified before any scan can run." />
      <div className="mb-6">
        <Card eyebrow="Step 1" title="Add a target">
          <form onSubmit={submit} className="grid gap-4 md:grid-cols-[1fr_220px_1fr_auto] md:items-end">
            <div>
              <label className={labelCls} htmlFor="target-name">Name</label>
              <input id="target-name" className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="My website" required maxLength={200} />
            </div>
            <div>
              <label className={labelCls} htmlFor="target-type">Type</label>
              <select id="target-type" className={inputCls} value={type} onChange={(e) => setType(e.target.value)}>
                {TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </div>
            <div>
              <label className={labelCls} htmlFor="target-value">Address / value</label>
              <input id="target-value" className={inputCls} value={value} onChange={(e) => setValue(e.target.value)} placeholder={selected.placeholder} required maxLength={2048} />
              <p className="mt-1 text-xs text-slate-500">{selected.hint}</p>
            </div>
            <button type="submit" disabled={busy} className="inline-flex h-9 items-center rounded-full bg-white px-4 text-sm font-medium text-black transition-colors hover:bg-slate-200 disabled:opacity-50">
              {busy ? "Adding…" : "Add target"}
            </button>
          </form>
          {error ? <p role="alert" className="mt-3 text-sm text-red-300">{error} Check the value matches the type you picked.</p> : null}
          {added ? <p role="status" className="mt-3 text-sm text-emerald-300">{added}</p> : null}
        </Card>
      </div>
      <ResourceList
        key={refreshKey}
        path="/targets"
        emptyTitle="No targets yet"
        emptyBody="Use the Add a target form above — a domain, web application, IP, API, repository, image or lab environment — then verify ownership to continue."
        columns={['Name','Type','Value','Status','Verified']}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[<Link key="name" href={`/targets/${String(item.id ?? "")}`} className="text-sky-300 hover:underline">{String(item.name ?? "")}</Link>, String(item.type ?? ""), String(item.value ?? ""), String(item.status ?? ""), item.verified ? <Badge tone="VERIFIED">Verified</Badge> : <Badge tone="PENDING">Pending</Badge>]} />
        )}
      />
    </>
  );
}
