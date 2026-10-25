"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { DeleteButton } from "@/components/DeleteButton";
import { apiFetch, ApiError } from "@/lib/api-client";

/**
 * Targets — step 1 of the road, framed-sheet skin (owner-approved
 * sample, 2026-10-25). The Add Target form posts to the real POST
 * /targets API. A fresh target starts unverified: verification is the
 * next step and nothing can scan it before that. Delete uses the Rare
 * UI delete button (rareui.com, MIT + Commons Clause — credit below):
 * the bin disappears, Tick and Cross take its place, Cross brings the
 * bin back, Tick soft-deletes via DELETE /targets/:id (the row stays
 * for history; every list already filters deleted targets out).
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

interface TargetItem {
  id: string;
  name: string;
  type: string;
  value: string;
  status: string;
  verified: boolean;
}

const inputCls = "w-full rounded-lg border border-[#e8eaec] bg-white px-3 py-2 text-sm text-[#131416] placeholder:text-[#5d5f60] outline-none transition focus:border-[#1b6c80]";
const labelCls = "block text-[13px] font-medium text-[#131416]";

export default function Page() {
  const [name, setName] = useState("");
  const [type, setType] = useState(TYPES[0].value);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [added, setAdded] = useState("");
  const [items, setItems] = useState<TargetItem[] | null>(null);
  const [listError, setListError] = useState("");
  const [deleteError, setDeleteError] = useState("");

  const selected = TYPES.find((t) => t.value === type) ?? TYPES[0];

  const refresh = useCallback(async () => {
    try {
      const data = await apiFetch<{ items?: TargetItem[] } | TargetItem[]>("/targets");
      setItems(Array.isArray(data) ? data : data.items ?? []);
      setListError("");
    } catch (err) {
      setListError(err instanceof ApiError ? err.message : "Could not load targets.");
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

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
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not add the target. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  async function removeTarget(id: string) {
    await apiFetch(`/targets/${id}`, { method: "DELETE" });
  }

  const verifiedCount = items?.filter((t) => t.verified).length ?? 0;
  const pending = items?.filter((t) => !t.verified) ?? [];

  return (
    <>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <h1 className="order-1 text-[22px] font-semibold leading-tight text-[#131416]">Targets</h1>
        <a href="#add-target" className="order-2 ml-auto inline-flex h-8 items-center rounded-lg bg-[#131416] px-4 text-sm font-medium text-white transition-colors hover:bg-black">
          Add a target
        </a>
        {items ? <span className="order-3 w-full text-sm text-[#5d5f60] md:order-2 md:w-auto">{verifiedCount} verified</span> : null}
      </div>
      <p className="mt-2 max-w-2xl text-sm text-[#5d5f60]">Every site you are allowed to test, in one list. Add a target, verify it, then it can be planned into a check.</p>

      {items ? (
        <section className="mt-12">
          <div className="rounded-lg bg-[#fafafa] p-1.5">
            <div className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-[#e8eaec] bg-[#e8eaec] lg:grid-cols-3">
              <div className="bg-[#fafafa] p-4">
                <p className="text-sm font-medium text-[#131416]">Total targets</p>
                <p className="mt-1 text-[28px] leading-none text-[#131416] [font-variant-numeric:tabular-nums]">{items.length}</p>
                <p className="mt-1 text-[13px] text-[#5d5f60]">Across this workspace</p>
              </div>
              <div className="bg-[#fafafa] p-4">
                <p className="text-sm font-medium text-[#131416]">Verified</p>
                <p className="mt-1 text-[28px] leading-none text-[#131416] [font-variant-numeric:tabular-nums]">{verifiedCount}</p>
                <p className="mt-1 text-[13px] text-[#5d5f60]">Ready for a check</p>
              </div>
              <div className="col-span-2 bg-[#fafafa] p-4 lg:col-span-1">
                <p className="text-sm font-medium text-[#131416]">Pending verification</p>
                <p className="mt-1 text-[28px] leading-none text-[#131416] [font-variant-numeric:tabular-nums]">{pending.length}</p>
                <p className="mt-1 text-[13px] text-[#5d5f60]">{pending.length === 0 ? "Nothing waiting" : "See Needs attention below"}</p>
              </div>
            </div>
          </div>
        </section>
      ) : null}

      <div id="add-target" className="mt-12 scroll-mt-4">
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
              <p className="mt-1 text-xs text-[#5d5f60]">{selected.hint}</p>
            </div>
            <button type="submit" disabled={busy} className="h-8 rounded-lg bg-[#131416] px-4 text-sm font-medium text-white transition-colors hover:bg-black disabled:opacity-50">
              {busy ? "Adding…" : "Add target"}
            </button>
          </form>
          {error ? <p role="alert" className="mt-3 text-sm text-[#c4242a]">{error} Check the value matches the type you picked.</p> : null}
          {added ? <p role="status" className="mt-3 text-sm text-[#1e7b4f]">{added}</p> : null}
        </Card>
      </div>

      <section className="mt-12">
        <div className="mb-4 flex items-baseline justify-between">
          <h2 className="text-base font-medium text-[#131416]">All targets</h2>
        </div>
        {deleteError ? <p role="alert" className="mb-3 text-sm text-[#c4242a]">{deleteError}</p> : null}
        {listError ? (
          <EmptyState title="Nothing to show yet" body={`${listError} When the API is running and data exists, it will appear here — no placeholder data is shown.`} />
        ) : items === null ? (
          <p className="text-sm text-[#5d5f60]">Loading…</p>
        ) : items.length === 0 ? (
          <EmptyState title="No targets yet" body="Use the Add a target form above — a domain, web application, IP, API, repository, image or lab environment — then verify ownership to continue." />
        ) : (
          <>
            <div className="hidden overflow-x-auto rounded-lg border border-[#e8eaec] md:block">
              <table className="w-full min-w-[640px] text-left text-sm">
                <thead className="text-[#5d5f60]">
                  <tr>
                    <th className="px-4 py-3 text-[12px] font-normal">Target</th>
                    <th className="px-4 py-3 text-[12px] font-normal">Type</th>
                    <th className="px-4 py-3 text-[12px] font-normal">Value</th>
                    <th className="px-4 py-3 text-[12px] font-normal">Status</th>
                    <th className="px-4 py-3 text-[12px] font-normal">Verified</th>
                    <th className="px-4 py-3" aria-label="Actions" />
                  </tr>
                </thead>
                <tbody>
                  {items.map((t) => (
                    <tr key={t.id} className="border-t border-[#f0f1f2]">
                      <td className="px-4 py-3">
                        <Link href={`/targets/${t.id}`} className="font-medium text-[#1b6c80] hover:underline">{t.name}</Link>
                      </td>
                      <td className="px-4 py-3 text-[#131416]">{t.type}</td>
                      <td className="max-w-[280px] truncate px-4 py-3 text-[#5d5f60]">{t.value}</td>
                      <td className="px-4 py-3 text-[#131416]">{t.status}</td>
                      <td className="px-4 py-3">{t.verified ? <Badge tone="VERIFIED">Verified</Badge> : <Badge tone="PENDING">Pending</Badge>}</td>
                      <td className="px-4 py-3">
                        <DeleteButton label={t.name} onConfirm={() => removeTarget(t.id)}
                          onDeleted={() => setItems((cur) => (cur ?? []).filter((x) => x.id !== t.id))}
                          onError={(m) => setDeleteError(m)} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="space-y-0 md:hidden">
              {items.map((t) => (
                <div key={t.id} className="relative border-t border-[#f0f1f2] py-3.5 pr-12 first:border-t-0 first:pt-0">
                  <Link href={`/targets/${t.id}`} className="font-medium text-[#1b6c80] hover:underline">{t.name}</Link>
                  <p className="truncate text-[13px] text-[#5d5f60]">{t.value}</p>
                  <p className="text-[13px] text-[#5d5f60]">
                    {t.type} · {t.status} · {t.verified ? <span className="text-[#1e7b4f]">Verified</span> : <span>Pending</span>}
                  </p>
                  <span className="absolute right-0 top-1/2 -translate-y-1/2">
                    <DeleteButton label={t.name} onConfirm={() => removeTarget(t.id)}
                      onDeleted={() => setItems((cur) => (cur ?? []).filter((x) => x.id !== t.id))}
                      onError={(m) => setDeleteError(m)} />
                  </span>
                </div>
              ))}
            </div>
          </>
        )}
        <p className="mt-4 text-sm text-[#5d5f60]">A target can only be scanned after verification. Verification is one declaration: you own it, or you have the owner&apos;s permission.</p>
      </section>

      {items ? (
        <section className="mt-12">
          <div className="mb-4 flex items-baseline justify-between">
            <h2 className="text-base font-medium text-[#131416]">Needs attention</h2>
          </div>
          {pending.length === 0 ? (
            <div className="rounded-lg border border-[#e8eaec] bg-white p-5">
              <p className="text-sm text-[#5d5f60]"><span className="font-medium text-[#131416]">Nothing needs attention.</span> Every target is verified and ready. When a target is added but not verified, it shows up here with its next step.</p>
            </div>
          ) : (
            <div className="rounded-lg border border-[#e8eaec] bg-white p-5">
              <ul className="space-y-2">
                {pending.map((t) => (
                  <li key={t.id} className="flex items-center justify-between gap-3 text-sm">
                    <span className="min-w-0"><span className="font-medium text-[#131416]">{t.name}</span> <span className="text-[#5d5f60]">— not verified yet</span></span>
                    <Link href={`/targets/${t.id}`} className="shrink-0 font-medium text-[#1b6c80] hover:underline">Verify →</Link>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      ) : null}

      <p className="mt-12 text-[12px] text-[#5d5f60]">Delete button by <a href="https://www.rareui.com" target="_blank" rel="noreferrer" className="underline hover:text-[#131416]">Rare UI</a>.</p>
    </>
  );
}
