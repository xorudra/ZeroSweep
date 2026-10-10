"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface MemberRow { userId: string; email: string; displayName: string; organizationRole: string; membershipStatus: string; mfaEnrolled: boolean; passkeyCount: number; workspaceIds: string[]; lastActive: string | null }
const ROLES = ["OWNER", "ADMIN", "SECURITY_ADMIN", "SECURITY_ENGINEER", "ANALYST", "MEMBER", "VIEWER"];

/**
 * User directory (Prompt 23 §88/89). Shows identity and access state only —
 * never password hashes, MFA secrets, recovery codes or SCIM tokens. Role
 * and status changes take effect on the target's next authorization check
 * (roles are read from current membership, §124).
 */
export default function MembersPage() {
  const [orgId, setOrgId] = useState<string>("");
  const [members, setMembers] = useState<MemberRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [invite, setInvite] = useState({ email: "", role: "VIEWER" });
  const [inviteToken, setInviteToken] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const me = await apiFetch<{ organizationId: string }>("/auth/me");
      setOrgId(me.organizationId);
      setMembers(await apiFetch<MemberRow[]>(`/organizations/${me.organizationId}/members`));
    } catch (e) { setError((e as Error).message); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const act = async (fn: () => Promise<unknown>, msg: string) => {
    setError(null);
    try { await fn(); setNotice(msg); await load(); } catch (e) { setError((e as Error).message); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Settings" title="Organization members" body="Directory, roles, invitations and membership state. Sensitive authentication material is never shown here." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      <Card>
        <h2 className="font-semibold">Members</h2>
        <table className="mt-3 w-full text-sm">
          <thead><tr className="text-left text-slate-400"><th>Email</th><th>Role</th><th>Status</th><th>MFA</th><th>Workspaces</th><th>Last active</th><th /></tr></thead>
          <tbody>
            {members.map((m) => (
              <tr key={m.userId} className="border-t border-slate-800">
                <td className="py-2">{m.email}<div className="text-xs text-slate-500">{m.displayName}</div></td>
                <td>
                  <select className="rounded bg-slate-900 px-2 py-1" value={m.organizationRole} onChange={(e) => void act(() => apiFetch(`/organizations/${orgId}/members/${m.userId}/role`, { method: "PATCH", body: JSON.stringify({ role: e.target.value }) }), "Role updated — applies at the member's next authorization check.")}>
                    {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                </td>
                <td><Badge>{m.membershipStatus}</Badge></td>
                <td>{m.mfaEnrolled ? `Enrolled (${m.passkeyCount} passkey${m.passkeyCount === 1 ? "" : "s"})` : "Not enrolled"}</td>
                <td>{m.workspaceIds.length}</td>
                <td>{m.lastActive ? new Date(m.lastActive).toLocaleString() : "—"}</td>
                <td className="space-x-2">
                  {m.membershipStatus === "ACTIVE"
                    ? <button className="text-amber-300 hover:underline" onClick={() => void act(() => apiFetch(`/organizations/${orgId}/members/${m.userId}/status`, { method: "PATCH", body: JSON.stringify({ status: "SUSPENDED" }) }), "Member suspended and their sessions revoked.")}>Suspend</button>
                    : <button className="text-emerald-300 hover:underline" onClick={() => void act(() => apiFetch(`/organizations/${orgId}/members/${m.userId}/status`, { method: "PATCH", body: JSON.stringify({ status: "ACTIVE" }) }), "Member reactivated.")}>Reactivate</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {members.length === 0 && <p className="mt-3 text-sm text-slate-400">No members loaded.</p>}
      </Card>
      <Card>
        <h2 className="font-semibold">Invite a member</h2>
        <p className="mt-1 text-sm text-slate-400">Invitations are hashed, single-use and expire in 7 days. The raw token is shown once — share it through a trusted channel.</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <input className="rounded bg-slate-900 px-3 py-2 text-sm" placeholder="email" value={invite.email} onChange={(e) => setInvite({ ...invite, email: e.target.value })} />
          <select className="rounded bg-slate-900 px-2 py-2 text-sm" value={invite.role} onChange={(e) => setInvite({ ...invite, role: e.target.value })}>{ROLES.map((r) => <option key={r} value={r}>{r}</option>)}</select>
          <button className="rounded bg-sky-600 px-4 py-2 text-sm" onClick={() => void act(async () => { const res = await apiFetch<{ token: string }>(`/organizations/${orgId}/invitations`, { method: "POST", body: JSON.stringify(invite) }); setInviteToken(res.token); }, "Invitation created.")}>Create invitation</button>
        </div>
        {inviteToken && <p className="mt-3 break-all rounded bg-slate-900 p-3 text-xs text-amber-300">Invitation token (shown once): {inviteToken}<span className="mt-1 block text-slate-300">Send the invitee to this site&rsquo;s /invite page and give them this token — it creates their account. It expires in 7 days and works once.</span></p>}
      </Card>
    </div>
  );
}
