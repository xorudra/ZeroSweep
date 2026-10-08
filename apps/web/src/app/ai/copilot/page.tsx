"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Card, EmptyState } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";
import { AiResponseBlock, type AiResponseView } from "@/components/AiAssistant";

interface Message { id: string; role: string; content: string; answerOrigin?: string; confidence?: string }
interface Conversation { id: string; title?: string; contextType: string; updatedAt: string }

/**
 * Workspace Copilot chat (Prompt 21 §57). Scoped to the current
 * workspace and the signed-in user (§61). The copilot refuses
 * execution-shaped requests (§7/§120) — it is an analyst assistant.
 */
export default function CopilotPage() {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [lastResponse, setLastResponse] = useState<AiResponseView | null>(null);
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadConversations = useCallback(async () => {
    try { setConversations(await apiFetch<Conversation[]>("/ai/conversations")); } catch { setConversations([]); }
  }, []);
  useEffect(() => { void loadConversations(); }, [loadConversations]);

  const open = async (id: string) => {
    setActiveId(id); setLastResponse(null);
    try {
      const res = await apiFetch<{ messages: Message[] }>(`/ai/conversations/${id}`);
      setMessages(res.messages);
    } catch (e) { setError((e as Error).message); }
  };

  const send = async () => {
    if (!input.trim()) return;
    setBusy(true); setError(null);
    try {
      const res = await apiFetch<{ conversationId: string; response: AiResponseView }>(
        "/ai/chat",
        { method: "POST", body: JSON.stringify({ conversationId: activeId ?? undefined, message: input }) },
      );
      setInput("");
      setActiveId(res.conversationId);
      setLastResponse(res.response);
      const conv = await apiFetch<{ messages: Message[] }>(`/ai/conversations/${res.conversationId}`);
      setMessages(conv.messages);
      await loadConversations();
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <>
      <PageHeader eyebrow="AI Security Copilot" title="Workspace Copilot"
        body="Ask about this workspace's findings, assets and risk. Answers are grounded in stored records with citations. Execution requests are refused — the copilot proposes actions for the normal approval workflow instead." />
      <div className="grid gap-4 lg:grid-cols-[260px_1fr]">
        <Card title="Conversations">
          {conversations.length === 0
            ? <p className="text-sm text-slate-400">No conversations yet (retention applies per workspace AI policy).</p>
            : <ul className="space-y-1">
                {conversations.map((c) => (
                  <li key={c.id}>
                    <button onClick={() => void open(c.id)}
                      className={`w-full rounded-lg px-3 py-2 text-left text-sm ${c.id === activeId ? "bg-cyan-500/10 text-cyan-300" : "text-slate-300 hover:bg-slate-800/60"}`}>
                      {c.title ?? "Conversation"} <span className="text-slate-500">· {c.contextType}</span>
                    </button>
                  </li>
                ))}
              </ul>}
        </Card>
        <Card title="Chat">
          {messages.length === 0
            ? <EmptyState title="Start a conversation" body="Try: 'What are my highest-risk verified findings?' — the copilot answers from this workspace's records only." />
            : <div className="space-y-3">
                {messages.map((m) => (
                  <div key={m.id} className={`rounded-lg px-3 py-2 text-sm ${m.role === "USER" ? "bg-slate-800/60 text-slate-100" : "bg-slate-900 text-slate-300"}`}>
                    <p className="text-[11px] uppercase tracking-widest text-slate-500">{m.role}{m.answerOrigin ? ` · ${m.answerOrigin}` : ""}</p>
                    <p className="whitespace-pre-wrap">{m.content}</p>
                  </div>
                ))}
              </div>}
          {lastResponse && <div className="mt-4 border-t border-slate-800 pt-3"><AiResponseBlock response={lastResponse} /></div>}
          {error && <p className="mt-3 text-sm text-rose-300">{error}</p>}
          <div className="mt-4 flex gap-2">
            <input value={input} onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") void send(); }}
              placeholder="Ask about findings, risk, remediation…"
              className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100" />
            <button disabled={busy || !input.trim()} onClick={() => void send()}
              className="rounded-lg bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50">
              {busy ? "Thinking…" : "Send"}
            </button>
          </div>
        </Card>
      </div>
    </>
  );
}
