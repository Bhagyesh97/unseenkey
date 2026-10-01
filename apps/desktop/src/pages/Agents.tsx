import { useEffect, useState } from "react";
import { api, ago } from "../api";

const CLIENTS = [
  { id: "claude-code", name: "Claude Code", how: "Adds the server with `claude mcp add` (user scope)." },
  { id: "claude-desktop", name: "Claude Desktop", how: "Writes claude_desktop_config.json." },
  { id: "cursor", name: "Cursor", how: "Writes ~/.cursor/mcp.json." },
  { id: "windsurf", name: "Windsurf", how: "Writes Windsurf's mcp_config.json." },
];

export function Agents() {
  const [callers, setCallers] = useState<{ name: string; caller: string; last_seen_at: number | null }[]>([]);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = () => void api.callers().then(setCallers).catch(() => {});
  useEffect(load, []);

  const install = async (id: string) => {
    setBusy(id);
    setMsg(null);
    try {
      setMsg(await api.installMcp(id));
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(null);
      load();
    }
  };

  return (
    <div className="single">
      <header className="pane-head"><h2>AI agents</h2></header>
      <p>
        Agents get their own identity and can <b>use</b> your secrets by name through the <code>call_api</code> tool. They never see a value; each
        agent gets a handle per secret with the provider's least-privilege policy, and you can tighten or revoke it under Handles.
      </p>
      <div className="cards">
        {CLIENTS.map((c) => {
          const registered = callers.find((k) => k.name === c.id);
          return (
            <div key={c.id} className="card static">
              <div className="card-title">{c.name}{registered && <span className="chip ok">connected</span>}</div>
              <div className="muted small">{c.how}</div>
              {registered && <div className="muted small">last seen {ago(registered.last_seen_at)}</div>}
              <div className="actions">
                <button className="primary small" disabled={busy === c.id} onClick={() => void install(c.id)}>
                  {busy === c.id ? "Installing…" : registered ? "Reinstall" : "Install"}
                </button>
              </div>
            </div>
          );
        })}
      </div>
      {msg && <pre className="snippet">{msg}</pre>}
      <p className="muted small">After installing, restart the client and ask it to "list my unseenkey secrets".</p>
    </div>
  );
}
