import { useEffect, useState } from "react";
import { api, type Approval } from "../api";

export function Approvals({ approvals, onChange }: { approvals: Approval[]; onChange: () => void }) {
  const [now, setNow] = useState(Date.now());
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const decide = async (a: Approval, allow: boolean, remember: boolean) => {
    setErr(null);
    try {
      await api.decide(a.id, allow, remember);
    } catch (e) {
      setErr((e as Error).message);
    }
    onChange();
  };

  return (
    <div className="single">
      <header className="pane-head">
        <h2>Approvals</h2>
      </header>
      {err && <div className="err">{err}</div>}
      {approvals.length === 0 ? (
        <div className="empty">
          <div className="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="m9 12 2 2 4-4"/></svg></div>
          <b>Nothing is waiting</b>
          <p>Requests appear here when a policy says a path needs your approval, or when an agent asks for access or a new host. You also get a system notification.</p>
        </div>
      ) : (
        <ul className="rows">
          {approvals.map((a) => {
            const left = Math.max(0, Math.round((a.expires_at - now) / 1000));
            const total = Math.max(1, Math.round((a.expires_at - a.created_at) / 1000));
            return (
              <li key={a.id} className="row static approval">
                <div className="row-main">
                  <span className="chip info">{a.kind === "access" ? "access request" : "needs approval"}</span>
                  <span className="who"><b>{a.caller}</b> · {a.secret} via "{a.label}"</span>
                </div>
                <div className="what">
                  {a.kind === "access" ? (
                    <>Asks for <b>{a.scope}</b></>
                  ) : (
                    <><b>{a.method} {a.host}{a.path}</b> <span className="muted">({a.scope})</span></>
                  )}
                </div>
                <div className="timer"><i style={{ width: `${Math.min(100, (100 * left) / total)}%` }} /></div>
                <div className="row-sub muted">Refused automatically in {left}s</div>
                <div className="actions">
                  <button className="primary" onClick={() => void decide(a, true, false)}>Allow once</button>
                  {a.remember_key && <button onClick={() => void decide(a, true, true)}>Allow always for this rule</button>}
                  <button className="danger" onClick={() => void decide(a, false, false)}>Deny</button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
