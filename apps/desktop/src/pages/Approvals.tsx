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
        <div className="muted">
          Nothing is waiting. Requests appear here when a policy says a path needs your approval, or when an agent asks for access.
        </div>
      ) : (
        <ul className="rows">
          {approvals.map((a) => {
            const left = Math.max(0, Math.round((a.expires_at - now) / 1000));
            return (
              <li key={a.id} className="row static approval">
                <div className="row-main">
                  <span className="name">{a.caller}</span> wants to use <span className="chip">{a.secret}</span> via "{a.label}"
                </div>
                <div className="what">
                  {a.kind === "access" ? (
                    <>Access request: <b>{a.scope}</b></>
                  ) : (
                    <><b>{a.method} {a.host}{a.path}</b> <span className="muted">({a.scope})</span></>
                  )}
                </div>
                <div className="row-sub muted">{left}s left before it is refused automatically</div>
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
