import { useEffect, useState } from "react";
import { api, type Approval } from "../api";
import { shortPath, verbBase, who } from "../words";

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
          <b>Nothing is waiting for you</b>
          <p>When an AI tool wants to do something its rules say needs your OK, or asks for more access, it shows up here and as a notification.</p>
        </div>
      ) : (
        <ul className="rows">
          {approvals.map((a) => {
            const left = Math.max(0, Math.round((a.expires_at - now) / 1000));
            const total = Math.max(1, Math.round((a.expires_at - a.created_at) / 1000));
            return (
              <li key={a.id} className="row static approval">
                <div className="what">
                  {a.kind === "access" ? (
                    <><b>{who(a.caller, a.label)}</b> asks for more access to your <b>{a.secret}</b> key: {a.scope}.</>
                  ) : (
                    <><b>{who(a.caller, a.label)}</b> wants to use your <b>{a.secret}</b> key to {verbBase(a.method)} <b>{a.host}{shortPath(a.path)}</b>.</>
                  )}
                </div>
                <div className="timer"><i style={{ width: `${Math.min(100, (100 * left) / total)}%` }} /></div>
                <div className="row-sub muted">If you do not answer in {left} s, the answer is no.</div>
                <div className="actions">
                  <button className="primary" onClick={() => void decide(a, true, false)}>Allow this once</button>
                  {a.remember_key && <button onClick={() => void decide(a, true, true)}>Always allow this</button>}
                  <button className="danger" onClick={() => void decide(a, false, false)}>Don't allow</button>
                </div>
                <details className="tech">
                  <summary>Technical details</summary>
                  <dl className="kv small">
                    <dt>Tool</dt><dd><code>{a.caller}</code></dd>
                    <dt>Access</dt><dd>{a.label}</dd>
                    {a.method && <><dt>Request</dt><dd><code>{a.method} {a.host}{a.path}</code></dd></>}
                    <dt>Rule</dt><dd><code>{a.scope}</code></dd>
                  </dl>
                </details>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
