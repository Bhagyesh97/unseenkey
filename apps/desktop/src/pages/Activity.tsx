import { useEffect, useState } from "react";
import { api, fmtTime, type AuditEvent } from "../api";

const KINDS = ["", "use", "deny", "anomaly", "canary_tripped", "egress_blocked", "approval_required", "approval_decided", "reveal", "inject", "handle_created", "handle_revoked", "handle_resumed", "secret_created", "unlock", "lock", "audit_tampered"];

function describe(e: AuditEvent): string {
  const b = e.body as Record<string, string | number | string[] | undefined>;
  switch (e.kind) {
    case "use":
      return `${b.method} ${b.host}${b.path} → ${b.status} (${b.secret} via ${b.label}${b.caller ? `, ${b.caller}` : ""})`;
    case "deny":
      return `${b.method} ${b.host}${b.path} refused: ${b.reason} (${b.label})`;
    case "egress_blocked":
      return `request via ${b.label} carried ${(b.leaked as string[])?.join(", ")} → blocked`;
    case "approval_required":
      return `${b.caller} asked to ${b.method} ${b.path} (${b.scope})`;
    case "approval_decided":
      return `${b.allowed ? "allowed" : "refused"} ${b.method ?? ""} ${b.path ?? ""} for ${b.caller}`;
    case "reveal":
      return `value revealed${b.reason ? `: ${b.reason}` : ""}`;
    case "inject":
      return `${b.name} injected as ${b.var} into: ${b.command}`;
    case "anomaly":
      return `${b.label}: ${b.detail} → ${b.response}`;
    case "canary_tripped":
      return `${b.detail} → ${b.response}`;
    case "handle_resumed":
      return `handle ${b.id} back to normal`;
    case "lock":
      return `vault locked${b.reason ? ` (${b.reason})` : ""}`;
    default:
      return JSON.stringify(e.body);
  }
}

type VerifyReport = {
  ok: boolean;
  rows: number;
  first_broken: number | null;
  contiguous: boolean;
  head: { state: "unchecked" | "missing" | "verified" | "forged" } | { state: "mismatch"; head_seq: number; last_seq: number };
  head_checked: boolean;
};

export function Activity() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [kind, setKind] = useState("");
  const [verify, setVerify] = useState<VerifyReport | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = async (k = kind) => {
    try {
      const all = await api.audit(1, k || null, 1000);
      setEvents(all.slice(-200).reverse());
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const doVerify = async () => {
    setVerify(await api.call<VerifyReport>("GET", "/v1/audit/verify"));
  };

  const verifyText = (v: VerifyReport) => {
    if (v.ok) {
      if (v.head_checked) return `Audit log intact: ${v.rows} events, hash chain and keyed head verified.`;
      return `Audit log intact: ${v.rows} events, hash chain verified. Unlock the vault to also rule out a log cut short.`;
    }
    if (v.first_broken !== null) return `TAMPERED: first broken sequence ${v.first_broken}`;
    if (v.head.state === "forged") return "TAMPERED: the keyed head was rewritten without the vault key";
    if (v.head.state === "mismatch") return `TAMPERED: the log ends at event ${v.head.last_seq} where the keyed head says ${v.head.head_seq}`;
    return "TAMPERED: the keyed head does not match the log";
  };

  return (
    <div className="single">
      <header className="pane-head">
        <h2>Activity</h2>
        <div className="row-main">
          <select value={kind} onChange={(e) => { setKind(e.target.value); void load(e.target.value); }}>
            {KINDS.map((k) => <option key={k} value={k}>{k || "all kinds"}</option>)}
          </select>
          <button onClick={() => void load()}>Refresh</button>
          <button onClick={() => void doVerify()}>Verify log</button>
        </div>
      </header>
      {verify && (
        <div className={`banner ${verify.ok ? "ok" : "error"}`}>
          {verifyText(verify)}
        </div>
      )}
      {err && <div className="err">{err}</div>}
      {events.length === 0 && !err && (
        <div className="empty">
          <b>No events{kind ? ` of kind "${kind}"` : " yet"}</b>
          <p>Every call through the broker, every refusal and every change lands here, hash-chained.</p>
        </div>
      )}
      <table className="table" style={events.length === 0 ? { display: "none" } : undefined}>
        <thead><tr><th>#</th><th>When</th><th>Kind</th><th>Details</th></tr></thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.seq} className={e.kind === "deny" || e.kind === "egress_blocked" || e.kind === "anomaly" || e.kind === "canary_tripped" ? "bad" : ""}>
              <td className="mono">{e.seq}</td>
              <td className="mono">{fmtTime(e.ts)}</td>
              <td><span className={`chip kind-${e.kind}`}>{e.kind.replace(/_/g, " ")}</span></td>
              <td>{describe(e)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
