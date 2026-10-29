import { useEffect, useState } from "react";
import { api, ago, RESPONSES, type AnomalyResponse, type HandleCreated, type HandleView, type Preset, type SecretMeta } from "../api";
import { who } from "../words";

// A daemon older than the incidents feature sends no status; read it as normal.
const stateOf = (h: HandleView) => h.status?.state ?? "normal";

function standing(h: HandleView): { text: string; cls: string } | null {
  if (h.canary) return { text: "canary", cls: "warn" };
  const st = h.status;
  switch (stateOf(h)) {
    case "throttled":
      return { text: `throttled until ${st && "until" in st ? new Date(st.until).toLocaleTimeString() : "later"}`, cls: "warn" };
    case "approval_required":
      return { text: "asks before every request", cls: "warn" };
    case "paused":
      return { text: "paused", cls: "off" };
    default:
      return null;
  }
}

/** `tick` changes on every daemon event: reload in place, so a revealed
 * value, a selection or a half-filled form survives (a remount wiped them). */
export function Handles({ tick }: { tick: number }) {
  const [handles, setHandles] = useState<HandleView[]>([]);
  const [creating, setCreating] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    try {
      setHandles(await api.handles());
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);

  const forget = async (h: HandleView, rule: string | null) => {
    await api.call("POST", `/v1/handles/${h.id}/forget`, { rule });
    await load();
  };
  const revoke = async (h: HandleView) => {
    if (!confirm(`Revoke "${h.label}"? Anything using it fails immediately.`)) return;
    await api.call("DELETE", `/v1/handles/${h.id}`);
    await load();
  };
  const resume = async (h: HandleView) => {
    await api.call("POST", `/v1/handles/${h.id}/resume`, {});
    await load();
  };
  const setResponse = async (h: HandleView, on_anomaly: AnomalyResponse) => {
    await api.call("PATCH", `/v1/handles/${h.id}`, { on_anomaly });
    await load();
  };

  return (
    <div className="split">
      <section className="list-pane">
        <header className="pane-head">
          <h2>Agent access</h2>
          <button className="primary" onClick={() => setCreating(true)}>+ Give access</button>
        </header>
        <p className="muted small">Who can use which key, and what they may do with it. Tools get a stand-in instead of the real key; it only works through this computer, only on the key's websites, and only within these rules.</p>
        {err && <div className="err">{err}</div>}
        {handles.length === 0 && (
          <div className="empty">
            <div className="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="7" width="18" height="10" rx="3"/><circle cx="8" cy="12" r="1.6"/><path d="M12 12h6"/></svg></div>
            <b>No access given yet</b>
            <p>AI tools get access by themselves the first time they use a key. To give a script or another person access, create it here and copy the settings it shows.</p>
            <button className="primary" onClick={() => setCreating(true)}>Give access</button>
          </div>
        )}
        <ul className="rows">
          {handles.map((h) => (
            <li key={h.id} className="row static">
              <div className="row-main">
                <span className="name">{h.policy.callers?.length === 1 ? who(h.policy.callers[0]) : h.label}</span>
                <span className="muted small">uses</span>
                <span className="chip">{h.secret}</span>
                {h.project && <span className="chip info">{h.project}</span>}
                <span className={`chip ${h.revoked_at ? "off" : h.active ? "ok" : "warn"}`}>{h.revoked_at ? "removed" : h.active ? "working" : "expired"}</span>
                {standing(h) && <span className={`chip ${standing(h)!.cls}`}>{standing(h)!.text}</span>}
              </div>
              <div className="row-sub muted">Used {h.use_count} {h.use_count === 1 ? "time" : "times"} · last {ago(h.last_used_at)}{h.policy.callers?.length === 1 && who(h.policy.callers[0]) !== h.label ? ` · “${h.label}”` : ""}</div>
              {h.last_anomaly && !h.revoked_at && (
                <div className="err">
                  {h.last_anomaly.kind === "canary" ? "Canary tripped" : "Unusual activity"} {ago(h.last_anomaly.at)}: {h.last_anomaly.detail}.
                  {stateOf(h) !== "normal" && <> <button className="small" onClick={() => void resume(h)}>Back to normal</button></>}
                  {stateOf(h) === "normal" && <> <button className="link" onClick={() => void resume(h)}>dismiss</button></>}
                </div>
              )}
              {h.canary ? (
                <p className="muted small">A tripwire: it never works. Plant it where only an intruder would find it; any use is an incident.</p>
              ) : (
                <details className="tech">
                  <summary>What it may do: {h.policy_explanation.split("\n")[0]}</summary>
                  <pre className="policy">{h.policy_explanation}</pre>
                  <p className="muted small">Label <code>{h.label}</code> · id <code>{h.id}</code>{h.policy.callers?.length ? <> · only for <code>{h.policy.callers.join(", ")}</code></> : null}</p>
                </details>
              )}
              {!h.revoked_at && (
                <div className="row-main">
                  <span className="muted small">{h.canary ? "When it is used:" : "On unusual activity:"}</span>
                  <select value={h.on_anomaly ?? "throttle"} onChange={(e) => void setResponse(h, e.target.value as AnomalyResponse)}>
                    {RESPONSES.map((r) => <option key={r.id} value={r.id} title={r.hint}>{r.label}</option>)}
                  </select>
                </div>
              )}
              {h.remembered.length > 0 && (
                <div className="row-main">
                  <span className="muted small">Allowed always:</span>
                  {h.remembered.map((r) => (
                    <span key={r} className="chip">
                      {r} <button className="link" title="Ask again for this rule" onClick={() => void forget(h, r)}>×</button>
                    </span>
                  ))}
                  <button className="small" onClick={() => void forget(h, null)}>Forget all</button>
                </div>
              )}
              {!h.revoked_at && (
                <div className="actions right">
                  <button className="danger small" onClick={() => void revoke(h)}>Remove access</button>
                </div>
              )}
            </li>
          ))}
        </ul>
      </section>
      <section className="detail-pane">
        {creating ? <CreateHandle onDone={() => { setCreating(false); void load(); }} onCancel={() => setCreating(false)} /> : <div className="empty muted">“Give access” makes a stand-in key for a script, a server or a person, with its own rules and an end date.</div>}
      </section>
    </div>
  );
}

function CreateHandle({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [presets, setPresets] = useState<Preset[]>([]);
  const [secret, setSecret] = useState("");
  const [policy, setPolicy] = useState("");
  const [label, setLabel] = useState("");
  const [days, setDays] = useState<string>("");
  const [camouflage, setCamouflage] = useState(false);
  const [capDay, setCapDay] = useState<string>("");
  const [capMinute, setCapMinute] = useState<string>("");
  const [canary, setCanary] = useState(false);
  const [response, setResponse] = useState<AnomalyResponse | "">("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [created, setCreated] = useState<HandleCreated | null>(null);
  const [shell, setShell] = useState<"powershell" | "sh" | "dotenv">(navigator.userAgent.includes("Windows") ? "powershell" : "sh");

  useEffect(() => {
    void api.secrets().then((s) => { setSecrets(s); if (s[0]) setSecret(s[0].name); });
    void api.presets().then(setPresets);
  }, []);

  const meta = secrets.find((s) => s.name === secret);
  const preset = presets.find((p) => p.id === meta?.provider);

  const submit = async () => {
    setErr(null);
    setBusy(true);
    try {
      const body: Record<string, unknown> = { secret, label: label || null };
      if (policy) body.preset_policy = `${preset!.id}:${policy}`;
      if (days) body.expires_in_days = Number(days);
      if (camouflage && preset?.camouflage) body.camouflage = true;
      if (capDay) body.cap_per_day = Number(capDay);
      if (capMinute) body.cap_per_minute = Number(capMinute);
      if (canary) body.canary = true;
      if (response) body.on_anomaly = response;
      setCreated(await api.call<HandleCreated>("POST", "/v1/handles", body));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (created) {
    const lines = Object.entries(created.env).map(([k, v]) =>
      shell === "powershell" ? `$env:${k} = "${v}"` : shell === "sh" ? `export ${k}=${v}` : `${k}=${v}`,
    );
    return (
      <div className="form">
        <h2>{created.canary ? "Canary created" : "Handle created"}</h2>
        {created.canary ? (
          <p>This is shown once. It never works: put it where only an intruder would find it (a .env.example, an old repo, a notes page). The moment anyone uses it, the response is "{RESPONSES.find((r) => r.id === created.on_anomaly)?.label.toLowerCase()}" and the event appears under Activity.</p>
        ) : (
          <p>This is shown once. It is safe to paste into tools: it only works from this computer, only for {created.policy.upstreams?.join(", ") || "its host"}, and only within this policy.</p>
        )}
        <code className="handle">{created.handle}</code>
        {!created.canary && <pre className="policy">{created.policy_explanation}</pre>}
        {lines.length > 0 && (
          <>
            <div className="row-main">
              <b>Environment for the SDK</b>
              <select value={shell} onChange={(e) => setShell(e.target.value as typeof shell)}>
                <option value="powershell">PowerShell</option>
                <option value="sh">bash / zsh</option>
                <option value="dotenv">.env</option>
              </select>
              <button className="small" onClick={() => void navigator.clipboard.writeText(lines.join("\n"))}>Copy</button>
            </div>
            <pre className="snippet">{lines.join("\n")}</pre>
          </>
        )}
        <button className="primary" onClick={onDone}>Done</button>
      </div>
    );
  }

  return (
    <div className="form">
      <h2>Create a handle</h2>
      <label>Secret
        <select value={secret} onChange={(e) => { setSecret(e.target.value); setPolicy(""); }}>
          {secrets.map((s) => <option key={s.secret_id} value={s.name}>{s.name}{s.provider ? ` (${s.provider})` : ""}</option>)}
        </select>
      </label>
      <label>Label<input placeholder="e.g. cursor on laptop" value={label} onChange={(e) => setLabel(e.target.value)} /></label>
      {preset ? (
        <>
          <div className="label">What may it do?</div>
          <div className="cards">
            {preset.policies.map((p) => (
              <button key={p.id} className={`card ${policy === p.id ? "sel" : ""}`} onClick={() => setPolicy(p.id)}>
                <div className="card-title">{p.display}{p.recommended && <span className="chip ok">recommended</span>}</div>
                <pre className="policy small">{p.explanation}</pre>
              </button>
            ))}
          </div>
        </>
      ) : (
        <p className="muted small">This secret has no provider preset; the handle allows any request to its locked hosts.</p>
      )}
      <label>Expires after (days, optional)<input type="number" min={1} value={days} onChange={(e) => setDays(e.target.value)} /></label>
      {!canary && (
        <div className="row-main">
          <label>Cap per day<input type="number" min={1} placeholder="unlimited" value={capDay} onChange={(e) => setCapDay(e.target.value)} /></label>
          <label>Cap per minute<input type="number" min={1} placeholder="unlimited" value={capMinute} onChange={(e) => setCapMinute(e.target.value)} /></label>
        </div>
      )}
      <label>{canary ? "When it is used" : "On unusual activity (a burst of refused requests)"}
        <select value={response} onChange={(e) => setResponse(e.target.value as AnomalyResponse | "")}>
          <option value="">{canary ? "Lock the vault (default)" : "Throttle (default)"}</option>
          {RESPONSES.map((r) => <option key={r.id} value={r.id}>{r.label}: {r.hint}</option>)}
        </select>
      </label>
      <label className="check">
        <input type="checkbox" checked={canary} onChange={(e) => setCanary(e.target.checked)} />
        Make it a canary: a handle that never works, to plant where only an intruder would find it
      </label>
      {preset?.camouflage && (
        <label className="check">
          <input type="checkbox" checked={camouflage} onChange={(e) => setCamouflage(e.target.checked)} />
          Make it look like a real {preset.display} key (only for tools that reject other formats; it is still just a handle)
        </label>
      )}
      {err && <div className="err">{err}</div>}
      <div className="actions">
        <button onClick={onCancel}>Cancel</button>
        <button className="primary" disabled={busy || !secret || (!!preset && !policy && !canary)} onClick={() => void submit()}>{busy ? "Creating…" : "Create"}</button>
      </div>
    </div>
  );
}
