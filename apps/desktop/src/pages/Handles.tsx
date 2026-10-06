import { useEffect, useState } from "react";
import { api, ago, type HandleCreated, type HandleView, type Preset, type SecretMeta } from "../api";

export function Handles() {
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
  }, []);

  const forget = async (h: HandleView, rule: string | null) => {
    await api.call("POST", `/v1/handles/${h.id}/forget`, { rule });
    await load();
  };
  const revoke = async (h: HandleView) => {
    if (!confirm(`Revoke "${h.label}"? Anything using it fails immediately.`)) return;
    await api.call("DELETE", `/v1/handles/${h.id}`);
    await load();
  };

  return (
    <div className="split">
      <section className="list-pane">
        <header className="pane-head">
          <h2>Handles</h2>
          <button className="primary" onClick={() => setCreating(true)}>+ Create</button>
        </header>
        <p className="muted small">A handle is what you give a tool instead of the key. It only works through this computer, for one host, within its policy.</p>
        {err && <div className="err">{err}</div>}
        <ul className="rows">
          {handles.map((h) => (
            <li key={h.id} className="row static">
              <div className="row-main">
                <span className="name">{h.label}</span>
                <span className="chip">{h.secret}</span>
                <span className={`chip ${h.revoked_at ? "off" : h.active ? "ok" : "warn"}`}>{h.revoked_at ? "revoked" : h.active ? "active" : "expired"}</span>
                {h.policy.callers?.length ? <span className="chip">{h.policy.callers.join(", ")}</span> : null}
              </div>
              <div className="row-sub muted">{h.use_count} uses · last {ago(h.last_used_at)}</div>
              <pre className="policy">{h.policy_explanation}</pre>
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
                  <button className="danger small" onClick={() => void revoke(h)}>Revoke</button>
                </div>
              )}
            </li>
          ))}
        </ul>
      </section>
      <section className="detail-pane">
        {creating ? <CreateHandle onDone={() => { setCreating(false); void load(); }} onCancel={() => setCreating(false)} /> : <div className="muted">Create a handle to get the environment variables for a tool.</div>}
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
        <h2>Handle created</h2>
        <p>This is shown once. It is safe to paste into tools: it only works from this computer, only for {created.policy.upstreams?.join(", ") || "its host"}, and only within this policy.</p>
        <code className="handle">{created.handle}</code>
        <pre className="policy">{created.policy_explanation}</pre>
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
      {preset?.camouflage && (
        <label className="check">
          <input type="checkbox" checked={camouflage} onChange={(e) => setCamouflage(e.target.checked)} />
          Make it look like a real {preset.display} key (only for tools that reject other formats; it is still just a handle)
        </label>
      )}
      {err && <div className="err">{err}</div>}
      <div className="actions">
        <button onClick={onCancel}>Cancel</button>
        <button className="primary" disabled={busy || !secret || (!!preset && !policy)} onClick={() => void submit()}>{busy ? "Creating…" : "Create"}</button>
      </div>
    </div>
  );
}
