import { useEffect, useState } from "react";
import { api, ago, type Preset, type SecretMeta } from "../api";

/** "api.example.com, *.other.com" or one per line → a clean list. */
function splitHosts(text: string): string[] {
  return text.split(/[\s,]+/).map((h) => h.trim()).filter(Boolean);
}

export function Secrets() {
  const [list, setList] = useState<SecretMeta[]>([]);
  const [selected, setSelected] = useState<SecretMeta | null>(null);
  const [adding, setAdding] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    try {
      const l = await api.secrets();
      setList(l);
      if (selected) setSelected(l.find((s) => s.secret_id === selected.secret_id) ?? null);
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="split">
      <section className="list-pane">
        <header className="pane-head">
          <h2>Secrets</h2>
          <button className="primary" onClick={() => setAdding(true)}>
            + Add
          </button>
        </header>
        {err && <div className="err">{err}</div>}
        {list.length === 0 && (
          <div className="empty">
            <div className="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m11 12 9-9M15 6l3 3M18 3l3 3"/></svg></div>
            <b>No secrets yet</b>
            <p>Add a key once. From then on tools get handles, and the key never needs to be pasted anywhere again.</p>
            <button className="primary" onClick={() => setAdding(true)}>Add a secret</button>
          </div>
        )}
        <ul className="rows">
          {list.map((s) => (
            <li key={s.secret_id} className={`row ${selected?.secret_id === s.secret_id ? "sel" : ""}`} onClick={() => setSelected(s)}>
              <div className="with-avatar">
                <div className={`avatar ${s.provider ? "" : "none"}`}>{(s.provider ?? s.name).slice(0, 1).toUpperCase()}</div>
                <div>
                  <div className="row-main">
                    <span className="name">{s.name}</span>
                    <span className="chip">{s.provider ?? s.kind.replace(/_/g, " ")}</span>
                    {s.upstreams.length === 0 && <span className="chip warn">no host lock</span>}
                    {s.allow_injection && <span className="chip warn">injection on</span>}
                  </div>
                  <div className="row-sub muted">{s.upstreams.join(", ") || "—"} · updated {ago(s.updated_at)}</div>
                </div>
              </div>
            </li>
          ))}
        </ul>
      </section>
      <section className="detail-pane">
        {adding ? (
          <AddSecret onDone={() => { setAdding(false); void load(); }} onCancel={() => setAdding(false)} />
        ) : selected ? (
          <SecretDetail secret={selected} onChange={load} />
        ) : (
          <div className="muted">Select a secret, or add one.</div>
        )}
      </section>
    </div>
  );
}

function AddSecret({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [notes, setNotes] = useState("");
  const [hosts, setHosts] = useState("");
  const [provider, setProvider] = useState("");
  const [presets, setPresets] = useState<Preset[]>([]);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    void api.presets().then(setPresets).catch(() => {});
  }, []);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<{ detected?: { display: string; note: string }; upstreams: string[]; name: string } | null>(null);

  const submit = async () => {
    setErr(null);
    setBusy(true);
    try {
      const body: Record<string, unknown> = { name: name.trim(), value, notes: notes || null };
      if (provider) body.provider = provider;
      const list = splitHosts(hosts);
      if (list.length) body.upstreams = list;
      const r = await api.call<{ detected?: { display: string; note: string }; upstreams: string[]; name: string }>(
        "POST",
        "/v1/secrets",
        body,
      );
      setValue("");
      setResult(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (result) {
    return (
      <div className="form">
        <h2>Saved {result.name}</h2>
        {result.detected && (
          <p>
            Detected: <b>{result.detected.display}</b> {result.detected.note && `(${result.detected.note})`}
          </p>
        )}
        <p>{result.upstreams.length ? <>Locked to <b>{result.upstreams.join(", ")}</b>. It can only ever be sent there.</> : "No host lock yet: add an allowed host in the secret's settings before using it."}</p>
        <p className="muted">The value is encrypted and will not be shown again. Create a handle to use it.</p>
        <button className="primary" onClick={onDone}>Done</button>
      </div>
    );
  }

  return (
    <div className="form">
      <h2>Add a secret</h2>
      <label>Name<input autoFocus placeholder="openai, stripe-live, …" value={name} onChange={(e) => setName(e.target.value)} /></label>
      <label>Value<textarea rows={3} placeholder="Paste the key. It is detected, encrypted and never shown again." value={value} onChange={(e) => setValue(e.target.value)} /></label>
      <label>Notes (optional)<input value={notes} onChange={(e) => setNotes(e.target.value)} /></label>
      <label>Provider (optional; detected from the value when left empty)
        <select value={provider} onChange={(e) => setProvider(e.target.value)}>
          <option value="">detect</option>
          {presets.map((p) => <option key={p.id} value={p.id}>{p.display}{p.id === "generic" ? "" : ` — ${p.upstreams.join(", ")}`}</option>)}
        </select>
      </label>
      <label>Allowed host(s) (optional; the provider's hosts when left empty)
        <input placeholder="api.example.com, *.example.com" value={hosts} onChange={(e) => setHosts(e.target.value)} />
      </label>
      {err && <div className="err">{err}</div>}
      <div className="actions">
        <button onClick={onCancel}>Cancel</button>
        <button className="primary" disabled={busy || !name.trim() || !value} onClick={() => void submit()}>{busy ? "Saving…" : "Save"}</button>
      </div>
    </div>
  );
}

function SecretDetail({ secret, onChange }: { secret: SecretMeta; onChange: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);

  const patch = async (body: Record<string, unknown>) => {
    setBusy(true);
    setErr(null);
    try {
      await api.call("PATCH", `/v1/secrets/${secret.secret_id}`, body);
      await onChange();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const del = async () => {
    if (!confirm(`Delete ${secret.name}? Handles for it stop working immediately.`)) return;
    await patch({});
    await api.call("DELETE", `/v1/secrets/${secret.secret_id}`);
    await onChange();
  };
  const reveal = async () => {
    const reason = prompt("Why do you need to see the value? (recorded in the audit log)");
    if (reason === null) return;
    try {
      const r = await api.call<{ value: string }>("POST", `/v1/secrets/${secret.secret_id}/reveal`, { confirm: true, reason });
      setRevealed(r.value);
      setTimeout(() => setRevealed(null), 30_000);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  return (
    <div className="form">
      <h2>{secret.name}</h2>
      <dl className="kv">
        <dt>Type</dt><dd>{secret.kind}</dd>
        <dt>Provider</dt><dd>{secret.provider ?? "—"}</dd>
        <dt>Allowed hosts</dt><dd>{secret.upstreams.join(", ") || <span className="warn-text">none</span>}</dd>
        <dt>Versions</dt><dd>{secret.value_version}</dd>
        <dt>Notes</dt><dd>{secret.notes ?? "—"}</dd>
        <dt>Value</dt>
        <dd>
          {revealed ? (
            <code className="revealed">{revealed}</code>
          ) : (
            <>
              <span className="muted">hidden</span> <button className="link" onClick={() => void reveal()}>reveal for 30 s (audited)</button>
            </>
          )}
        </dd>
      </dl>
      {editing ? (
        <EditSettings secret={secret} onDone={async () => { setEditing(false); await onChange(); }} onCancel={() => setEditing(false)} />
      ) : (
        <div className="actions">
          <button onClick={() => setEditing(true)}>Edit settings</button>
        </div>
      )}
      <h3>Flags</h3>
      <label className="check">
        <input type="checkbox" checked={secret.allow_injection} disabled={busy} onChange={(e) => void patch({ allow_injection: e.target.checked })} />
        Allow <code>usk run</code> to inject this value into a program's environment (the program will see it)
      </label>
      <label className="check">
        <input type="checkbox" checked={secret.no_scrub} disabled={busy} onChange={(e) => void patch({ no_scrub: e.target.checked })} />
        Do not scrub this value from responses (only for false positives)
      </label>
      {err && <div className="err">{err}</div>}
      <div className="actions">
        <button className="danger" onClick={() => void del()}>Delete</button>
      </div>
    </div>
  );
}

/** Name, provider, allowed hosts, tags and notes: what `usk secret set` changes. */
function EditSettings({ secret, onDone, onCancel }: { secret: SecretMeta; onDone: () => Promise<void>; onCancel: () => void }) {
  const [presets, setPresets] = useState<Preset[]>([]);
  const [name, setName] = useState(secret.name);
  const [provider, setProvider] = useState(secret.provider ?? "");
  const [hosts, setHosts] = useState(secret.upstreams.join(", "));
  const [tags, setTags] = useState(secret.tags.join(", "));
  const [notes, setNotes] = useState(secret.notes ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    void api.presets().then(setPresets).catch(() => {});
  }, []);

  const chooseProvider = (id: string) => {
    setProvider(id);
    // A new provider brings its hosts, as the CLI does; the owner can still edit them.
    const p = presets.find((x) => x.id === id);
    if (p && p.upstreams.length) setHosts(p.upstreams.join(", "));
  };

  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      const body: Record<string, unknown> = {
        upstreams: splitHosts(hosts),
        tags: splitHosts(tags),
        notes: notes.trim() ? notes.trim() : null,
        provider: provider || null,
      };
      if (name.trim() && name.trim() !== secret.name) body.name = name.trim();
      await api.call("PATCH", `/v1/secrets/${secret.secret_id}`, body);
      await onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="form sub">
      <h3>Settings</h3>
      <label>Name<input value={name} onChange={(e) => setName(e.target.value)} /></label>
      <label>Provider
        <select value={provider} onChange={(e) => chooseProvider(e.target.value)}>
          <option value="">none (generic: any locked host, placeholders in the request)</option>
          {presets.map((p) => <option key={p.id} value={p.id}>{p.display}</option>)}
        </select>
      </label>
      <label>Allowed hosts (comma separated; the only places this secret can ever be sent)
        <input placeholder="api.example.com, *.example.com" value={hosts} onChange={(e) => setHosts(e.target.value)} />
      </label>
      {splitHosts(hosts).length === 0 && <div className="err">With no host the secret cannot be used anywhere. Add at least one.</div>}
      <label>Tags (comma separated)<input value={tags} onChange={(e) => setTags(e.target.value)} /></label>
      <label>Notes<input value={notes} onChange={(e) => setNotes(e.target.value)} /></label>
      <p className="muted small">Hosts are normalised: <code>https://api.example.com/v1/</code> becomes <code>api.example.com</code>. Handles keep their own policies; a handle's hosts can only narrow these.</p>
      {err && <div className="err">{err}</div>}
      <div className="actions">
        <button onClick={onCancel} disabled={busy}>Cancel</button>
        <button className="primary" disabled={busy || splitHosts(hosts).length === 0} onClick={() => void save()}>{busy ? "Saving…" : "Save settings"}</button>
      </div>
    </div>
  );
}
