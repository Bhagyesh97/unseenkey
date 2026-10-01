import { useEffect, useState } from "react";
import { api, ago, type SecretMeta } from "../api";

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
        {list.length === 0 && <div className="muted">No secrets yet. Add a key and it never needs to be pasted anywhere again.</div>}
        <ul className="rows">
          {list.map((s) => (
            <li key={s.secret_id} className={`row ${selected?.secret_id === s.secret_id ? "sel" : ""}`} onClick={() => setSelected(s)}>
              <div className="row-main">
                <span className="name">{s.name}</span>
                <span className="chip">{s.provider ?? s.kind}</span>
                {s.upstreams.length === 0 && <span className="chip warn">no host lock</span>}
                {s.allow_injection && <span className="chip warn">injection on</span>}
              </div>
              <div className="row-sub muted">{s.upstreams.join(", ") || "—"} · updated {ago(s.updated_at)}</div>
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
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<{ detected?: { display: string; note: string }; upstreams: string[]; name: string } | null>(null);

  const submit = async () => {
    setErr(null);
    setBusy(true);
    try {
      const r = await api.call<{ detected?: { display: string; note: string }; upstreams: string[]; name: string }>(
        "POST",
        "/v1/secrets",
        { name: name.trim(), value, notes: notes || null },
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
