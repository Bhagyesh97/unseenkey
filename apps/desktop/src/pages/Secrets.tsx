import { useEffect, useState } from "react";
import { api, ago, type Preset, type SecretMeta } from "../api";

/** "api.example.com, *.other.com" or one per line → a clean list. */
function splitHosts(text: string): string[] {
  return text.split(/[\s,]+/).map((h) => h.trim()).filter(Boolean);
}

/** `tick` changes on every daemon event: reload in place, so a revealed
 * value, a selection or a half-filled form survives (a remount wiped them). */
export function Secrets({ tick }: { tick: number }) {
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
  }, [tick]);

  return (
    <div className="split">
      <section className="list-pane">
        <header className="pane-head">
          <h2>Keys</h2>
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

type Recognised = { provider: string; display: string; how: "shape" | "name"; note: string; testable: boolean };
type TestResult = { tested: boolean; ok: boolean | null; status: number | null; provider: string | null; message: string };

const CATEGORY_NAMES: Record<string, string> = {
  ai: "AI", payments: "Payments", hosting: "Hosting", database: "Databases", email: "Email", messaging: "Messaging",
  devtools: "Developer tools", productivity: "Productivity", crm: "CRM", auth: "Sign-in", backend: "Backend",
  maps: "Maps", social: "Social", other: "Other",
};

function TestBanner({ t }: { t: TestResult }) {
  const cls = t.ok === true ? "ok" : t.ok === false ? "error" : "info";
  const head = t.ok === true ? "It works." : t.ok === false ? "This key was refused." : t.tested ? "Tested, result unclear." : "Not tested.";
  return <div className={`banner ${cls}`}><b>{head}</b> {t.message}</div>;
}

/** Paste a key; Unseenkey works out the rest. Everything stays editable under "More options". */
function AddSecret({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [value, setValue] = useState("");
  const [name, setName] = useState("");
  const [nameTouched, setNameTouched] = useState(false);
  const [picked, setPicked] = useState<string>("");
  const [hosts, setHosts] = useState("");
  const [notes, setNotes] = useState("");
  const [more, setMore] = useState(false);
  const [search, setSearch] = useState("");
  const [presets, setPresets] = useState<Preset[]>([]);
  const [recog, setRecog] = useState<Recognised | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState<{ name: string; display: string | null; upstreams: string[]; test: TestResult | null } | null>(null);

  const [taken, setTaken] = useState<string[]>([]);
  useEffect(() => {
    void api.presets().then((p) => setPresets(p.filter((x) => x.id !== "generic"))).catch(() => {});
    void api.secrets().then((l) => setTaken(l.map((s) => s.name.toLowerCase()))).catch(() => {});
  }, []);
  // Recognise as the user types. Nothing is stored or sent off this computer.
  useEffect(() => {
    if (!value.trim()) {
      setRecog(null);
      return;
    }
    const id = setTimeout(() => {
      void api.call<{ recognised: Recognised | null }>("POST", "/v1/detect", { value: value.trim(), name: nameTouched ? name : null })
        .then((r) => setRecog(r.recognised))
        .catch(() => setRecog(null));
    }, 250);
    return () => clearTimeout(id);
  }, [value, name, nameTouched]);

  const provider = picked === "other" || picked === "__choose" ? "" : picked || recog?.provider || "";
  const preset = presets.find((p) => p.id === provider);
  const display = preset?.display ?? (provider ? recog?.display : null) ?? null;
  // A default name never clashes with a key you already have: openai, openai-2, …
  const defaultName = (() => {
    if (!provider) return "";
    let n = provider;
    for (let i = 2; taken.includes(n.toLowerCase()); i++) n = `${provider}-${i}`;
    return n;
  })();
  const effectiveName = (nameTouched ? name : "").trim() || defaultName;
  const needHosts = picked === "other";
  const canSave = !!value.trim() && !!effectiveName && (!!provider || (needHosts && splitHosts(hosts).length > 0));

  const save = async () => {
    setErr(null);
    setBusy(true);
    try {
      const body: Record<string, unknown> = { name: effectiveName, value: value.includes("\n") ? value : value.trim(), notes: notes || null };
      if (provider) body.provider = provider;
      const list = splitHosts(hosts);
      if (list.length) body.upstreams = list;
      const r = await api.call<{ id: string; name: string; upstreams: string[] }>("POST", "/v1/secrets", body);
      setValue("");
      let test: TestResult | null = null;
      if (provider) {
        try {
          test = await api.call<TestResult>("POST", `/v1/secrets/${r.id}/test`, {});
        } catch (e) {
          test = { tested: false, ok: null, status: null, provider: display, message: (e as Error).message };
        }
      }
      setDone({ name: r.name, display, upstreams: r.upstreams, test });
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (done) {
    return (
      <div className="form">
        <h2>Saved {done.name}</h2>
        {done.test && <TestBanner t={done.test} />}
        <p className="muted small">
          {done.display ? `${done.display} · ` : ""}It can only ever be sent to {done.upstreams.join(", ") || "the websites you set"}. The key is encrypted and is not shown again.
        </p>
        {done.test?.ok === false && <p className="small">Fix it by opening the key and choosing <b>Replace value</b>, or paste the right key again.</p>}
        <div className="actions"><button className="primary" onClick={onDone}>Done</button></div>
      </div>
    );
  }

  const q = search.trim().toLowerCase();
  const shown = presets.filter((p) => !q || p.display.toLowerCase().includes(q) || p.id.includes(q) || (p.category ?? "").includes(q));
  const groups = new Map<string, Preset[]>();
  for (const p of shown) {
    const c = p.category || "other";
    groups.set(c, [...(groups.get(c) ?? []), p]);
  }

  return (
    <div className="form">
      <h2>Add a key</h2>
      <label>Paste your key
        <textarea rows={2} autoFocus spellCheck={false} autoComplete="off" placeholder="Paste it here. It is encrypted on this computer and never shown again." value={value} onChange={(e) => setValue(e.target.value)} />
      </label>

      {value.trim() && (provider ? (
        <div className="recog">
          <span className="avatar small">{(display ?? provider).slice(0, 1).toUpperCase()}</span>
          <span>
            <b>{display ?? provider}</b>
            {picked ? "" : recog?.how === "name" ? " (from the name)" : recog?.note ? ` (${recog.note})` : ""}
          </span>
          <button className="link" onClick={() => { setSearch(""); setPicked("__choose"); }}>change</button>
        </div>
      ) : picked !== "other" ? (
        <div className="section">
          <h3>Which service is this key for?</h3>
          <input placeholder="Search: stripe, supabase, gemini…" value={search} onChange={(e) => setSearch(e.target.value)} />
          <div className="picker">
            {[...groups.entries()].map(([cat, list]) => (
              <div key={cat}>
                <div className="muted small picker-cat">{CATEGORY_NAMES[cat] ?? cat}</div>
                <div className="picker-grid">
                  {list.map((p) => (
                    <button key={p.id} className="picker-item" onClick={() => setPicked(p.id)} title={p.upstreams.join(", ")}>
                      <span className="avatar small">{p.display.slice(0, 1).toUpperCase()}</span>
                      <span>{p.display}</span>
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <button className="link" onClick={() => setPicked("other")}>It is not in the list</button>
        </div>
      ) : (
        <label>Which website is this key for?
          <input autoFocus placeholder="api.example.com" value={hosts} onChange={(e) => setHosts(e.target.value)} />
          <span className="muted small">The key will only ever be sent there. <button className="link" onClick={() => setPicked("__choose")}>Back to the list</button></span>
        </label>
      ))}

      <button className="link" onClick={() => setMore(!more)}>{more ? "Fewer options" : "More options"}</button>
      {more && (
        <>
          <label>Name<input placeholder={provider || "openai, stripe-live, …"} value={nameTouched ? name : ""} onChange={(e) => { setName(e.target.value); setNameTouched(true); }} /></label>
          {!needHosts && (
            <label>Allowed websites (empty: the provider's own)
              <input placeholder={preset?.upstreams.join(", ") ?? "api.example.com"} value={hosts} onChange={(e) => setHosts(e.target.value)} />
            </label>
          )}
          <label>Notes<input value={notes} onChange={(e) => setNotes(e.target.value)} /></label>
        </>
      )}
      {!effectiveName && value.trim() && needHosts && <p className="muted small">Give it a name under More options.</p>}
      {err && <div className="err">{err}</div>}
      <div className="actions">
        <button onClick={onCancel}>Cancel</button>
        <button className="primary" disabled={busy || !canSave} onClick={() => void save()}>{busy ? "Saving and testing…" : preset?.testable ? "Save and test" : "Save"}</button>
      </div>
      <p className="muted small">In a terminal: <code>usk add {effectiveName || "<name>"}</code></p>
    </div>
  );
}

function SecretDetail({ secret, onChange }: { secret: SecretMeta; onChange: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [replacing, setReplacing] = useState(false);
  const [testing, setTesting] = useState(false);
  const [test, setTest] = useState<TestResult | null>(null);
  const runTest = async () => {
    setTesting(true);
    setTest(null);
    try {
      setTest(await api.call<TestResult>("POST", `/v1/secrets/${secret.secret_id}/test`, {}));
    } catch (e) {
      setTest({ tested: false, ok: null, status: null, provider: null, message: (e as Error).message });
    } finally {
      setTesting(false);
    }
  };
  const [inProjects, setInProjects] = useState<string[] | null>(null);
  useEffect(() => {
    void api.projects()
      .then((ps) => setInProjects(ps.filter((p) => p.secrets.some((s) => s.id === secret.secret_id)).map((p) => p.name)))
      .catch(() => setInProjects(null));
  }, [secret.secret_id, secret.updated_at]);

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
        <dt>Allowed websites</dt><dd>{secret.upstreams.join(", ") || <span className="warn-text">none</span>}</dd>
        {inProjects && <><dt>Projects</dt><dd>{inProjects.length ? inProjects.join(", ") : <span className="muted">none (add it from a project's page)</span>}</dd></>}
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
      {test && <TestBanner t={test} />}
      {editing ? (
        <EditSettings secret={secret} onDone={async () => { setEditing(false); await onChange(); }} onCancel={() => setEditing(false)} />
      ) : replacing ? (
        <ReplaceValue secret={secret} onDone={async () => { setReplacing(false); await onChange(); }} onCancel={() => setReplacing(false)} />
      ) : (
        <div className="actions">
          <button onClick={() => setEditing(true)}>Edit settings</button>
          {secret.provider && <button disabled={testing} onClick={() => void runTest()}>{testing ? "Testing…" : "Test key"}</button>}
          {secret.kind !== "aws_credentials" && secret.kind !== "oauth2_client" && (
            <button onClick={() => setReplacing(true)}>Replace value</button>
          )}
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
      <label>Allowed websites (comma separated; the only places this key can ever be sent)
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

/** Paste a new or rotated key. The handles keep working; only the value changes. */
function ReplaceValue({ secret, onDone, onCancel }: { secret: SecretMeta; onDone: () => Promise<void>; onCancel: () => void }) {
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api.call("PATCH", `/v1/secrets/${secret.secret_id}`, { value: value.trim() });
      setValue("");
      await onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="section">
      <h3>Replace the value of {secret.name}</h3>
      <p className="muted small">Paste the new key, for example after you made a fresh one at the provider. Everything that uses {secret.name} keeps working and gets the new key on its next request.</p>
      <label>New value
        <input type="password" autoFocus autoComplete="off" spellCheck={false} value={value} onChange={(e) => setValue(e.target.value)} placeholder="Paste the new key" />
      </label>
      {err && <div className="err">{err}</div>}
      <div className="actions">
        <button className="primary" disabled={busy || !value.trim()} onClick={() => void save()}>{busy ? "Saving…" : "Save new value"}</button>
        <button onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}
