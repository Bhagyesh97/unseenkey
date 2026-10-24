import { useEffect, useState } from "react";
import { api, ago, folderName, pickFolder, type EnvFinding, type Project, type SecretMeta, type Status } from "../api";
import type { UpdateInfo } from "../updates";

type Caller = { name: string; caller: string; last_seen_at: number | null };

const AI_TOOLS = [
  { id: "claude-code", name: "Claude Code" },
  { id: "cursor", name: "Cursor" },
  { id: "claude-desktop", name: "Claude Desktop" },
  { id: "windsurf", name: "Windsurf" },
];

/** `tick` changes on every daemon event: reload in place (see Secrets). */
export function Projects({ tick, status, update, onUpdate, onSettings }: {
  tick: number;
  status: Status;
  update: UpdateInfo | null;
  onUpdate: () => void;
  onSettings: () => void;
}) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [callers, setCallers] = useState<Caller[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [protecting, setProtecting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    try {
      setProjects(await api.projects());
      setCallers(await api.callers());
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);

  const current = projects.find((p) => p.id === selected) ?? null;

  return (
    <div className="split">
      <section className="list-pane">
        <header className="pane-head">
          <h2>Projects</h2>
          <button className="primary" onClick={() => { setSelected(null); setProtecting(true); }}>+ Protect a project</button>
        </header>
        <Health status={status} callers={callers} update={update} onUpdate={onUpdate} onSettings={onSettings} onConnected={load} />
        {err && <div className="err">{err}</div>}
        {projects.length === 0 ? (
          <div className="empty">
            <p><b>Keep each app's keys together.</b></p>
            <p className="muted small">
              Pick the folder of an app you are building. Unseenkey finds the API keys in its <code>.env</code>, locks them in the vault and leaves
              harmless stand-ins behind. AI tools working in that folder then see only that app's keys.
            </p>
          </div>
        ) : (
          <ul className="rows">
            {projects.map((p) => (
              <li key={p.id} className={`row ${selected === p.id ? "sel" : ""}`} onClick={() => { setProtecting(false); setSelected(p.id); }}>
                <div className="row-main">
                  <span className="name">{p.name}</span>
                  {p.secrets.length === 0 ? <span className="chip warn">no keys yet</span> : <span className="chip">{p.secrets.length} {p.secrets.length === 1 ? "key" : "keys"}</span>}
                </div>
                <div className="row-sub muted">{p.paths[0] ?? "no folder"}</div>
                <Usage p={p} />
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="detail-pane">
        {protecting ? (
          <Protect
            callers={callers}
            onDone={async (id) => { setProtecting(false); await load(); if (id) setSelected(id); }}
            onCancel={() => setProtecting(false)}
          />
        ) : current ? (
          <ProjectDetail key={current.id} project={current} onChange={load} onDeleted={async () => { setSelected(null); await load(); }} />
        ) : (
          <div className="empty muted">
            {projects.length ? "Select a project to see its keys, folders and daily limit." : "Start with “Protect a project”."}
          </div>
        )}
      </section>
    </div>
  );
}

function Usage({ p }: { p: Project }) {
  if (p.cap_per_day == null) {
    return <div className="row-sub muted small">{p.requests_today} requests today · no daily limit</div>;
  }
  const pct = Math.min(100, Math.round((100 * p.requests_today) / p.cap_per_day));
  return (
    <div className="row-sub small">
      <span className={pct >= 100 ? "warn-text" : "muted"}>{p.requests_today} of {p.cap_per_day} requests today</span>
      <div className="timer"><i style={{ width: `${pct}%`, background: pct >= 100 ? "var(--warn)" : undefined }} /></div>
    </div>
  );
}

/** Is everything working? One line each, with the fix one click away. */
function Health({ status, callers, update, onUpdate, onSettings, onConnected }: {
  status: Status;
  callers: Caller[];
  update: UpdateInfo | null;
  onUpdate: () => void;
  onSettings: () => void;
  onConnected: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const seen = callers.filter((c) => AI_TOOLS.some((t) => t.id === c.name));
  const connect = async () => {
    setBusy(true);
    setMsg(null);
    try {
      setMsg(await api.installMcp("claude-code"));
      await onConnected();
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const tool = (c: Caller) => AI_TOOLS.find((t) => t.id === c.name)?.name ?? c.name;
  return (
    <div className="health">
      <div className="health-item">
        <span className="dot ok" />
        <span>Vault unlocked{status.daemon ? ` · ${status.daemon.secrets ?? 0} keys` : ""}</span>
      </div>
      <div className="health-item">
        <span className={`dot ${seen.length ? "ok" : "warn"}`} />
        {seen.length ? (
          <span>{seen.map((c) => `${tool(c)} (seen ${ago(c.last_seen_at)})`).join(", ")}</span>
        ) : (
          <>
            <span>No AI tool connected</span>
            <button className="link" disabled={busy} onClick={() => void connect()}>{busy ? "Connecting…" : "Connect Claude Code"}</button>
          </>
        )}
      </div>
      <div className="health-item">
        <span className={`dot ${update ? "warn" : "ok"}`} />
        {update ? (
          <>
            <span>Version {update.version} is available</span>
            <button className="link" onClick={onUpdate}>Install</button>
          </>
        ) : (
          <>
            <span>App {status.app_version}</span>
            <button className="link" onClick={onSettings}>Check for updates</button>
          </>
        )}
      </div>
      {msg && <div className="muted small">{msg}</div>}
    </div>
  );
}

type Step =
  | { at: "folder" }
  | { at: "scan"; dir: string; project: Project; files: { path: string; found: EnvFinding[] }[] }
  | { at: "done"; project: Project; moved: number; notes: string[] };

/** Folder → project → keys moved out of .env → AI tool connected. */
function Protect({ callers, onDone, onCancel }: { callers: Caller[]; onDone: (id: string | null) => Promise<void>; onCancel: () => void }) {
  const [step, setStep] = useState<Step>({ at: "folder" });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const choose = async () => {
    setErr(null);
    const dir = await pickFolder("Choose your project folder");
    if (!dir) return;
    setBusy(true);
    try {
      const project = (await api.projectForDir(dir)) ?? (await api.createProject({ paths: [dir] }));
      const paths = await api.envFiles(dir);
      const files = [];
      for (const path of paths) files.push({ path, found: await api.guardScan(path) });
      setStep({ at: "scan", dir, project, files });
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const move = async () => {
    if (step.at !== "scan") return;
    setBusy(true);
    setErr(null);
    try {
      let moved = 0;
      const notes: string[] = [];
      for (const f of step.files) {
        const n = f.found.filter((x) => x.fixable).length;
        if (!n) continue;
        notes.push(await api.guardFix(f.path, step.project.id));
        moved += n;
      }
      const project = (await api.projects()).find((p) => p.id === step.project.id) ?? step.project;
      setStep({ at: "done", project, moved, notes });
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (step.at === "folder") {
    return (
      <div className="form">
        <h2>Protect a project</h2>
        <ol className="steps">
          <li className="now">Choose the folder of the app you are building.</li>
          <li>Unseenkey finds the API keys in its <code>.env</code> files and locks them in the vault.</li>
          <li>The file keeps working: each key is replaced by a stand-in that only works through Unseenkey.</li>
        </ol>
        {err && <div className="err">{err}</div>}
        <div className="actions">
          <button className="primary" disabled={busy} onClick={() => void choose()}>{busy ? "Looking…" : "Choose folder…"}</button>
          <button onClick={onCancel}>Cancel</button>
        </div>
      </div>
    );
  }

  if (step.at === "scan") {
    const fixable = step.files.flatMap((f) => f.found.filter((x) => x.fixable).map((x) => ({ ...x, file: f.path })));
    const other = step.files.flatMap((f) => f.found.filter((x) => !x.fixable).map((x) => ({ ...x, file: f.path })));
    return (
      <div className="form">
        <h2>{step.project.name}</h2>
        <p className="muted small">{step.dir}</p>
        {step.files.length === 0 ? (
          <div className="banner info">No <code>.env</code> file here. The project is set up; add keys to it from its page.</div>
        ) : fixable.length === 0 ? (
          <div className="banner ok">No real keys left in {step.files.map((f) => folderName(f.path)).join(", ")}. Nothing to move.</div>
        ) : (
          <>
            <h3>Keys found</h3>
            <ul className="rows">
              {fixable.map((x) => (
                <li key={`${x.file}:${x.line}`} className="row static">
                  <div className="row-main"><span className="name">{x.key}</span><span className="chip info">{x.detected}</span></div>
                  <div className="row-sub muted">{folderName(x.file)}, line {x.line}: will move into the vault</div>
                </li>
              ))}
            </ul>
          </>
        )}
        {other.length > 0 && (
          <p className="muted small">
            Left alone (no known provider, or already a stand-in): {other.map((x) => x.key).join(", ")}. You can add those by hand under Keys.
          </p>
        )}
        {err && <div className="err">{err}</div>}
        <div className="actions">
          {fixable.length > 0 ? (
            <button className="primary" disabled={busy} onClick={() => void move()}>
              {busy ? "Moving…" : `Move ${fixable.length} ${fixable.length === 1 ? "key" : "keys"} into the vault`}
            </button>
          ) : (
            <button className="primary" onClick={() => void onDone(step.project.id)}>Open project</button>
          )}
          <button onClick={() => void onDone(step.project.id)}>{fixable.length ? "Skip" : "Close"}</button>
        </div>
      </div>
    );
  }

  const connected = callers.some((c) => AI_TOOLS.some((t) => t.id === c.name));
  return (
    <div className="form">
      <h2>{step.project.name} is protected</h2>
      <div className="banner ok">
        {step.moved > 0
          ? `${step.moved} ${step.moved === 1 ? "key is" : "keys are"} now in the vault. Your .env holds stand-ins, so the app keeps working through Unseenkey.`
          : "The project is set up."}
      </div>
      {step.notes.map((n) => <p key={n} className="muted small">{n}</p>)}
      <h3>Next</h3>
      <ul className="steps">
        <li>Restart your app so it reads the updated <code>.env</code>.</li>
        <li>{connected ? "Your AI tool is connected. " : "Connect your AI tool (Claude Code, Cursor) on the Agents page. "}When it works in this folder it sees only this project's keys.</li>
      </ul>
      <div className="actions">
        <button className="primary" onClick={() => void onDone(step.project.id)}>Open project</button>
      </div>
    </div>
  );
}

function ProjectDetail({ project, onChange, onDeleted }: { project: Project; onChange: () => Promise<void>; onDeleted: () => Promise<void> }) {
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [add, setAdd] = useState("");
  const [cap, setCap] = useState(project.cap_per_day?.toString() ?? "");
  const [name, setName] = useState(project.name);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    void api.secrets().then(setSecrets).catch(() => {});
  }, []);

  const run = async (f: () => Promise<unknown>) => {
    setBusy(true);
    setErr(null);
    try {
      await f();
      await onChange();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const addFolder = async () => {
    const dir = await pickFolder(`Add a folder to ${project.name}`);
    if (dir) await run(() => api.patchProject(project.id, { paths: [...project.paths, dir] }));
  };
  const saveCap = () => {
    const n = Number(cap.trim());
    if (!cap.trim()) return run(() => api.patchProject(project.id, { cap_per_day: null }));
    if (!Number.isInteger(n) || n < 1) {
      setErr("The daily limit is a whole number of requests, 1 or more.");
      return;
    }
    return run(() => api.patchProject(project.id, { cap_per_day: n }));
  };
  const del = async () => {
    if (!confirm(`Delete the project ${project.name}? Its keys stay in the vault and keep working.`)) return;
    setBusy(true);
    try {
      await api.deleteProject(project.id);
      await onDeleted();
    } catch (e) {
      setErr((e as Error).message);
      setBusy(false);
    }
  };
  const available = secrets.filter((s) => !project.secrets.some((p) => p.id === s.secret_id));

  return (
    <div className="form">
      <h2>{project.name}</h2>
      <Usage p={project} />

      <h3>Keys</h3>
      {project.secrets.length === 0 ? (
        <p className="muted small">No keys yet. AI tools working in this project's folder will see none until you add some.</p>
      ) : (
        <div className="chips">
          {project.secrets.map((s) => (
            <span key={s.id} className="chip">
              {s.name}
              <button className="link" title={`Take ${s.name} out of ${project.name}`} disabled={busy} onClick={() => void run(() => api.detachSecret(project.id, s.id))}>×</button>
            </span>
          ))}
        </div>
      )}
      {available.length > 0 && (
        <div className="row-main">
          <select value={add} onChange={(e) => setAdd(e.target.value)}>
            <option value="">Add a key from the vault…</option>
            {available.map((s) => <option key={s.secret_id} value={s.secret_id}>{s.name}{s.provider ? ` (${s.provider})` : ""}</option>)}
          </select>
          <button disabled={!add || busy} onClick={() => void run(async () => { await api.attachSecret(project.id, add); setAdd(""); })}>Add</button>
        </div>
      )}

      <h3>Folders</h3>
      <p className="muted small">AI tools started in these folders (or below them) see only this project's keys.</p>
      {project.paths.length === 0 && <p className="warn-text small">No folder yet, so no AI tool is limited to this project.</p>}
      <ul className="rows">
        {project.paths.map((p) => (
          <li key={p} className="row static">
            <div className="row-main">
              <code className="grow">{p}</code>
              <button className="link" disabled={busy} onClick={() => void run(() => api.patchProject(project.id, { paths: project.paths.filter((x) => x !== p) }))}>remove</button>
            </div>
          </li>
        ))}
      </ul>
      <div className="actions"><button disabled={busy} onClick={() => void addFolder()}>Add folder…</button></div>

      <h3>Daily limit</h3>
      <p className="muted small">The most requests this project's keys may make in 24 hours. A runaway script or a leaked stand-in stops here instead of running up a bill.</p>
      <div className="row-main">
        <input type="number" min={1} placeholder="no limit" value={cap} onChange={(e) => setCap(e.target.value)} />
        <span className="muted small">requests a day</span>
        {cap.trim() || project.cap_per_day == null ? (
          <button disabled={busy || !cap.trim() || Number(cap) === project.cap_per_day} onClick={() => void saveCap()}>Save limit</button>
        ) : (
          <button disabled={busy} onClick={() => void saveCap()}>Remove limit</button>
        )}
      </div>

      <h3>Name</h3>
      <div className="row-main">
        <input value={name} onChange={(e) => setName(e.target.value)} />
        <button disabled={busy || !name.trim() || name === project.name} onClick={() => void run(() => api.patchProject(project.id, { name }))}>Rename</button>
      </div>

      {err && <div className="err">{err}</div>}
      <div className="actions">
        <button className="danger" disabled={busy} onClick={() => void del()}>Delete project</button>
      </div>
      <p className="muted small">In a terminal: <code>usk project show "{project.name}"</code></p>
    </div>
  );
}
