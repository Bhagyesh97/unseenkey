import { useState } from "react";
import { api, type Status } from "../api";

export function Settings({ status, onLock }: { status: Status; onLock: () => Promise<void> }) {
  const [path, setPath] = useState(".env");
  const [scan, setScan] = useState<{ line: number; key: string; detected: string | null; fixable: boolean }[] | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  return (
    <div className="single">
      <header className="pane-head"><h2>Settings</h2></header>
      <dl className="kv">
        <dt>Vault file</dt><dd><code>{status.vault_path}</code></dd>
        <dt>Daemon</dt><dd>{status.daemon ? `running (v${status.daemon.version}, up ${Math.round(status.daemon.uptime_s / 60)} min, ${status.daemon.locked ? "locked" : "unlocked"})` : "not running"}</dd>
        <dt>Auto-lock</dt><dd>{status.daemon ? `${status.daemon.idle_lock_minutes} min idle (config.toml)` : "—"}</dd>
        <dt>App</dt><dd>v{status.app_version}</dd>
      </dl>
      {status.daemon && !status.daemon.locked && (
        <div className="actions">
          <button onClick={() => void onLock()}>Lock vault now</button>
        </div>
      )}
      <h3>.env guard</h3>
      <p className="muted small">Find real keys in a project's .env file, move them into the vault and replace them with handles.</p>
      <div className="row-main">
        <input style={{ flex: 1 }} value={path} onChange={(e) => setPath(e.target.value)} placeholder="C:\path\to\project\.env" />
        <button onClick={() => void api.guardScan(path).then(setScan).catch((e) => setMsg((e as Error).message))}>Scan</button>
        <button className="primary" disabled={!scan?.some((s) => s.fixable)} onClick={() => void api.guardFix(path).then((m) => { setMsg(m); setScan(null); }).catch((e) => setMsg((e as Error).message))}>Fix</button>
      </div>
      {scan && (
        <table className="table">
          <thead><tr><th>Line</th><th>Key</th><th>Looks like</th><th>Action</th></tr></thead>
          <tbody>
            {scan.map((s) => (
              <tr key={s.line}><td>{s.line}</td><td>{s.key}</td><td>{s.detected ?? "secret (by name)"}</td><td>{s.fixable ? "replace with handle" : "leave (no preset)"}</td></tr>
            ))}
            {scan.length === 0 && <tr><td colSpan={4} className="muted">Nothing that looks like a secret.</td></tr>}
          </tbody>
        </table>
      )}
      {msg && <pre className="snippet">{msg}</pre>}
    </div>
  );
}
