import { useEffect, useState } from "react";
import { api, type DeviceUnlock, type Status } from "../api";
import { checkForUpdate, installUpdate, type UpdateInfo } from "../updates";

export function Settings({ status, onLock }: { status: Status; onLock: () => Promise<void> }) {
  const [path, setPath] = useState(".env");
  const [scan, setScan] = useState<{ line: number; key: string; detected: string | null; fixable: boolean }[] | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [device, setDevice] = useState<DeviceUnlock | null>(null);
  const [deviceMsg, setDeviceMsg] = useState<string | null>(null);
  const [deviceBusy, setDeviceBusy] = useState(false);
  const [update, setUpdate] = useState<UpdateInfo | null | "none" | "checking" | "installing">(null);
  const [updateErr, setUpdateErr] = useState<string | null>(null);
  const [progress, setProgress] = useState<string>("");

  const loadDevice = () => void api.deviceStatus().then(setDevice).catch(() => setDevice(null));
  useEffect(loadDevice, [status.daemon?.locked]);

  const enroll = async () => {
    setDeviceBusy(true);
    setDeviceMsg(null);
    try {
      const label = await api.deviceEnroll();
      setDeviceMsg(`Windows Hello enabled for ${label}. Your password still works and is still required for recovery.`);
    } catch (e) {
      setDeviceMsg((e as Error).message);
    } finally {
      setDeviceBusy(false);
      loadDevice();
    }
  };
  const remove = async () => {
    setDeviceBusy(true);
    setDeviceMsg(null);
    try {
      await api.deviceRemove();
      setDeviceMsg("Windows Hello unlock removed.");
    } catch (e) {
      setDeviceMsg((e as Error).message);
    } finally {
      setDeviceBusy(false);
      loadDevice();
    }
  };

  const doCheck = async () => {
    setUpdateErr(null);
    setUpdate("checking");
    try {
      const u = await checkForUpdate();
      setUpdate(u ?? "none");
    } catch (e) {
      setUpdate(null);
      setUpdateErr((e as Error).message);
    }
  };
  const doInstall = async () => {
    setUpdateErr(null);
    setUpdate("installing");
    try {
      await installUpdate((d, t) => setProgress(t ? `${Math.round((100 * d) / t)}%` : `${Math.round(d / 1024)} KB`));
    } catch (e) {
      setUpdate(null);
      setUpdateErr((e as Error).message);
    }
  };

  return (
    <div className="single">
      <header className="pane-head"><h2>Settings</h2></header>
      <section className="section">
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
      </section>
      <section className="section">
      <h3>Windows Hello</h3>
      {!device || !device.available ? (
        <p className="muted small">Not available on this computer. Set up Windows Hello (PIN, face or fingerprint) in Windows settings first.</p>
      ) : device.enrolled ? (
        <>
          <p className="muted small">Enabled. Unlocking asks Windows Hello; your password keeps working. The vault file alone, without this computer's Hello key, cannot be opened this way.</p>
          <div className="actions">
            <button className="danger" disabled={deviceBusy || !!status.daemon?.locked} onClick={() => void remove()}>Disable Windows Hello unlock</button>
          </div>
        </>
      ) : (
        <>
          <p className="muted small">Unlock with your PIN, face or fingerprint instead of typing the password. Enabling creates a Hello-protected key for this vault on this computer.</p>
          <div className="actions">
            <button className="primary" disabled={deviceBusy || !!status.daemon?.locked} onClick={() => void enroll()}>{deviceBusy ? "Waiting for Windows Hello…" : "Enable Windows Hello unlock"}</button>
          </div>
        </>
      )}
      {device && !device.available && status.daemon?.locked && <p className="muted small">Unlock the vault to change this.</p>}
      {deviceMsg && <pre className="snippet">{deviceMsg}</pre>}

      </section>
      <section className="section">
      <h3>Updates</h3>
      <p className="muted small">Updates are signed; a bundle whose signature does not match the built-in key is refused.</p>
      <div className="actions">
        <button disabled={update === "checking" || update === "installing"} onClick={() => void doCheck()}>{update === "checking" ? "Checking…" : "Check for updates"}</button>
        {update && typeof update === "object" && (
          <button className="primary" onClick={() => void doInstall()}>Install {update.version} and restart</button>
        )}
      </div>
      {update === "none" && <p className="muted small">You are on the latest version.</p>}
      {update === "installing" && <p className="muted small">Downloading {progress}…</p>}
      {update && typeof update === "object" && update.notes && <pre className="snippet">{update.notes}</pre>}
      {updateErr && <div className="err">{updateErr}</div>}

      </section>
      <section className="section">
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
      </section>
    </div>
  );
}
