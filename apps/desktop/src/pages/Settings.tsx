import { useEffect, useState } from "react";
import { api, type DeviceUnlock, type Status } from "../api";
import { openReleases, progressText, type Updater } from "../updates";

const CARE = [
  { id: "relaxed", title: "Relaxed", text: "For your own projects. AI tools can do anything; only deleting things and moving money out (refunds, payouts) ask you first." },
  { id: "balanced", title: "Balanced", text: "AI tools can do the work; deleting, moving money out, and changing keys, billing or account settings ask you first, with “Always allow this”." },
  { id: "strict", title: "Strict", text: "Each provider's cautious default, often read only. Best when you share keys with other people." },
];

export function Settings({ status, onLock, updater }: { status: Status; onLock: () => Promise<void>; updater: Updater }) {
  const [path, setPath] = useState(".env");
  const [scan, setScan] = useState<{ line: number; key: string; detected: string | null; fixable: boolean }[] | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [device, setDevice] = useState<DeviceUnlock | null>(null);
  const [deviceMsg, setDeviceMsg] = useState<string | null>(null);
  const [deviceBusy, setDeviceBusy] = useState(false);

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


  // The settings are kept in the vault, so what the service reports changes
  // with an unlock. A value saved here is shown until then.
  const [careSaved, setCare] = useState<string | null>(null);
  const care = careSaved ?? status.daemon?.care ?? "balanced";
  const [careMsg, setCareMsg] = useState<string | null>(null);
  const saveCare = async (c: string) => {
    setCareMsg(null);
    try {
      const r = await api.call<{ care: string; handles_updated: number | null }>("PATCH", "/v1/settings", { care: c });
      setCare(r.care);
      const n = r.handles_updated ?? 0;
      setCareMsg(n ? `Saved. Updated ${n} AI tool ${n === 1 ? "access" : "accesses"}; access you set up yourself is unchanged.` : "Saved.");
    } catch (e) {
      setCareMsg((e as Error).message);
    }
  };
  const [lockAfter, setLockAfter] = useState<number | null>(null);
  const [lockMsg, setLockMsg] = useState<string | null>(null);
  const saveLock = async (m: number) => {
    setLockMsg(null);
    try {
      await api.call("PATCH", "/v1/settings", { idle_lock_minutes: m });
      setLockAfter(m);
      setLockMsg(m === 0 ? "Saved. The vault no longer locks after a time without use." : "Saved.");
    } catch (e) {
      setLockMsg((e as Error).message);
    }
  };
  type Switch = "lock_on_sleep" | "lock_on_session_lock" | "mcp_allow_store";
  const [switches, setSwitches] = useState<Partial<Record<Switch, boolean>>>({});
  const [switchMsg, setSwitchMsg] = useState<string | null>(null);
  const isOn = (k: Switch) => switches[k] ?? status.daemon?.[k] ?? false;
  // A service older than 0.1.10 does not report these and cannot set them.
  const fixed = (k: Switch) => !status.daemon || status.daemon.locked || status.daemon[k] === undefined;
  const saveSwitch = async (k: Switch, on: boolean) => {
    setSwitchMsg(null);
    try {
      const r = await api.call<Partial<Record<Switch, boolean>>>("PATCH", "/v1/settings", { [k]: on });
      setSwitches((s) => ({ ...s, [k]: r[k] }));
    } catch (e) {
      setSwitchMsg((e as Error).message);
    }
  };
  useEffect(() => {
    setCare(null);
    setLockAfter(null);
    setSwitches({});
  }, [status.daemon?.locked]);
  return (
    <div className="single">
      <header className="pane-head"><h2>Settings</h2></header>
      <section className="section">
      <h3>How careful should Unseenkey be?</h3>
      <p className="muted small">This decides what AI tools may do with your keys when they first use them. Whatever you pick, a key only ever goes to its own provider, never shows up in an AI tool's answers, and every use is in Activity.</p>
      <div className="care">
        {CARE.map((c) => (
          <label key={c.id} className={`care-option ${care === c.id ? "on" : ""}`}>
            <input type="radio" name="care" checked={care === c.id} disabled={!status.daemon || status.daemon.locked} onChange={() => void saveCare(c.id)} />
            <span><b>{c.title}</b>{c.id === "balanced" && <span className="chip info">recommended</span>}<br /><span className="muted small">{c.text}</span></span>
          </label>
        ))}
      </div>
      {careMsg && <p className="muted small">{careMsg}</p>}
      <p className="muted small">In a terminal: <code>usk care {care}</code></p>

      <h3>Locking</h3>
      <p className="muted small">A locked vault hands out no keys until you unlock it again.</p>
      <div className="row-main">
        <span>Lock when not used for</span>
        <select value={String(lockAfter ?? status.daemon?.idle_lock_minutes ?? 15)} disabled={!status.daemon || status.daemon.locked} onChange={(e) => void saveLock(Number(e.target.value))}>
          {[5, 15, 30, 60, 240, 0].map((m) => <option key={m} value={m}>{m === 0 ? "never" : m < 60 ? `${m} minutes` : `${m / 60} hour${m === 60 ? "" : "s"}`}</option>)}
        </select>
        {status.daemon && !status.daemon.locked && <button onClick={() => void onLock()}>Lock now</button>}
      </div>
      {lockMsg && <p className="muted small">{lockMsg}</p>}
      <label className="check">
        <input type="checkbox" checked={isOn("lock_on_sleep")} disabled={fixed("lock_on_sleep")} onChange={(e) => void saveSwitch("lock_on_sleep", e.target.checked)} />
        Lock when the computer goes to sleep
      </label>
      <label className="check">
        <input type="checkbox" checked={isOn("lock_on_session_lock")} disabled={fixed("lock_on_session_lock")} onChange={(e) => void saveSwitch("lock_on_session_lock", e.target.checked)} />
        Lock when you lock Windows
      </label>

      <h3>Adding keys</h3>
      <label className="check">
        <input type="checkbox" checked={isOn("mcp_allow_store")} disabled={fixed("mcp_allow_store")} onChange={(e) => void saveSwitch("mcp_allow_store", e.target.checked)} />
        Let AI tools add keys they come across to the vault
      </label>
      <p className="muted small">Off unless you turn it on. An AI tool that finds a key in your project can then put it in the vault; it still cannot read any key back.</p>
      {switchMsg && <p className="muted small">{switchMsg}</p>}
      {status.daemon && !status.daemon.locked && status.daemon.lock_on_sleep === undefined && <p className="muted small">The background service is older than this app; restart it to change these.</p>}
      <p className="muted small">In a terminal: <code>usk settings</code></p>
      <details className="tech">
        <summary>Technical details</summary>
        <dl className="kv small">
          <dt>Vault file</dt><dd><code>{status.vault_path}</code></dd>
          <dt>Background service</dt><dd>{status.daemon ? `running, version ${status.daemon.version}, for ${Math.round(status.daemon.uptime_s / 60)} min, ${status.daemon.locked ? "locked" : "unlocked"}` : "not running"}</dd>
          <dt>App</dt><dd>version {status.app_version}</dd>
          <dt>Settings</dt><dd>kept in the vault, so only you can change them. <code>config.toml</code> next to the vault file sets the address the service listens on, nothing else once the vault has been unlocked</dd>
        </dl>
      </details>
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
        <button disabled={updater.checking || !!updater.progress} onClick={() => void updater.check()}>{updater.checking ? "Checking…" : "Check for updates"}</button>
        {updater.available && (
          <button className="primary" disabled={!!updater.progress} onClick={() => void updater.install()}>Install {updater.available.version} and restart</button>
        )}
      </div>
      {updater.upToDate && !updater.available && <p className="muted small">You are on the latest version ({status.app_version}).</p>}
      {updater.progress && <p className="muted small">{progressText(updater.progress)}</p>}
      {updater.available?.notes && <pre className="snippet">{updater.available.notes}</pre>}
      {updater.error && (
        <div className="err">
          {updater.error} <button className="link" onClick={openReleases}>Download it yourself</button>
        </div>
      )}

      </section>
      <section className="section">
      <h3>Protect a single .env file</h3>
      <p className="muted small">The easiest way is “Protect a project” on the Projects page. Here you can point at one .env file directly: real keys move into the vault and are replaced by stand-ins.</p>
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
