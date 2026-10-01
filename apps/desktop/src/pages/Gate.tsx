import { useState } from "react";
import { api, type Status } from "../api";

/// Onboarding (create vault + recovery words) or unlock.
export function Gate({ status, onDone }: { status: Status; onDone: () => Promise<void> }) {
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [words, setWords] = useState<string[] | null>(null);
  const [ack, setAck] = useState(false);

  const create = async () => {
    setErr(null);
    if (password.length < 12) return setErr("Use at least 12 characters.");
    if (password !== again) return setErr("Passwords do not match.");
    setBusy(true);
    try {
      const r = await api.createVault(password);
      setWords(r.words);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const unlock = async () => {
    setErr(null);
    setBusy(true);
    try {
      await api.unlock(password);
      setPassword("");
      await onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (words) {
    return (
      <div className="gate">
        <h1>Your recovery phrase</h1>
        <p>
          Write these 24 words down and keep them offline. They are shown <b>once</b> and never stored. If you forget
          your password, this phrase is the only way back in.
        </p>
        <ol className="words">
          {words.map((w, i) => (
            <li key={i}>{w}</li>
          ))}
        </ol>
        <label className="check">
          <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> I have written the
          phrase down
        </label>
        <button className="primary" disabled={!ack} onClick={() => void onDone()}>
          Continue
        </button>
      </div>
    );
  }

  if (!status.vault_exists) {
    return (
      <div className="gate">
        <h1>Create your vault</h1>
        <p>
          Secrets are encrypted on this computer with a key derived from your password. Nothing leaves your machine.
          <br />
          <b>The password cannot be reset.</b> You will get a recovery phrase next.
        </p>
        <input type="password" placeholder="Password (12+ characters)" value={password} onChange={(e) => setPassword(e.target.value)} />
        <input type="password" placeholder="Repeat password" value={again} onChange={(e) => setAgain(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void create()} />
        {err && <div className="err">{err}</div>}
        <button className="primary" disabled={busy} onClick={() => void create()}>
          {busy ? "Creating…" : "Create vault"}
        </button>
        <div className="muted small">Vault file: {status.vault_path}</div>
      </div>
    );
  }

  return (
    <div className="gate">
      <h1>Unlock</h1>
      <p>Your vault is locked. Enter your password to let tools and agents use your keys again.</p>
      <input
        type="password"
        placeholder="Vault password"
        autoFocus
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && void unlock()}
      />
      {err && <div className="err">{err}</div>}
      <button className="primary" disabled={busy || !password} onClick={() => void unlock()}>
        {busy ? "Unlocking…" : "Unlock"}
      </button>
      <div className="muted small">Forgot it? Run <code>usk recover</code> with your recovery phrase.</div>
    </div>
  );
}
