import { useCallback, useEffect, useState, type ReactElement } from "react";
import { api, onDaemonEvent, setOwnerPrompt, type Approval, type DaemonEvent, type Status } from "./api";
import { Gate } from "./pages/Gate";
import { Projects } from "./pages/Projects";
import { Secrets } from "./pages/Secrets";
import { Handles } from "./pages/Handles";
import { Approvals } from "./pages/Approvals";
import { Activity } from "./pages/Activity";
import { Agents } from "./pages/Agents";
import { Settings } from "./pages/Settings";
import { openReleases, progressText, useUpdater } from "./updates";
import { who } from "./words";

import icon from "./assets/icon.png";

type Tab = "projects" | "secrets" | "handles" | "approvals" | "activity" | "agents" | "settings";

const I = {
  folder: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>,
  key: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m11 12 9-9M15 6l3 3M18 3l3 3"/></svg>,
  handle: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="7" width="18" height="10" rx="3"/><circle cx="8" cy="12" r="1.6"/><path d="M12 12h6"/></svg>,
  approve: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="m9 12 2 2 4-4"/></svg>,
  activity: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>,
  agents: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="4" y="8" width="16" height="12" rx="3"/><circle cx="9" cy="14" r="1.5"/><circle cx="15" cy="14" r="1.5"/><path d="M12 8V4M8 4h8"/></svg>,
  settings: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>,
  lock: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>,
};

const TABS: { id: Tab; label: string; icon: ReactElement }[] = [
  { id: "projects", label: "Projects", icon: I.folder },
  { id: "secrets", label: "Keys", icon: I.key },
  { id: "handles", label: "Agent access", icon: I.handle },
  { id: "approvals", label: "Approvals", icon: I.approve },
  { id: "activity", label: "Activity", icon: I.activity },
  { id: "agents", label: "Agents", icon: I.agents },
  { id: "settings", label: "Settings", icon: I.settings },
];

export function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("projects");
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [toast, setToast] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const updater = useUpdater();
  const [restarting, setRestarting] = useState(false);
  // A pending "it is you?" question from an action that needs the owner.
  const [ownerAsk, setOwnerAsk] = useState<{ resolve: (password: string | null) => void } | null>(null);
  const [ownerPassword, setOwnerPassword] = useState("");

  // Actions that need the owner (reveal, approve, change access) ask for the
  // password here when Windows Hello cannot confirm it.
  useEffect(() => {
    setOwnerPrompt(() => new Promise<string | null>((resolve) => setOwnerAsk({ resolve })));
    return () => setOwnerPrompt(null);
  }, []);

  const answerOwner = (password: string | null) => {
    ownerAsk?.resolve(password);
    setOwnerAsk(null);
    setOwnerPassword("");
  };

  const refresh = useCallback(async () => {
    try {
      const s = await api.status();
      setStatus(s);
      setError(null);
      if (s.daemon && !s.daemon.locked) {
        setApprovals(await api.approvals());
      } else {
        setApprovals([]);
      }
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const id = setInterval(() => void refresh(), 10_000);
    return () => clearInterval(id);
  }, [refresh]);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void onDaemonEvent((e: DaemonEvent) => {
      setTick((t) => t + 1);
      if (e.event === "approval_requested") {
        setTab("approvals");
        void api.approvals().then(setApprovals).catch(() => {});
        setToast(`${e.caller} wants to use ${e.secret}: ${e.scope}`);
      } else if (e.event === "approval_decided") {
        void api.approvals().then(setApprovals).catch(() => {});
      } else if (e.event === "caller_changed" && e.change === "registered") {
        setToast(`New AI tool connected: ${who(`mcp:${e.name}`)}. If you did not set it up, disconnect it with: usk mcp remove ${e.name}`);
      } else if (e.event === "egress_blocked") {
        setToast(`Blocked: a request via ${e.secret} carried ${e.leaked.join(", ")}`);
      } else if (e.event === "anomaly") {
        const did = { alert: "recorded", throttle: "throttled for an hour", approve: "now needs your approval for every request", pause: "paused", lock: "the vault was locked" }[e.response];
        setToast(`${e.kind === "canary" ? "Canary tripped" : "Unusual activity"} on "${e.label}": ${e.detail}. ${did}.`);
        if (e.response !== "lock") setTab("handles");
        void refresh();
      } else if (e.event === "locked" || e.event === "unlocked") {
        void refresh();
      }
    }).then((u) => {
      unlisten = u;
    });
    return () => unlisten?.();
  }, [refresh]);

  useEffect(() => {
    if (!toast) return;
    // Incidents stay up until read; the rest fade.
    const id = setTimeout(() => setToast(null), toast.startsWith("Unusual") || toast.startsWith("Canary") ? 30_000 : 6000);
    return () => clearTimeout(id);
  }, [toast]);

  const unlocked = !!status?.daemon && !status.daemon.locked;

  const lockNow = useCallback(async () => {
    setError(null);
    try {
      await api.lock();
    } catch (e) {
      setError(`Lock failed: ${(e as Error).message}`);
    }
    await refresh();
  }, [refresh]);

  return (
    <div className="app">
      {ownerAsk && (
        <div className="modal-backdrop" onClick={() => answerOwner(null)}>
          <div className="modal" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
            <h3>Confirm it is you</h3>
            <p className="muted small">
              This changes what your keys can do or shows one. Any program on this computer can talk to Unseenkey; only you know
              the password.
            </p>
            <input
              type="password"
              placeholder="Vault password"
              autoFocus
              value={ownerPassword}
              onChange={(e) => setOwnerPassword(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && ownerPassword) answerOwner(ownerPassword);
                if (e.key === "Escape") answerOwner(null);
              }}
            />
            <div className="actions">
              <button className="primary" disabled={!ownerPassword} onClick={() => answerOwner(ownerPassword)}>
                Confirm
              </button>
              <button onClick={() => answerOwner(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
      <aside className="sidebar">
        <div className="brand">
          <img src={icon} alt="" />
          <div>
            <div className="brand-name">Unseenkey</div>
            <div className="brand-sub">use keys, never see them</div>
          </div>
        </div>
        <nav>
          {TABS.map((t) => (
            <button
              key={t.id}
              className={`nav-item ${tab === t.id ? "active" : ""}`}
              onClick={() => setTab(t.id)}
              disabled={!unlocked}
            >
              {t.icon}
              <span className="grow">{t.label}</span>
              {t.id === "approvals" && approvals.length > 0 && <span className="badge">{approvals.length}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className={`dot ${unlocked ? "ok" : status?.daemon ? "warn" : "off"}`} />
          <span className="grow" style={{ flex: 1 }}>{status?.daemon ? (unlocked ? "Vault unlocked" : "Vault locked") : "Daemon off"}</span>
          {unlocked && (
            <button className="small" title="Lock the vault now" onClick={() => void lockNow()}>
              Lock
            </button>
          )}
        </div>
      </aside>
      <main className="content">
        {error && <div className="banner error">{error}</div>}
        {status?.daemon && status.daemon.version !== status.app_version && (
          <div className="banner error">
            The Unseenkey service running now is version {status.daemon.version}, but this app is {status.app_version}, so some pages will not work.{" "}
            <button className="link" disabled={restarting} onClick={() => { setRestarting(true); void api.restartDaemon().catch((e) => setError((e as Error).message)).finally(() => { setRestarting(false); void refresh(); }); }}>
              {restarting ? "Restarting…" : "Restart the service"}
            </button>
            <span className="muted small"> (the vault locks; unlock it again afterwards)</span>
          </div>
        )}
        {toast && <div className="banner info">{toast}</div>}
        {updater.error ? (
          <div className="banner error">
            {updater.error}{" "}
            <button className="link" onClick={() => void updater.install()}>Try again</button>
            <button className="link" onClick={openReleases}>Download it yourself</button>
            <button className="link" onClick={updater.dismiss}>later</button>
          </div>
        ) : updater.progress ? (
          <div className="banner info">{progressText(updater.progress)}</div>
        ) : updater.available && (
          <div className="banner info">
            Unseenkey {updater.available.version} is available.{" "}
            <button className="link" onClick={() => void updater.install()}>Install and restart</button>
            <button className="link" onClick={updater.dismiss}>later</button>
          </div>
        )}
        {!status ? (
          <div className="muted">Connecting to the daemon…</div>
        ) : !unlocked ? (
          <Gate status={status} onDone={refresh} />
        ) : (
          <>
            {tab === "projects" && (
              <Projects
                tick={tick}
                status={status}
                updater={updater}
                onSettings={() => setTab("settings")}
              />
            )}
            {tab === "secrets" && <Secrets tick={tick} />}
            {tab === "handles" && <Handles tick={tick} />}
            {tab === "approvals" && (
              <Approvals approvals={approvals} onChange={() => void api.approvals().then(setApprovals)} />
            )}
            {tab === "activity" && <Activity tick={tick} />}
            {tab === "agents" && <Agents />}
            {tab === "settings" && <Settings status={status} onLock={lockNow} updater={updater} />}
          </>
        )}
      </main>
    </div>
  );
}
