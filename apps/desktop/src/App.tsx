import { useCallback, useEffect, useState } from "react";
import { api, onDaemonEvent, type Approval, type DaemonEvent, type Status } from "./api";
import { Gate } from "./pages/Gate";
import { Secrets } from "./pages/Secrets";
import { Handles } from "./pages/Handles";
import { Approvals } from "./pages/Approvals";
import { Activity } from "./pages/Activity";
import { Agents } from "./pages/Agents";
import { Settings } from "./pages/Settings";

type Tab = "secrets" | "handles" | "approvals" | "activity" | "agents" | "settings";

const TABS: { id: Tab; label: string }[] = [
  { id: "secrets", label: "Secrets" },
  { id: "handles", label: "Handles" },
  { id: "approvals", label: "Approvals" },
  { id: "activity", label: "Activity" },
  { id: "agents", label: "Agents" },
  { id: "settings", label: "Settings" },
];

export function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("secrets");
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [toast, setToast] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

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
      } else if (e.event === "egress_blocked") {
        setToast(`Blocked: a request via ${e.secret} carried ${e.leaked.join(", ")}`);
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
    const id = setTimeout(() => setToast(null), 6000);
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
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">U</div>
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
              {t.label}
              {t.id === "approvals" && approvals.length > 0 && <span className="badge">{approvals.length}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className={`dot ${unlocked ? "ok" : status?.daemon ? "warn" : "off"}`} />
          {status?.daemon ? (unlocked ? "unlocked" : "locked") : "daemon off"}
          {unlocked && (
            <button className="link" onClick={() => void lockNow()}>
              lock now
            </button>
          )}
        </div>
      </aside>
      <main className="content">
        {error && <div className="banner error">{error}</div>}
        {toast && <div className="banner info">{toast}</div>}
        {!status ? (
          <div className="muted">Connecting to the daemon…</div>
        ) : !unlocked ? (
          <Gate status={status} onDone={refresh} />
        ) : (
          <>
            {tab === "secrets" && <Secrets key={tick} />}
            {tab === "handles" && <Handles key={tick} />}
            {tab === "approvals" && (
              <Approvals approvals={approvals} onChange={() => void api.approvals().then(setApprovals)} />
            )}
            {tab === "activity" && <Activity key={tick} />}
            {tab === "agents" && <Agents />}
            {tab === "settings" && <Settings status={status} onLock={lockNow} />}
          </>
        )}
      </main>
    </div>
  );
}
