import { useEffect, useMemo, useState } from "react";
import { api, type AuditEvent, type SecretMeta } from "../api";
import { lockWords, reasonWords, responseWords, shortPath, statusWords, verb, verbBase, who, whoMid } from "../words";

type Tone = "ok" | "warn" | "bad" | "info" | "plain";
type Line = { text: string; result?: string; tone: Tone };

const FILTERS: { id: string; label: string; kinds: string[] }[] = [
  { id: "all", label: "Everything", kinds: [] },
  { id: "used", label: "Keys used", kinds: ["use", "key_tested"] },
  { id: "blocked", label: "Blocked", kinds: ["deny", "egress_blocked"] },
  { id: "alerts", label: "Alerts", kinds: ["anomaly", "canary_tripped", "audit_tampered"] },
  { id: "asks", label: "Requests to you", kinds: ["approval_required", "approval_decided", "access_requested"] },
  { id: "changes", label: "Changes", kinds: ["secret_created", "secret_updated", "secret_deleted", "handle_created", "handle_revoked", "handle_resumed", "policy_changed", "project_created", "project_changed", "project_deleted", "settings_changed", "unlock_method_added", "unlock_method_removed", "approval_forgotten", "reveal", "inject"] },
  { id: "signins", label: "Lock and unlock", kinds: ["unlock", "lock"] },
];

/** One event as a sentence. `names` maps secret ids to names. */
function sentence(e: AuditEvent, names: Map<string, string>): Line {
  const b = e.body as Record<string, unknown>;
  const s = (k: string) => (typeof b[k] === "string" ? (b[k] as string) : "");
  const key = s("secret") || names.get(s("id")) || names.get(s("secret_id")) || "a key";
  const by = who(b.caller, b.label);
  switch (e.kind) {
    case "use": {
      const st = statusWords(b.status);
      return { text: `${by} used ${key}: ${verb(b.method)} ${s("host")}${shortPath(b.path)}`, result: st.text, tone: st.tone };
    }
    case "deny":
      return { text: `${by} was stopped from using ${key}: ${reasonWords(b.reason, b.detail)}`, tone: "bad" };
    case "egress_blocked":
      return { text: `Blocked a request through “${s("label")}” that carried ${((b.leaked as string[]) ?? []).join(", ") || "another key"}`, tone: "bad" };
    case "approval_required":
      return { text: `${by} asked to ${verbBase(b.method)} ${shortPath(b.path)} with ${key}`, tone: "info" };
    case "approval_decided":
      return { text: `You ${b.allowed ? "allowed" : "refused"} ${whoMid(b.caller, b.label)}${b.path ? ` to ${verbBase(b.method)} ${shortPath(b.path)}` : ""}${b.remembered ? ", and every time from now on" : ""}`, tone: b.allowed ? "ok" : "plain" };
    case "access_requested":
      return { text: `${by} asked for access to ${key}${s("reason") ? `: “${s("reason")}”` : ""}`, tone: "info" };
    case "reveal":
      return { text: `You looked at the value of ${key}${s("reason") ? ` (“${s("reason")}”)` : ""}`, tone: "warn" };
    case "inject":
      return { text: `${s("name") || key} was handed to a program: ${s("command")}`, tone: "warn" };
    case "anomaly":
      return { text: `Unusual activity on “${s("label")}”: ${s("detail")}`, result: responseWords(b.response), tone: "bad" };
    case "canary_tripped":
      return { text: `A tripwire key was used. ${s("detail")}`, result: responseWords(b.response), tone: "bad" };
    case "audit_tampered":
      return { text: "The activity log was cut short or rewritten while the vault was locked", tone: "bad" };
    case "key_tested": {
      const ok = b.ok === true ? "works" : b.ok === false ? "was refused" : "result unclear";
      return { text: `Tested ${key}: it ${ok}`, tone: b.ok === true ? "ok" : b.ok === false ? "bad" : "plain" };
    }
    case "secret_created":
      return { text: `Key added: ${s("name") || key}${s("provider") ? ` (${s("provider")})` : ""}`, tone: "ok" };
    case "secret_updated":
      return { text: b.value_changed ? `New value stored for ${key}` : `Settings changed for ${key}`, tone: "plain" };
    case "secret_deleted":
      return { text: `Key deleted${b.handles_revoked ? `, and its ${b.handles_revoked} access ${b.handles_revoked === 1 ? "entry" : "entries"} removed` : ""}`, tone: "plain" };
    case "handle_created":
      return { text: `${b.auto ? `${by} got` : "New"} access to ${key}${s("label") ? ` (“${s("label")}”)` : ""}${b.canary ? " — a tripwire" : ""}`, tone: "ok" };
    case "handle_revoked":
      return { text: `Access removed${b.reason === "secret_deleted" ? " because its key was deleted" : ""}`, tone: "plain" };
    case "handle_resumed":
      return { text: "Access back to normal after an incident", tone: "ok" };
    case "policy_changed":
      return { text: `Rules changed${s("label") ? ` for “${s("label")}”` : ""}`, tone: "plain" };
    case "approval_forgotten":
      return { text: "Forgot an “always allow” answer", tone: "plain" };
    case "project_created":
      return { text: `Project ${s("name")} created`, tone: "ok" };
    case "project_changed":
      return { text: `Project ${s("name")} changed${b.added ? ": key added" : b.removed ? ": key removed" : ""}`, tone: "plain" };
    case "project_deleted":
      return { text: `Project ${s("name")} deleted (its keys stay)`, tone: "plain" };
    case "settings_changed":
      return { text: b.idle_lock_minutes === 0 ? "Auto-lock turned off" : `Auto-lock set to ${b.idle_lock_minutes} minutes`, tone: "plain" };
    case "unlock_method_added":
      return { text: "Windows Hello unlock turned on", tone: "ok" };
    case "unlock_method_removed":
      return { text: "Windows Hello unlock turned off", tone: "plain" };
    case "unlock":
      return { text: `Vault unlocked${b.method === "windows_hello" ? " with Windows Hello" : b.method === "password" ? " with your password" : ""}`, tone: "plain" };
    case "lock":
      return { text: `Vault locked ${lockWords(b.reason)}`.trim(), tone: "plain" };
    default:
      return { text: e.kind.replace(/_/g, " "), tone: "plain" };
  }
}

function dayLabel(ts: number): string {
  const d = new Date(ts);
  const today = new Date();
  const start = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((start(today) - start(d)) / 86_400_000);
  if (diff === 0) return "Today";
  if (diff === 1) return "Yesterday";
  return d.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long" });
}

type VerifyReport = {
  ok: boolean;
  rows: number;
  first_broken: number | null;
  contiguous: boolean;
  head: { state: "unchecked" | "missing" | "verified" | "forged" } | { state: "mismatch"; head_seq: number; last_seq: number };
  head_checked: boolean;
};

function verifyWords(v: VerifyReport): { text: string; ok: boolean } {
  if (v.ok) {
    return {
      ok: true,
      text: v.head_checked
        ? `Nothing was changed or removed: all ${v.rows} entries check out.`
        : `No entry was changed: all ${v.rows} check out. Unlock the vault to also check that none were removed from the end.`,
    };
  }
  if (v.first_broken !== null) return { ok: false, text: `The log was tampered with: entry ${v.first_broken} was changed or removed.` };
  if (v.head.state === "mismatch") return { ok: false, text: `The log was cut short: it ends at entry ${v.head.last_seq}, but ${v.head.head_seq} were written.` };
  return { ok: false, text: "The log's seal was rewritten by someone without the vault key." };
}

const PAGE = 150;

/** `tick` changes on every daemon event: reload in place (see Secrets). */
export function Activity({ tick }: { tick: number }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [names, setNames] = useState<Map<string, string>>(new Map());
  const [filter, setFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [shown, setShown] = useState(PAGE);
  const [open, setOpen] = useState<number | null>(null);
  const [verify, setVerify] = useState<VerifyReport | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const all = await api.audit(1, null, 5000);
        setEvents(all.slice().reverse());
        const secrets: SecretMeta[] = await api.secrets().catch(() => []);
        setNames(new Map(secrets.map((s) => [s.secret_id, s.name])));
      } catch (e) {
        setErr((e as Error).message);
      }
    })();
  }, [tick]);

  const lines = useMemo(() => events.map((e) => ({ e, l: sentence(e, names) })), [events, names]);
  const kinds = FILTERS.find((f) => f.id === filter)?.kinds ?? [];
  const q = query.trim().toLowerCase();
  const visible = lines.filter(({ e, l }) => (!kinds.length || kinds.includes(e.kind)) && (!q || l.text.toLowerCase().includes(q) || JSON.stringify(e.body).toLowerCase().includes(q)));

  const today = lines.filter(({ e }) => dayLabel(e.ts) === "Today");
  const usedToday = today.filter(({ e }) => e.kind === "use").length;
  const blockedToday = today.filter(({ e }) => e.kind === "deny" || e.kind === "egress_blocked").length;
  const alertsToday = today.filter(({ e }) => ["anomaly", "canary_tripped", "audit_tampered"].includes(e.kind)).length;

  const groups: { day: string; items: typeof visible }[] = [];
  for (const it of visible.slice(0, shown)) {
    const day = dayLabel(it.e.ts);
    const g = groups[groups.length - 1];
    if (g && g.day === day) g.items.push(it);
    else groups.push({ day, items: [it] });
  }

  return (
    <div className="single">
      <header className="pane-head">
        <h2>Activity</h2>
        <button onClick={() => void api.call<VerifyReport>("GET", "/v1/audit/verify").then(setVerify).catch((e) => setErr((e as Error).message))}>
          Check nothing was changed
        </button>
      </header>
      <p className="muted small">Everything that happened with your keys, newest first. Each entry is sealed, so a change or a missing entry shows up when you check.</p>

      <div className="stats">
        <div className="stat"><b>{usedToday}</b><span>keys used today</span></div>
        <div className={`stat ${blockedToday ? "warn" : ""}`}><b>{blockedToday}</b><span>blocked today</span></div>
        <div className={`stat ${alertsToday ? "bad" : ""}`}><b>{alertsToday}</b><span>alerts today</span></div>
      </div>

      {verify && <div className={`banner ${verifyWords(verify).ok ? "ok" : "error"}`}>{verifyWords(verify).text}</div>}
      {err && <div className="err">{err}</div>}

      <div className="filters">
        {FILTERS.map((f) => (
          <button key={f.id} className={`pill ${filter === f.id ? "on" : ""}`} onClick={() => { setFilter(f.id); setShown(PAGE); }}>{f.label}</button>
        ))}
        <input className="grow" placeholder="Search: a key, a tool, a website…" value={query} onChange={(e) => { setQuery(e.target.value); setShown(PAGE); }} />
      </div>

      {visible.length === 0 && !err ? (
        <div className="empty">
          <b>{events.length ? "Nothing matches" : "Nothing has happened yet"}</b>
          <p>Every time a key is used, blocked or changed, it shows up here.</p>
        </div>
      ) : (
        groups.map((g) => (
          <section key={g.day} className="feed">
            <h3>{g.day}</h3>
            <ul>
              {g.items.map(({ e, l }) => (
                <li key={e.seq} className={`feed-item tone-${l.tone}`}>
                  <button className="feed-line" onClick={() => setOpen(open === e.seq ? null : e.seq)} aria-expanded={open === e.seq}>
                    <span className="dot" />
                    <span className="feed-text">{l.text}{l.result && <span className={`feed-result tone-${l.tone}`}> · {l.result}</span>}</span>
                    <span className="feed-time muted">{new Date(e.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                  </button>
                  {open === e.seq && (
                    <div className="feed-detail">
                      <dl className="kv small">
                        <dt>What</dt><dd><code>{e.kind}</code></dd>
                        <dt>When</dt><dd>{new Date(e.ts).toLocaleString()}</dd>
                        <dt>Entry</dt><dd>#{e.seq}</dd>
                      </dl>
                      <pre className="snippet">{JSON.stringify(e.body, null, 2)}</pre>
                      <p className="muted small">In a terminal: <code>usk log --kind {e.kind}</code></p>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          </section>
        ))
      )}
      {visible.length > shown && (
        <div className="actions"><button onClick={() => setShown(shown + PAGE)}>Show older</button></div>
      )}
    </div>
  );
}
