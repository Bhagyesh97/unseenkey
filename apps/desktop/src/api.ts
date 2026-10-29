// Thin typed layer over the Tauri commands. The webview never talks HTTP;
// the Rust side holds the daemon session token and forwards /v1 calls.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type Json = Record<string, unknown> | unknown[] | string | number | boolean | null;

export interface Status {
  vault_path: string;
  vault_exists: boolean;
  daemon: null | {
    locked: boolean;
    vault_id: string;
    version: string;
    uptime_s: number;
    secrets: number | null;
    idle_lock_minutes: number;
  };
  app_version: string;
}

export interface SecretMeta {
  secret_id: string;
  name: string;
  kind: string;
  provider: string | null;
  tags: string[];
  upstreams: string[];
  notes: string | null;
  no_scrub: boolean;
  allow_injection: boolean;
  created_at: number;
  updated_at: number;
  value_version: number;
}

export interface HandleView {
  id: string;
  label: string;
  secret: string;
  secret_id: string;
  provider: string | null;
  policy_explanation: string;
  policy: { callers?: string[]; mcp?: boolean; upstreams?: string[] };
  created_at: number;
  expires_at: number | null;
  revoked_at: number | null;
  use_count: number;
  last_used_at: number | null;
  active: boolean;
  remembered: string[];
  // The three fields below are absent on daemons older than 0.1.0.
  canary?: boolean;
  on_anomaly?: AnomalyResponse;
  status?: { state: "normal" } | { state: "throttled"; until: number } | { state: "approval_required" } | { state: "paused" };
  last_anomaly?: { kind: string; detail: string; at: number; response: AnomalyResponse } | null;
  // Absent on daemons older than 0.1.2.
  project?: string | null;
  project_id?: string | null;
}

/** A project: code folders and the secrets they use (daemon 0.1.2+). */
export interface Project {
  id: string;
  name: string;
  paths: string[];
  secrets: { id: string; name: string; provider: string | null }[];
  cap_per_day: number | null;
  requests_today: number;
  handles: number;
  last_used_at: number | null;
  notes: string | null;
  created_at: number;
  updated_at: number;
}

export interface EnvFinding {
  line: number;
  key: string;
  detected: string | null;
  fixable: boolean;
}

export type AnomalyResponse = "alert" | "throttle" | "approve" | "pause" | "lock";

export const RESPONSES: { id: AnomalyResponse; label: string; hint: string }[] = [
  { id: "alert", label: "Alert only", hint: "record it and tell me; nothing else changes" },
  { id: "throttle", label: "Throttle", hint: "a few requests a minute for an hour" },
  { id: "approve", label: "Ask me", hint: "every request needs my approval until I resume it" },
  { id: "pause", label: "Pause", hint: "refuse everything until I resume it" },
  { id: "lock", label: "Lock the vault", hint: "everything stops until I unlock" },
];

export interface HandleCreated extends HandleView {
  handle: string;
  env: Record<string, string>;
  base_url: string | null;
}

export interface Approval {
  id: string;
  kind: "request" | "access";
  label: string;
  secret: string;
  caller: string;
  method: string;
  host: string;
  path: string;
  scope: string;
  remember_key: string | null;
  created_at: number;
  expires_at: number;
  seconds_left: number;
}

export interface AuditEvent {
  seq: number;
  ts: number;
  kind: string;
  body: Record<string, unknown>;
}

export interface Preset {
  id: string;
  display: string;
  upstreams: string[];
  docs: string;
  camouflage: boolean;
  policies: { id: string; display: string; recommended: boolean; explanation: string }[];
}

export interface DeviceUnlock {
  available: boolean;
  enrolled: boolean;
  methods: { id: string; kind: string; label: string; created_at: number }[];
}

export class ApiError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

function wrap<T>(p: Promise<T>): Promise<T> {
  return p.catch((e: unknown) => {
    const text = typeof e === "string" ? e : (e as Error)?.message ?? String(e);
    const m = /^([a-z_]+): (.*)$/s.exec(text);
    throw m ? new ApiError(m[1], m[2]) : new ApiError("error", text);
  });
}

export const api = {
  status: () => wrap(invoke<Status>("status")),
  createVault: (password: string) => wrap(invoke<{ vault_id: string; words: string[] }>("create_vault", { password })),
  unlock: (password: string) => wrap(invoke<void>("unlock", { password })),
  lock: () => wrap(invoke<void>("lock")),
  call: <T = Json>(method: string, path: string, body?: Json) => wrap(invoke<T>("api", { method, path, body: body ?? null })),
  secrets: () => api.call<SecretMeta[]>("GET", "/v1/secrets"),
  handles: () => api.call<HandleView[]>("GET", "/v1/handles"),
  approvals: () => api.call<Approval[]>("GET", "/v1/approvals"),
  decide: (id: string, allow: boolean, remember: boolean) =>
    api.call("POST", `/v1/approvals/${id}`, { decision: allow ? "allow" : "deny", remember }),
  audit: (since: number, kind: string | null, limit: number) =>
    api.call<AuditEvent[]>("GET", `/v1/audit?since=${since}&limit=${limit}${kind ? `&kind=${kind}` : ""}`),
  presets: () => wrap(invoke<Preset[]>("presets")),
  installMcp: (client: string) => wrap(invoke<string>("install_mcp", { client })),
  callers: () => api.call<{ name: string; caller: string; last_seen_at: number | null }[]>("GET", "/v1/callers"),
  guardScan: (path: string) => wrap(invoke<EnvFinding[]>("guard_scan", { path })),
  guardFix: (path: string, project?: string) => wrap(invoke<string>("guard_fix", { path, project: project ?? null })),
  restartDaemon: () => wrap(invoke<void>("restart_daemon")),
  envFiles: (dir: string) => wrap(invoke<string[]>("env_files", { dir })),
  projects: () => api.call<Project[]>("GET", "/v1/projects"),
  projectForDir: (dir: string) => api.call<Project[]>("GET", `/v1/projects?dir=${encodeURIComponent(dir)}`).then((l) => l[0] ?? null),
  createProject: (body: { name?: string; paths?: string[]; secrets?: string[]; cap_per_day?: number }) => api.call<Project>("POST", "/v1/projects", body),
  patchProject: (id: string, body: { name?: string; paths?: string[]; cap_per_day?: number | null; notes?: string }) =>
    api.call<Project>("PATCH", `/v1/projects/${id}`, body),
  deleteProject: (id: string) => api.call("DELETE", `/v1/projects/${id}`),
  attachSecret: (id: string, secret: string) => api.call<Project>("POST", `/v1/projects/${id}/secrets`, { secret }),
  detachSecret: (id: string, secretId: string) => api.call<Project>("DELETE", `/v1/projects/${id}/secrets/${secretId}`),
  deviceStatus: () => wrap(invoke<DeviceUnlock>("device_unlock_status")),
  deviceEnroll: () => wrap(invoke<string>("device_unlock_enroll")),
  deviceUnlock: () => wrap(invoke<void>("device_unlock")),
  deviceRemove: () => wrap(invoke<void>("device_unlock_remove")),
};

export type DaemonEvent =
  | { event: "unlocked" }
  | { event: "locked"; reason: string }
  | { event: "secret_changed"; id: string; change: string }
  | { event: "project_changed"; id: string; change: string }
  | { event: "revealed"; id: string }
  | { event: "use"; secret: string; label: string; status: number }
  | { event: "egress_blocked"; secret: string; leaked: string[] }
  | { event: "approval_requested"; id: string; label: string; secret: string; caller: string; method: string; path: string; scope: string }
  | { event: "approval_decided"; id: string; allowed: boolean }
  | { event: "anomaly"; id: string; label: string; secret: string; kind: string; detail: string; response: AnomalyResponse };

export function onDaemonEvent(cb: (e: DaemonEvent) => void): Promise<UnlistenFn> {
  return listen<DaemonEvent>("usk://event", (ev) => cb(ev.payload));
}

export function fmtTime(ms: number): string {
  if (!ms) return "";
  return new Date(ms).toLocaleString();
}

export function ago(ms: number | null): string {
  if (!ms) return "never";
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

/** Ask the user for a folder (native dialog). `null` when they cancel. */
export async function pickFolder(title: string): Promise<string | null> {
  const { open } = await import("@tauri-apps/plugin-dialog");
  const r = await open({ directory: true, multiple: false, title });
  return typeof r === "string" ? r : null;
}

/** Last part of a folder path, for display and default names. */
export function folderName(path: string): string {
  const parts = path.replace(/[\\/]+$/, "").split(/[\\/]/);
  return parts[parts.length - 1] || path;
}
