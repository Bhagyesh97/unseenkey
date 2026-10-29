// Plain words for what the daemon records. One place, so every page says
// things the same way; the technical form is always one click away.

const TOOLS: Record<string, string> = {
  "claude-code": "Claude Code",
  "claude-desktop": "Claude Desktop",
  cursor: "Cursor",
  windsurf: "Windsurf",
};

/** Who did it: "Claude Code", "an app on this computer", or the handle's label. */
export function who(caller?: unknown, label?: unknown): string {
  const c = typeof caller === "string" ? caller : "";
  if (c.startsWith("mcp:")) {
    const name = c.slice(4);
    return TOOLS[name] ?? name;
  }
  if (c === "local" || c === "") {
    const l = typeof label === "string" ? label : "";
    return l && !l.startsWith("mcp:") ? `“${l}”` : "An app on this computer";
  }
  return c;
}

/** [`who`] for the middle of a sentence ("you allowed an app on this computer"). */
export function whoMid(caller?: unknown, label?: unknown): string {
  const w = who(caller, label);
  return w === "An app on this computer" ? "an app on this computer" : w;
}

/** "read", "send a request to", "change", "delete": what someone wants to do. */
export function verbBase(method?: unknown): string {
  switch (String(method ?? "").toUpperCase()) {
    case "GET":
    case "HEAD":
      return "read";
    case "POST":
      return "send a request to";
    case "PUT":
    case "PATCH":
      return "change";
    case "DELETE":
      return "delete";
    default:
      return "call";
  }
}

/** "read", "sent", "changed", "deleted" for an HTTP method. */
export function verb(method?: unknown): string {
  switch (String(method ?? "").toUpperCase()) {
    case "GET":
    case "HEAD":
      return "read";
    case "POST":
      return "sent";
    case "PUT":
    case "PATCH":
      return "changed";
    case "DELETE":
      return "deleted";
    default:
      return "called";
  }
}

/** What the provider's answer means. */
export function statusWords(status?: unknown): { text: string; tone: "ok" | "warn" | "bad" } {
  const s = Number(status);
  if (s >= 200 && s < 300) return { text: "OK", tone: "ok" };
  if (s === 401 || s === 403) return { text: `refused the key (${s})`, tone: "bad" };
  if (s === 404) return { text: "not found (404)", tone: "warn" };
  if (s === 429) return { text: "said slow down (429)", tone: "warn" };
  if (s >= 500) return { text: `had a problem (${s})`, tone: "warn" };
  if (s >= 400) return { text: `rejected the request (${s})`, tone: "warn" };
  return { text: s ? String(s) : "no answer", tone: "warn" };
}

/** Why Unseenkey stopped a request. */
export function reasonWords(reason?: unknown, detail?: unknown): string {
  const r = String(reason ?? "");
  const map: Record<string, string> = {
    policy_denied: "the rules for this access do not allow it",
    host_not_allowed: "that website is not allowed for this key",
    egress_blocked: "the request carried another key",
    throttled: "it is slowed down after unusual activity",
    paused: "it is paused after unusual activity",
    handle_paused: "it is paused after unusual activity",
    project_cap: "the project reached its daily limit",
    rate_limited_minute: "its per-minute limit was reached",
    rate_limited_day: "its daily limit was reached",
    approval_denied: "you said no",
    approval_timeout: "nobody answered in time",
    expired: "this access has expired",
    revoked: "this access was removed",
    caller_not_allowed: "this tool is not allowed to use it",
    outside_schedule: "it is outside the hours you allowed",
    body_too_large: "the request was too large",
  };
  return map[r] ?? (typeof detail === "string" && detail ? detail : r.replace(/_/g, " ") || "it is not allowed");
}

/** Why the vault locked. */
export function lockWords(reason?: unknown): string {
  switch (String(reason ?? "")) {
    case "idle":
      return "after it was not used for a while";
    case "session_lock":
      return "when you locked Windows";
    case "sleep":
      return "when the computer went to sleep";
    case "request":
      return "by you";
    case "canary":
      return "because a tripwire key was used";
    case "anomaly":
      return "after unusual activity";
    case "shutdown":
      return "when the service stopped";
    default:
      return "";
  }
}

/** What an incident response does, in a few words. */
export function responseWords(r?: unknown): string {
  switch (String(r ?? "")) {
    case "alert":
      return "you were told";
    case "throttle":
      return "slowed down for an hour";
    case "approve":
      return "every request now needs your OK";
    case "pause":
      return "paused";
    case "lock":
      return "the vault was locked";
    default:
      return String(r ?? "");
  }
}

/** A path made shorter for a sentence: "/v1/chat/completions" stays, ids become "…". */
export function shortPath(path?: unknown): string {
  const p = String(path ?? "");
  return p
    .split("/")
    .map((seg) => (seg.length > 24 || /^[0-9a-f]{12,}$/i.test(seg) ? "…" : seg))
    .join("/");
}
