// Starts a daemon on a throwaway vault for the whole run; the returned
// function stops it. The daemon's address and log file are handed to the
// tests via a state file. The log is how the tests prove that a request
// reached the daemon and was refused there, rather than never being sent.
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const STATE_FILE = path.join(here, ".pw-state.json");
const PASSWORD = "browser-test-password-1\n";

function binary(): string {
  if (process.env.USK_BIN) return process.env.USK_BIN;
  const exe = process.platform === "win32" ? "usk.exe" : "usk";
  const p = path.resolve(here, "..", "..", "target", "debug", exe);
  if (!fs.existsSync(p)) throw new Error(`usk binary not found at ${p}; run \`cargo build -p usk\` or set USK_BIN`);
  return p;
}

async function waitFor(file: string, ms: number): Promise<string> {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (fs.existsSync(file)) {
      const s = fs.readFileSync(file, "utf8").trim();
      if (s) return s;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ${file}`);
}

export default async function globalSetup() {
  const usk = binary();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "usk-pw-"));
  const vault = path.join(dir, "vault.db");
  const log = path.join(dir, "daemon.log");
  const env = { ...process.env, USK_LISTEN: "127.0.0.1:0", USK_IDLE_LOCK_MINUTES: "0", USK_LOG: "info" };

  const init = spawnSync(usk, ["--vault", vault, "init", "--profile", "light"], { input: PASSWORD, env, encoding: "utf8" });
  if (init.status !== 0) throw new Error(`usk init failed: ${init.stderr}`);

  const out = fs.openSync(log, "a");
  const daemon = spawn(usk, ["--vault", vault, "daemon", "run"], { env, stdio: ["ignore", "ignore", out] });
  daemon.on("exit", (code) => {
    if (code !== null && code !== 0) console.error(`daemon exited with ${code}; see ${log}`);
  });
  const addr = await waitFor(path.join(dir, "daemon.addr"), 15_000);
  fs.writeFileSync(STATE_FILE, JSON.stringify({ addr, dir, log }));
  console.log(`daemon for browser tests at http://${addr}, log ${log}`);

  return async () => {
    daemon.kill();
    await new Promise((r) => setTimeout(r, 300));
    fs.closeSync(out);
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(STATE_FILE, { force: true });
  };
}
