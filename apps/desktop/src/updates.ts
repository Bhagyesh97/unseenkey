// Signed auto-updates (tauri-plugin-updater). The manifest is fetched from the
// GitHub release of the newest tag; the bundle signature is checked against the
// public key baked into tauri.conf.json before anything is installed.
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

export interface UpdateInfo {
  version: string;
  notes: string;
  date: string;
}

let pending: Update | null = null;

export async function checkForUpdate(): Promise<UpdateInfo | null> {
  const u = await check({ timeout: 15_000 });
  pending = u;
  if (!u) return null;
  return { version: u.version, notes: u.body ?? "", date: u.date ?? "" };
}

export async function installUpdate(onProgress?: (downloaded: number, total: number | undefined) => void): Promise<void> {
  if (!pending) {
    const u = await check({ timeout: 15_000 });
    if (!u) throw new Error("No update is available.");
    pending = u;
  }
  let downloaded = 0;
  let total: number | undefined;
  await pending.downloadAndInstall((ev) => {
    if (ev.event === "Started") total = ev.data.contentLength ?? undefined;
    else if (ev.event === "Progress") {
      downloaded += ev.data.chunkLength;
      onProgress?.(downloaded, total);
    }
  });
  await relaunch();
}
