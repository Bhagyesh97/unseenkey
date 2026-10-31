// Signed auto-updates (tauri-plugin-updater). The manifest is fetched from the
// GitHub release of the newest tag; the bundle signature is checked against the
// public key baked into tauri.conf.json before anything is installed.
//
// One updater per app (`useUpdater` in App), shared by the banner, the
// Projects health line and Settings, so they show the same progress and the
// same error. The app lives in the tray for days, so it checks again every few
// hours, not only at startup. Failures go to `logs/desktop.log`.
import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

export interface UpdateInfo {
  version: string;
  notes: string;
  date: string;
}

export interface Updater {
  /** The newer version, when one was found. */
  available: UpdateInfo | null;
  checking: boolean;
  /** A check the owner asked for found nothing newer. */
  upToDate: boolean;
  /** Set while downloading: "42%", or "1.2 MB" when the size is unknown. */
  progress: string | null;
  error: string | null;
  check: () => Promise<void>;
  install: () => Promise<void>;
  dismiss: () => void;
}

const FIRST_CHECK_MS = 4_000;
const CHECK_EVERY_MS = 6 * 60 * 60 * 1000;
const CHECK_TIMEOUT_MS = 15_000;
const DOWNLOAD_TIMEOUT_MS = 5 * 60 * 1000;

export const RELEASES_URL = "https://github.com/Bhagyesh97/unseenkey/releases/latest";

/** Append a line to `logs/desktop.log`; never fails. */
export function logLine(message: string) {
  void invoke("log_line", { message }).catch(() => {});
}

/** Open the releases page in the browser, to download the installer by hand. */
export function openReleases() {
  void invoke("open_releases").catch(() => {});
}

function info(u: Update): UpdateInfo {
  return { version: u.version, notes: u.body ?? "", date: u.date ?? "" };
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function size(bytes: number): string {
  return bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.round(bytes / 1024)} KB`;
}

export function useUpdater(): Updater {
  const [available, setAvailable] = useState<UpdateInfo | null>(null);
  const [checking, setChecking] = useState(false);
  const [upToDate, setUpToDate] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Separate, so a background check never swallows a click on Install.
  const checkBusy = useRef(false);
  const installBusy = useRef(false);

  // Automatic checks stay quiet when they fail (offline); the log keeps why.
  const run = useCallback(async (manual: boolean) => {
    if (checkBusy.current || installBusy.current) return;
    checkBusy.current = true;
    setChecking(true);
    if (manual) setError(null);
    try {
      const u = await check({ timeout: CHECK_TIMEOUT_MS });
      setAvailable(u ? info(u) : null);
      setUpToDate(manual && !u);
      await u?.close();
    } catch (e) {
      logLine(`update check failed: ${message(e)}`);
      if (manual) setError(`Could not check for updates: ${message(e)}`);
    } finally {
      setChecking(false);
      checkBusy.current = false;
    }
  }, []);

  useEffect(() => {
    const first = setTimeout(() => void run(false), FIRST_CHECK_MS);
    const every = setInterval(() => void run(false), CHECK_EVERY_MS);
    return () => {
      clearTimeout(first);
      clearInterval(every);
    };
  }, [run]);

  const install = useCallback(async () => {
    if (installBusy.current) return;
    installBusy.current = true;
    setError(null);
    setProgress("starting");
    try {
      // A fresh check: the one behind the banner may be hours old.
      const u = await check({ timeout: CHECK_TIMEOUT_MS });
      if (!u) {
        setAvailable(null);
        throw new Error("No update is available any more.");
      }
      setAvailable(info(u));
      logLine(`installing ${u.version}`);
      let downloaded = 0;
      let total: number | undefined;
      await u.downloadAndInstall((ev) => {
        if (ev.event === "Started") total = ev.data.contentLength ?? undefined;
        else if (ev.event === "Progress") {
          downloaded += ev.data.chunkLength;
          setProgress(total ? `${Math.min(100, Math.round((100 * downloaded) / total))}%` : size(downloaded));
        } else if (ev.event === "Finished") setProgress("installing");
      }, { timeout: DOWNLOAD_TIMEOUT_MS });
      // On Windows the installer has already closed the app by now.
      await relaunch();
    } catch (e) {
      logLine(`update install failed: ${message(e)}`);
      setError(`The update did not install: ${message(e)}`);
      setProgress(null);
    } finally {
      installBusy.current = false;
    }
  }, []);

  const dismiss = useCallback(() => {
    setAvailable(null);
    setError(null);
  }, []);

  return { available, checking, upToDate, progress, error, check: () => run(true), install, dismiss };
}

/** "Downloading 42%…" and the like, for a button label or a status line. */
export function progressText(p: string): string {
  if (p === "starting") return "Starting the download…";
  if (p === "installing") return "Installing; the app restarts by itself…";
  return `Downloading ${p}…`;
}
