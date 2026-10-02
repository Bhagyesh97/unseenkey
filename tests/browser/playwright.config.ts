import { defineConfig } from "@playwright/test";

// Locally, PW_CHANNEL=msedge or chrome uses an installed browser and skips the
// Chromium download. CI installs Chromium.
//
// Two projects:
//  - "browser-blocks": stock Chromium. Its local-network-access rules already
//    refuse most page-initiated requests to loopback, so few reach the daemon.
//  - "guard-only": those rules switched off. Every request reaches the daemon
//    and the daemon's own guard (INV-6) is the only thing refusing it.
const LNA_OFF = [
  "--disable-features=LocalNetworkAccessChecks,PrivateNetworkAccessSendPreflights,PrivateNetworkAccessRespectPreflightResults,BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessForWorkers",
];

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.ts/,
  globalSetup: "./global-setup.ts",
  timeout: 60_000,
  retries: 0,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  use: {
    browserName: "chromium",
    channel: process.env.PW_CHANNEL || undefined,
    headless: true,
  },
  projects: [
    { name: "browser-blocks" },
    { name: "guard-only", use: { launchOptions: { args: LNA_OFF } } },
  ],
});
