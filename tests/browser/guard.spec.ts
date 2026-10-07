// INV-6: the daemon rejects anything that comes from a browser.
//
// Two attacking pages, both served by Playwright's request interception so no
// real server is needed: a public site (evil.example) and a page on another
// loopback port (a dev server, another app's web UI). Each tries fetch with
// and without CORS, simple POSTs that need no preflight, image and script
// tags, a form submission and a WebSocket; plus a typed-in navigation.
//
// Two Playwright projects run the same tests (see playwright.config.ts):
//  - "browser-blocks": stock Chromium. Its local-network-access rules refuse
//    most page-initiated requests to loopback before they are sent.
//  - "guard-only": those rules switched off, so every request reaches the
//    daemon and only the daemon's own guard stands. The daemon's log counts
//    the rejections, which is the proof that the guard did the refusing.
// In both: every response the daemon sends must be a 403 with
// `browser_origin_rejected`, and nothing may ever be a 2xx.
import { test, expect, type Page } from "@playwright/test";
import fs from "node:fs";
import { STATE_FILE } from "./global-setup";

const state = JSON.parse(fs.readFileSync(STATE_FILE, "utf8")) as { addr: string; log: string };
const base = `http://${state.addr}`;
const REJECTED = "browser-origin request rejected";

const SITES = [
  { name: "a public site", url: "http://evil.example/" },
  { name: "a local site on another port", url: "http://127.0.0.1:9/" },
];

type Seen = { url: string; status: number; body: string };

function watch(page: Page): Seen[] {
  const seen: Seen[] = [];
  page.on("response", async (r) => {
    if (!r.url().startsWith(base)) return;
    let body = "";
    try {
      body = await r.text();
    } catch {
      /* opaque or aborted */
    }
    seen.push({ url: r.url(), status: r.status(), body });
  });
  return seen;
}

/// Rejections the daemon logged so far.
function rejections(): number {
  try {
    return fs.readFileSync(state.log, "utf8").split("\n").filter((l) => l.includes(REJECTED)).length;
  } catch {
    return 0;
  }
}

async function hostedPage(page: Page, site: string, html: string) {
  await page.route(`${site}**`, (route) => route.fulfill({ status: 200, contentType: "text/html", body: html }));
  await page.goto(site);
}

function expectAllRejected(seen: Seen[]) {
  for (const s of seen) {
    expect(s.status, `${s.url} answered ${s.status}`).toBe(403);
    if (s.body) expect(s.body).toContain("browser_origin_rejected");
  }
}

const guardOnly = () => test.info().project.name === "guard-only";

test("typed-in navigation to the daemon is refused", async ({ page }) => {
  const before = rejections();
  for (const path of ["/healthz", "/v1/status", "/p/openai/v1/models", "/mcp"]) {
    const resp = await page.goto(base + path);
    expect(resp, path).not.toBeNull();
    expect(resp!.status(), path).toBe(403);
    expect(await resp!.text()).toContain("browser_origin_rejected");
  }
  await page.waitForTimeout(300);
  expect(rejections() - before).toBeGreaterThanOrEqual(4);
});

for (const site of SITES) {
  test(`fetch from ${site.name} never gets through`, async ({ page }) => {
    const seen = watch(page);
    const before = rejections();
    await hostedPage(page, site.url, "<html><body>evil</body></html>");
    const results = await page.evaluate(async (base) => {
      const out: Record<string, string> = {};
      const attempt = async (name: string, f: () => Promise<Response>) => {
        try {
          const r = await f();
          out[name] = `status ${r.status} type ${r.type}`;
        } catch (e) {
          out[name] = `blocked: ${(e as Error).message}`;
        }
      };
      await attempt("get-cors", () => fetch(`${base}/v1/status`));
      await attempt("get-no-cors", () => fetch(`${base}/v1/status`, { mode: "no-cors" }));
      // text/plain POST is a "simple request": no preflight, the body reaches the server.
      await attempt("post-simple", () =>
        fetch(`${base}/v1/unlock`, { method: "POST", mode: "no-cors", headers: { "content-type": "text/plain" }, body: '{"password":"x"}' }),
      );
      await attempt("post-json", () =>
        fetch(`${base}/v1/lock`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }),
      );
      await attempt("proxy", () => fetch(`${base}/p/openai/v1/models`, { headers: { authorization: "Bearer usk_h_x" } }));
      await attempt("mcp", () =>
        fetch(`${base}/mcp`, { method: "POST", mode: "no-cors", headers: { "content-type": "text/plain" }, body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' }),
      );
      return out;
    }, base);
    await page.waitForTimeout(500);
    const reached = rejections() - before;
    console.log(`${site.name}: ${reached} requests reached the daemon and were refused`, results);
    for (const v of Object.values(results)) expect(v).not.toMatch(/status 2\d\d/);
    expectAllRejected(seen);
    // Six attempts; preflighted ones reach the daemon as OPTIONS, the rest as sent.
    if (guardOnly()) expect(reached, "with browser checks off, every attempt must reach the daemon's guard").toBeGreaterThanOrEqual(6);
  });

  test(`image, script, form and WebSocket from ${site.name} never get through`, async ({ page }) => {
    const seen = watch(page);
    const socketErrors: string[] = [];
    page.on("websocket", (ws) => {
      ws.on("socketerror", (e) => socketErrors.push(String(e)));
    });
    const before = rejections();
    await hostedPage(
      page,
      site.url,
      `<html><body>
        <img id="i" src="${base}/healthz">
        <script src="${base}/v1/status"></script>
        <form id="f" method="POST" action="${base}/v1/lock"><input name="x" value="1"></form>
      </body></html>`,
    );
    await page.evaluate((base) => {
      try {
        new WebSocket(`${base.replace("http", "ws")}/v1/events`);
      } catch {
        /* refused synchronously */
      }
    }, base);
    await page.waitForTimeout(800);
    const subresources = rejections() - before;
    await page.evaluate(() => (document.getElementById("f") as HTMLFormElement).submit());
    // The submission is a navigation to the daemon; wait for it rather than a fixed time.
    await page.waitForURL(`${base}/v1/lock`, { timeout: 15_000 });
    await page.waitForTimeout(300);
    const total = rejections() - before;
    console.log(`${site.name}: ${subresources} subresource/websocket requests and ${total - subresources} form submissions reached the daemon and were refused; ${socketErrors.length} websocket errors`);
    expectAllRejected(seen);
    expect(socketErrors.length).toBeGreaterThanOrEqual(1);
    // image, script and the WebSocket handshake
    if (guardOnly()) expect(subresources).toBeGreaterThanOrEqual(3);
    // The form navigation always reaches the daemon and lands on its 403 page.
    expect(total - subresources).toBeGreaterThanOrEqual(1);
    expect(page.url()).toBe(`${base}/v1/lock`);
    await expect(page.locator("body")).toContainText("browser_origin_rejected");
  });
}
